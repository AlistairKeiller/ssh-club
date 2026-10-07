//! Everything that touches the host on behalf of a workspace: home
//! directory, systemd resource limits, disk quota, firewall, cleanup.
//! All functions are no-ops when `cfg.dry_run` is set.

use crate::config::Config;
use crate::registry::valid_name;
use std::fs;
use std::io;
use std::os::unix::fs::{chown, DirBuilderExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

/// Run a command quietly; true if it exited 0.
pub fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn daemon_reload() {
    run("systemctl", &["daemon-reload"]);
}

pub fn write_if_changed(path: &Path, content: &str) -> io::Result<bool> {
    if fs::read_to_string(path).map(|c| c == content).unwrap_or(false) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, content)?;
    Ok(true)
}

fn limits_path(uid: u32) -> String {
    format!("/etc/systemd/system/user-{uid}.slice.d/50-club.conf")
}

fn limits_text(cfg: &Config) -> String {
    let mut s = String::from("# managed by club\n[Slice]\n");
    let mut kv = |k: &str, v: &str| {
        if !v.is_empty() {
            s.push_str(&format!("{k}={v}\n"));
        }
    };
    kv("MemoryHigh", &cfg.mem_high);
    kv("MemoryMax", &cfg.mem_max);
    kv("TasksMax", &cfg.tasks_max);
    kv("CPUQuota", &cfg.cpu_quota);
    s
}

/// Returns true if the drop-in changed (caller should daemon-reload).
fn write_limits(cfg: &Config, uid: u32) -> io::Result<bool> {
    write_if_changed(Path::new(&limits_path(uid)), &limits_text(cfg))
}

pub fn sync_limits(cfg: &Config, uids: &[u32]) {
    if cfg.dry_run {
        return;
    }
    let mut changed = false;
    for &u in uids {
        match write_limits(cfg, u) {
            Ok(c) => changed |= c,
            Err(e) => eprintln!("club: limits for uid {u}: {e}"),
        }
    }
    if changed {
        daemon_reload();
    }
}

fn copy_tree(from: &Path, to: &Path, uid: u32) -> io::Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dest)?;
            chown(&dest, Some(uid), Some(uid))?;
            copy_tree(&entry.path(), &dest, uid)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &dest)?;
            chown(&dest, Some(uid), Some(uid))?;
        }
    }
    Ok(())
}

static QUOTA_WARNED: AtomicBool = AtomicBool::new(false);

fn set_quota(cfg: &Config, uid: u32, gb: u64) {
    if cfg.disk_quota_gb == 0 {
        return;
    }
    let kb = (gb * 1024 * 1024).to_string();
    let ok = run(
        "setquota",
        &["-u", &uid.to_string(), &kb, &kb, "0", "0", &cfg.home_base],
    );
    if !ok && !QUOTA_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!("club: setquota failed; per-user disk quotas are not active (see README)");
    }
}

/// Idempotent: safe to run on every login.
pub fn provision_user(cfg: &Config, name: &str, uid: u32) -> io::Result<()> {
    if cfg.dry_run {
        return Ok(());
    }
    let home = Path::new(&cfg.home_base).join(name);
    if !home.exists() {
        fs::DirBuilder::new().mode(0o700).create(&home)?;
        chown(&home, Some(uid), Some(uid))?;
        let skel = Path::new("/etc/skel");
        if skel.is_dir() {
            copy_tree(skel, &home, uid)?;
        }
        set_quota(cfg, uid, cfg.disk_quota_gb);
    }
    if write_limits(cfg, uid)? {
        daemon_reload();
    }
    Ok(())
}

pub fn remove_user(cfg: &Config, name: &str, uid: u32) {
    if cfg.dry_run || !valid_name(name) {
        return;
    }
    let u = uid.to_string();
    run("loginctl", &["terminate-user", &u]);
    run("pkill", &["-KILL", "-u", &u]);
    let _ = fs::remove_dir_all(format!("/etc/systemd/system/user-{uid}.slice.d"));
    daemon_reload();
    set_quota(cfg, uid, 0);
    let home = Path::new(&cfg.home_base).join(name);
    if home.starts_with(&cfg.home_base) && home != Path::new(&cfg.home_base) {
        if let Err(e) = fs::remove_dir_all(&home) {
            if e.kind() != io::ErrorKind::NotFound {
                eprintln!("club: removing {}: {e}", home.display());
            }
        }
    }
}

pub fn session_active(uid: u32) -> bool {
    Command::new("loginctl")
        .args(["show-user", &uid.to_string(), "--property=State", "--value"])
        .stderr(Stdio::null())
        .output()
        .map(|o| {
            o.status.success()
                && matches!(String::from_utf8_lossy(&o.stdout).trim(), "active" | "online")
        })
        .unwrap_or(false)
}

/// Outbound rules for workspace uids: no cloud metadata service, no SMTP,
/// plus any configured networks. Safe to run repeatedly.
pub fn apply_firewall(cfg: &Config) {
    if cfg.dry_run {
        return;
    }
    let owner = format!("{}-{}", cfg.uid_min, cfg.uid_max());
    let mut rules: Vec<Vec<String>> = vec![
        vec!["-d".into(), "169.254.169.254".into()],
        vec!["-p".into(), "tcp".into(), "--dport".into(), "25".into()],
    ];
    for c in &cfg.block_cidrs {
        rules.push(vec!["-d".into(), c.clone()]);
    }
    for r in rules {
        let mut spec: Vec<String> = vec!["OUTPUT".into()];
        spec.extend(["-m", "owner", "--uid-owner", &owner].map(String::from));
        spec.extend(r);
        spec.extend(["-j", "REJECT"].map(String::from));
        let spec_ref: Vec<&str> = spec.iter().map(String::as_str).collect();

        let mut check = vec!["-w", "-C"];
        check.extend(&spec_ref);
        if run("iptables", &check) {
            continue;
        }
        let mut insert = vec!["-w", "-I", "OUTPUT", "1"];
        insert.extend(&spec_ref[1..]);
        if !run("iptables", &insert) {
            eprintln!("club: could not install firewall rule {:?}", &spec_ref[1..]);
        }
    }
}
