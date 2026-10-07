//! Everything that touches the machine on behalf of a workspace.
//! Each function does nothing when `cfg.dry_run` is set (tests).

use crate::config::*;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::process::{Command, Stdio};

/// Run a command quietly; true if it exited 0.
pub fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn set_quota(cfg: &Config, uid: u32, gb: u64) {
    if cfg.disk_quota_gb == 0 {
        return;
    }
    let kb = (gb * 1024 * 1024).to_string();
    if !run("setquota", &["-u", &uid.to_string(), &kb, &kb, "0", "0", HOME_BASE]) {
        eprintln!("club: setquota failed for uid {uid}; is the home image mounted with quotas?");
    }
}

/// Create the member's home (first login only) and apply the resource
/// limits to their systemd slice. Safe to repeat on every login.
pub fn provision(cfg: &Config, name: &str, uid: u32) -> io::Result<()> {
    if cfg.dry_run {
        return Ok(());
    }
    let home = format!("{HOME_BASE}/{name}");
    match fs::DirBuilder::new().mode(0o700).create(&home) {
        Ok(()) => {
            let owner = format!("{uid}:{uid}");
            if !run("cp", &["-rT", "/etc/skel", &home]) || !run("chown", &["-R", &owner, &home]) {
                return Err(io::Error::other("could not populate home from /etc/skel"));
            }
            set_quota(cfg, uid, cfg.disk_quota_gb);
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // set-property works before the slice exists and survives reboots.
    let slice = format!("user-{uid}.slice");
    let (high, max) = (format!("MemoryHigh={}", cfg.mem_high), format!("MemoryMax={}", cfg.mem_max));
    if !run("systemctl", &["set-property", &slice, &high, &max, "TasksMax=1500"]) {
        return Err(io::Error::other("systemctl set-property failed"));
    }
    Ok(())
}

pub fn remove(cfg: &Config, name: &str, uid: u32) {
    if cfg.dry_run {
        return;
    }
    let uid_s = uid.to_string();
    run("loginctl", &["terminate-user", &uid_s]);
    run("pkill", &["-KILL", "-u", &uid_s]);
    run("systemctl", &["revert", &format!("user-{uid}.slice")]);
    set_quota(cfg, uid, 0);
    if let Err(e) = fs::remove_dir_all(format!("{HOME_BASE}/{name}")) {
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!("club: removing home of '{name}': {e}");
        }
    }
}

/// Is this uid logged in right now?
pub fn online(uid: u32) -> bool {
    Command::new("loginctl")
        .args(["show-user", &uid.to_string(), "--property=State", "--value"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| matches!(String::from_utf8_lossy(&o.stdout).trim(), "active" | "online"))
}

/// Members must not reach the cloud metadata service (instance credentials).
pub fn block_metadata(cfg: &Config) {
    if cfg.dry_run {
        return;
    }
    let owner = format!("{}-{}", UID_RANGE.0, UID_RANGE.1);
    let rule = ["OUTPUT", "-m", "owner", "--uid-owner", &owner, "-d", "169.254.169.254", "-j", "REJECT"];
    // -C: already there?  otherwise insert at the top of OUTPUT
    let mut check = vec!["-w", "-C"];
    check.extend(rule);
    if !run("iptables", &check) {
        let mut add = vec!["-w", "-I", "OUTPUT", "1"];
        add.extend(&rule[1..]);
        if !run("iptables", &add) {
            eprintln!("club: could not install the metadata-service firewall rule");
        }
    }
}
