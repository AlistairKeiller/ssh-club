//! Everything that touches the machine on behalf of a member.
//! Each function does nothing when `cfg.dry_run` is set (tests).

use crate::config::*;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::process::{Command, Stdio};
use std::sync::Mutex;

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

/// Create the member's home on first login. It is built under a temporary name
/// and renamed into place, so nobody ever sees (or is stuck with) a half-made
/// home. Safe to call on every login.
pub fn provision(cfg: &Config, name: &str, uid: u32) -> io::Result<()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _guard = ONE_AT_A_TIME.lock().unwrap();
    let home = format!("{HOME_BASE}/{name}");
    if cfg.dry_run || std::path::Path::new(&home).exists() {
        return Ok(());
    }
    let tmp = format!("{HOME_BASE}/.new-{name}"); // valid names never start with a dot
    let _ = fs::remove_dir_all(&tmp);
    fs::DirBuilder::new().mode(0o700).create(&tmp)?;
    let owner = format!("{uid}:{uid}");
    if !run("cp", &["-rT", "/etc/skel", &tmp]) || !run("chown", &["-R", &owner, &tmp]) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(io::Error::other("could not populate the home from /etc/skel"));
    }
    fs::rename(&tmp, &home)
}

/// Stop a member's processes and delete their files.
pub fn remove(cfg: &Config, name: &str, uid: u32) {
    if cfg.dry_run {
        return;
    }
    let uid_s = uid.to_string();
    run("loginctl", &["terminate-user", &uid_s]);
    run("pkill", &["-KILL", "-u", &uid_s]);
    if let Err(e) = fs::remove_dir_all(format!("{HOME_BASE}/{name}")) {
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!("club: removing the home of '{name}': {e}");
        }
    }
}

/// Does this uid have running processes? When in doubt, say yes: the answer
/// only ever protects someone from being deleted.
pub fn busy(uid: u32) -> bool {
    Command::new("pgrep")
        .args(["-u", &uid.to_string()])
        .stdout(Stdio::null())
        .status()
        .map_or(true, |s| s.code() != Some(1))
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
