//! The two things club does to the machine: run commands, and create homes.

use crate::paths::*;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::fs;

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

/// Replace a file in one step, so readers never see it half-written.
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)
}

/// Create the member's home on first login (a no-op afterwards). It is built
/// under a temporary name and renamed into place, so nobody ever sees, or is
/// stuck with, a half-made home.
pub fn provision(name: &str, uid: u32) -> io::Result<()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let home = Path::new(HOME_BASE).join(name);
    if cfg!(test) || home.exists() {
        return Ok(());
    }
    let _guard = ONE_AT_A_TIME.lock().unwrap();
    if home.exists() {
        return Ok(()); // another login of the same member got here first
    }
    let tmp = Path::new(HOME_BASE).join(format!(".new-{name}")); // names never start with a dot
    let (tmp_s, owner) = (tmp.to_string_lossy(), format!("{uid}:{uid}"));
    let _ = fs::remove_dir_all(&tmp);
    let steps: [&[&str]; 3] =
        [&["cp", "-rT", "/etc/skel", &tmp_s], &["chown", "-R", &owner, &tmp_s], &["chmod", "700", &tmp_s]];
    if !steps.iter().all(|s| run(s[0], &s[1..])) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(io::Error::other("could not create the home from /etc/skel"));
    }
    fs::rename(&tmp, &home)
}
