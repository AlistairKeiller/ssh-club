//! `club install` / `club uninstall`: every file the setup needs is embedded
//! here and applied idempotently, so one binary sets up a fresh machine.

use crate::host::{run, write_atomic};
use crate::paths::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{fs, io::Read};

const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/10-club.conf";
const SSHD_SETTINGS: &str = "\
# managed by club. The 10- prefix matters: sshd keeps the first value it sees,
# and cloud images set PasswordAuthentication no in 60-cloudimg-settings.conf.
PasswordAuthentication yes
UsePAM yes
";

const PAM_FILE: &str = "/etc/pam.d/sshd";
const PAM_BLOCK: &str = "\
# BEGIN club
auth [success=done default=ignore] pam_exec.so quiet expose_authtok /usr/local/bin/club pam-auth
# END club
";

const UNIT_FILE: &str = "/etc/systemd/system/club.service";
const UNIT: &str = "\
[Unit]
Description=club: on-demand SSH accounts
After=local-fs.target network.target

[Service]
ExecStart=/usr/local/bin/club serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
";

fn step(msg: &str) {
    println!("==> {msg}");
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn make_dir(path: &str, mode: u32) -> Result<(), String> {
    io(fs::create_dir_all(path), path)?;
    io(fs::set_permissions(path, fs::Permissions::from_mode(mode)), path)
}

/// The PAM file without any club block.
fn strip_block(text: &str) -> String {
    let mut skipping = false;
    let mut out = String::new();
    for line in text.lines() {
        skipping |= line.starts_with("# BEGIN club");
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
        skipping &= !line.starts_with("# END club");
    }
    out
}

/// Does the host already use a uid or gid in the range club hands out?
fn range_in_use() -> bool {
    ["/etc/passwd", "/etc/group"].iter().any(|f| {
        let Ok(text) = fs::read_to_string(f) else { return true };
        text.lines()
            .filter_map(|l| l.split(':').nth(2)?.parse::<u32>().ok())
            .any(|id| (UID_RANGE.0..=UID_RANGE.1).contains(&id))
    })
}

/// Reload sshd if it is running (it picks the settings up when it starts otherwise).
fn reload_sshd() {
    let _ = run("systemctl", &["try-reload-or-restart", "ssh"]) || run("systemctl", &["try-reload-or-restart", "sshd"]);
}

/// 20 random characters without look-alikes.
fn random_password() -> Result<String, String> {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 56
    let mut urandom = io(fs::File::open("/dev/urandom"), "/dev/urandom")?;
    let mut pw = String::new();
    while pw.len() < 20 {
        let mut b = [0u8; 1];
        io(urandom.read_exact(&mut b), "/dev/urandom")?;
        if b[0] < 224 {
            // 224 = 4 * 56, so the modulo is unbiased
            pw.push(ALPHABET[b[0] as usize % 56] as char);
        }
    }
    Ok(pw)
}

pub fn install() -> Result<(), String> {
    if !Command::new("id").arg("-u").output().is_ok_and(|o| o.stdout == b"0\n") {
        return Err("run this with sudo".into());
    }
    if !Path::new("/run/systemd/system").exists() {
        return Err("needs a Linux host running systemd".into());
    }
    if range_in_use() {
        return Err(format!("this host already has users or groups with ids in {}-{}; club needs that range", UID_RANGE.0, UID_RANGE.1));
    }

    step("installing packages");
    let apt = Command::new("apt-get")
        .args(["install", "-y", "-qq", "libnss-systemd", "openssh-server"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdout(Stdio::null())
        .status();
    if !apt.is_ok_and(|s| s.success()) {
        return Err("apt-get install failed (this installer supports Debian and Ubuntu)".into());
    }

    step("setting up club");
    make_dir(CONF_DIR, 0o700)?;
    make_dir(STATE_DIR, 0o700)?;
    make_dir(HOME_BASE, 0o711)?; // members can reach their own home but not list each other's
    let new_password = if Path::new(PASSWORD_FILE).exists() {
        None
    } else {
        let pw = random_password()?;
        io(fs::write(PASSWORD_FILE, format!("{pw}\n")), PASSWORD_FILE)?;
        Some(pw)
    };
    let me = io(std::env::current_exe(), "locating myself")?;
    if me != Path::new(BIN) {
        io(fs::copy(&me, format!("{BIN}.new")), "copying the binary")?;
        io(fs::rename(format!("{BIN}.new"), BIN), BIN)?;
    }

    step("configuring sshd and PAM");
    io(write_atomic(Path::new(SSHD_DROPIN), SSHD_SETTINGS), SSHD_DROPIN)?;
    let _ = fs::create_dir_all("/run/sshd"); // `sshd -T` needs it before sshd has ever started
    let sshd = io(Command::new("sshd").arg("-T").output(), "checking SSH settings")?;
    if !String::from_utf8_lossy(&sshd.stdout).lines().any(|l| l == "passwordauthentication yes") {
        return Err("SSH still has password login off; check `sudo sshd -T` and /etc/ssh/sshd_config.d/".into());
    }
    let pam = io(fs::read_to_string(PAM_FILE), PAM_FILE)?;
    io(write_atomic(Path::new(PAM_FILE), &format!("{PAM_BLOCK}{}", strip_block(&pam))), PAM_FILE)?;

    step("starting the service");
    io(fs::write(UNIT_FILE, UNIT), UNIT_FILE)?;
    if !(run("systemctl", &["daemon-reload"]) && run("systemctl", &["enable", "club"]) && run("systemctl", &["restart", "club"])) {
        return Err("could not start club; see `journalctl -u club`".into());
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    reload_sshd();

    // Any valid name should now resolve, through nss-systemd, via the daemon.
    let found = Command::new("getent").args(["passwd", "club-selftest"]).output();
    if !found.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).starts_with("club-selftest:")) {
        return Err("self-test failed: `getent passwd club-selftest` found nothing. \
            Is `systemd` on the passwd: line of /etc/nsswitch.conf? See `journalctl -u club`.".into());
    }

    println!("\nDone. Anyone can now run:  ssh <any-username>@<this-server>");
    match new_password {
        Some(pw) => println!("Shared password:           {pw}"),
        None => println!("Shared password:           unchanged (it is in {PASSWORD_FILE})"),
    }
    println!("Test a login from a second terminal before closing this one.");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    run("systemctl", &["disable", "--now", "club"]);
    for f in [UNIT_FILE, SSHD_DROPIN, SOCKET] {
        let _ = fs::remove_file(f);
    }
    if let Ok(pam) = fs::read_to_string(PAM_FILE) {
        io(write_atomic(Path::new(PAM_FILE), &strip_block(&pam)), PAM_FILE)?;
    }
    reload_sshd();
    println!("Removed the service and the sshd/PAM hooks. Members' files stay in {HOME_BASE} (see the README to erase them).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_block_is_added_once_and_removed_cleanly() {
        let original = "# PAM configuration for sshd\n@include common-auth\naccount required pam_nologin.so\n";
        let once = format!("{PAM_BLOCK}{}", strip_block(original));
        let twice = format!("{PAM_BLOCK}{}", strip_block(&once));
        assert_eq!(once, twice);
        assert!(once.starts_with("# BEGIN club"), "our hook must run before common-auth");
        assert_eq!(strip_block(&once), original);
    }

    #[test]
    fn passwords_are_20_unambiguous_characters() {
        let pw = random_password().unwrap();
        assert_eq!(pw.len(), 20);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric() && !"0O1lI".contains(c)));
    }
}
