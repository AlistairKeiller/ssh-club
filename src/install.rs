//! `club install` / `club uninstall`: every file the setup needs is embedded
//! here and applied idempotently, so one binary sets up a fresh machine.

use crate::config::*;
use crate::host::run;
use std::path::Path;
use std::process::{Command, Stdio};
use std::fs;

const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/10-club.conf";
const SSHD_SETTINGS: &str = "\
# managed by club. The 10- prefix matters: sshd keeps the first value it sees,
# and cloud images set PasswordAuthentication no in 60-cloudimg-settings.conf.
PasswordAuthentication yes
MaxStartups 50:30:200
ClientAliveInterval 60
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
Description=club: on-demand SSH workspaces
After=local-fs.target network.target netfilter-persistent.service
RequiresMountsFor=/home/club /var/lib/club

[Service]
ExecStart=/usr/local/bin/club serve
Restart=always

[Install]
WantedBy=multi-user.target
";

fn step(msg: &str) {
    println!("==> {msg}");
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
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

fn reload_sshd() {
    let _ = run("systemctl", &["reload", "ssh"]) || run("systemctl", &["reload", "sshd"]);
}

pub fn install() -> Result<(), String> {
    crate::need_root()?;
    if !Path::new("/run/systemd/system").exists() {
        return Err("needs a Linux host running systemd".into());
    }

    step("installing packages");
    let apt = Command::new("apt-get")
        .args(["install", "-y", "-qq", "quota", "iptables", "libnss-systemd", "openssh-server"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdout(Stdio::null())
        .status();
    if !apt.is_ok_and(|s| s.success()) {
        return Err("apt-get install failed (this installer supports Debian and Ubuntu)".into());
    }

    step("writing /etc/club, /var/lib/club and the binary");
    io(fs::create_dir_all(CONF_DIR), CONF_DIR)?;
    io(fs::create_dir_all(STATE_DIR), STATE_DIR)?;
    io(fs::set_permissions(STATE_DIR, std::os::unix::fs::PermissionsExt::from_mode(0o700)), STATE_DIR)?;
    if !Path::new(CONF_FILE).exists() {
        io(fs::write(CONF_FILE, CONF_TEMPLATE), CONF_FILE)?;
    }
    let new_password = (!Path::new(PASSWORD_FILE).exists()).then(crate::rotate_password).transpose()?;
    let me = io(std::env::current_exe(), "locating myself")?;
    if me != Path::new(BIN) {
        io(fs::copy(&me, format!("{BIN}.new")), "copying the binary")?;
        io(fs::rename(format!("{BIN}.new"), BIN), BIN)?;
    }

    step("preparing /home/club");
    mount_homes(&Config::load())?;

    step("configuring sshd and PAM");
    io(fs::write(SSHD_DROPIN, SSHD_SETTINGS), SSHD_DROPIN)?;
    let pam = io(fs::read_to_string(PAM_FILE), PAM_FILE)?;
    io(fs::write(PAM_FILE, format!("{PAM_BLOCK}{}", strip_block(&pam))), PAM_FILE)?;
    let _ = fs::create_dir_all("/run/sshd"); // `sshd -T` needs it before sshd has ever started
    let sshd = Command::new("sshd").arg("-T").output();
    let effective = sshd.as_ref().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if !effective.contains("passwordauthentication yes") {
        return Err("sshd did not accept the new settings; check `sudo sshd -T` and /etc/ssh/sshd_config.d/".into());
    }

    step("starting the service");
    io(fs::write(UNIT_FILE, UNIT), UNIT_FILE)?;
    if !(run("systemctl", &["daemon-reload"])
        && run("systemctl", &["enable", "club"])
        && run("systemctl", &["restart", "club"]))
    {
        return Err("could not start club; see `journalctl -u club`".into());
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    reload_sshd();

    // Any valid name should now resolve, via the daemon, through nss-systemd.
    let resolves = Command::new("getent").args(["passwd", "club-selftest"]).output();
    if !resolves.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("club-selftest:")) {
        return Err("self-test failed: `getent passwd club-selftest` found nothing. \
            Is `systemd` on the passwd: line of /etc/nsswitch.conf? See `journalctl -u club`.".into());
    }

    println!("\nDone. Members run:  ssh <any-username>@<this-server>");
    match new_password {
        Some(pw) => println!("Shared password:    {pw}"),
        None => println!("Shared password:    unchanged (see `sudo club password`)"),
    }
    println!("Test a login from a second terminal before closing this one.");
    Ok(())
}

/// Mount the sparse ext4 image that holds every home (or just use a directory).
fn mount_homes(cfg: &Config) -> Result<(), String> {
    io(fs::create_dir_all(HOME_BASE), HOME_BASE)?;
    let mounted = fs::read_to_string("/proc/mounts").is_ok_and(|m| m.lines().any(|l| l.contains(" /home/club ")));
    if cfg.home_pool_gb > 0 && !mounted {
        let img = format!("{STATE_DIR}/home.img");
        let quota = cfg.disk_quota_gb > 0;
        if !Path::new(&img).exists() {
            let file = io(fs::File::create(&img), &img)?;
            io(file.set_len(cfg.home_pool_gb << 30), &img)?;
            let mut mkfs = vec!["-q", "-F"];
            if quota {
                mkfs.extend(["-O", "quota", "-E", "quotatype=usrquota"]);
            }
            mkfs.push(&img);
            if !run("mkfs.ext4", &mkfs) {
                return Err("mkfs.ext4 failed".into());
            }
        }
        let opts = if quota { "loop,nosuid,nodev,noatime,usrquota" } else { "loop,nosuid,nodev,noatime" };
        let old = fs::read_to_string("/etc/fstab").unwrap_or_default();
        let mut fstab: Vec<&str> = old.lines().filter(|l| !l.ends_with("# club")).collect();
        let line = format!("{img} {HOME_BASE} ext4 {opts} 0 0 # club");
        fstab.push(&line);
        io(fs::write("/etc/fstab", fstab.join("\n") + "\n"), "/etc/fstab")?;
        run("systemctl", &["daemon-reload"]);
        if !run("mount", &[HOME_BASE]) {
            return Err(format!(
                "could not mount {img}. If this kernel lacks ext4 quota support, set \
                 disk_quota_gb = 0 in {CONF_FILE}, delete {img}, and run install again."
            ));
        }
    }
    // traverse-only: members reach their own home but cannot list each other's names
    io(fs::set_permissions(HOME_BASE, std::os::unix::fs::PermissionsExt::from_mode(0o711)), HOME_BASE)
}

pub fn uninstall() -> Result<(), String> {
    crate::need_root()?;
    run("systemctl", &["disable", "--now", "club"]);
    for f in [UNIT_FILE, SSHD_DROPIN, SOCKET] {
        let _ = fs::remove_file(f);
    }
    if let Ok(pam) = fs::read_to_string(PAM_FILE) {
        io(fs::write(PAM_FILE, strip_block(&pam)), PAM_FILE)?;
    }
    reload_sshd();
    println!("Removed the service and the sshd/PAM hooks. Members' files are untouched (see the README to erase them).");
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
}
