//! `club install` / `club uninstall`: everything that used to be a pile of
//! config files lives here as embedded text, applied idempotently.

use crate::config::*;
use crate::provision::{daemon_reload, run, write_if_changed};
use std::fs;
use std::path::Path;
use std::process::Command;

const SSHD_DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/10-club.conf";
const SSHD_DROPIN: &str = "\
# managed by club (https://github.com/OWNER/ssh-club)
# Must sort before 60-cloudimg-settings.conf: first value wins in sshd_config.
PasswordAuthentication yes
UsePAM yes
MaxStartups 50:30:200
LoginGraceTime 30
ClientAliveInterval 60
ClientAliveCountMax 5
";

const PAM_PATH: &str = "/etc/pam.d/sshd";
const PAM_BACKUP: &str = "/etc/pam.d/sshd.club-orig";
const PAM_AUTH: &str = "\
# BEGIN club
auth [success=done default=ignore] pam_exec.so quiet expose_authtok /usr/local/bin/club pam-auth
# END club
";
const PAM_ACCOUNT: &str = "\
# BEGIN club
account [success=done default=ignore] pam_exec.so quiet /usr/local/bin/club pam-account
# END club
";

const UNIT_PATH: &str = "/etc/systemd/system/club.service";

fn unit(cfg: &Config) -> String {
    format!(
        "[Unit]\n\
         Description=club: on-demand SSH workspaces (systemd userdb provider)\n\
         After=local-fs.target network.target netfilter-persistent.service\n\
         RequiresMountsFor={home} {state}\n\
         Before=ssh.service sshd.service\n\n\
         [Service]\n\
         ExecStart={bin} serve\n\
         Restart=always\n\
         RestartSec=2\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        home = cfg.home_base,
        state = STATE_DIR,
        bin = BIN_PATH
    )
}

fn step(msg: &str) {
    println!("==> {msg}");
}

fn warn(msg: &str) {
    println!("    WARNING: {msg}");
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn have(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd} >/dev/null")]).status().map(|s| s.success()).unwrap_or(false)
}

fn is_mounted(path: &str) -> bool {
    fs::read_to_string("/proc/mounts")
        .map(|m| m.lines().any(|l| l.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}

fn ssh_service() -> &'static str {
    if run("systemctl", &["cat", "ssh.service"]) { "ssh" } else { "sshd" }
}

pub fn install(args: &[String]) -> Result<(), String> {
    if !is_root() {
        return Err("run with sudo".into());
    }
    if !cfg!(target_os = "linux") || !Path::new("/run/systemd/system").exists() {
        return Err("needs a Linux host running systemd".into());
    }
    let mut password: Option<String> = None;
    let mut use_image = true;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--password" => password = Some(it.next().ok_or("--password needs a value")?.clone()),
            "--no-home-image" => use_image = false,
            other => return Err(format!("unknown option {other}")),
        }
    }

    // ---- packages ----
    step("installing packages (quota, iptables, libnss-systemd, openssh-server)");
    if have("apt-get") {
        let ok = Command::new("apt-get")
            .args(["install", "-y", "-qq", "quota", "iptables", "libnss-systemd", "openssh-server"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdout(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            warn("apt-get failed; continuing, but make sure these packages are present");
        }
    } else {
        warn("no apt-get here: install quota, iptables, libnss-systemd and openssh-server yourself");
    }

    // ---- state, config, password, binary ----
    step("writing /etc/club and /var/lib/club");
    io(fs::create_dir_all(CONF_DIR), CONF_DIR)?;
    io(fs::create_dir_all(STATE_DIR), STATE_DIR)?;
    let _ = fs::set_permissions(STATE_DIR, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    if !Path::new(CONF_FILE).exists() {
        let text = if use_image { CONF_TEMPLATE.to_string() } else { CONF_TEMPLATE.replace("home_pool_gb = 100", "home_pool_gb = 0") };
        io(fs::write(CONF_FILE, text), CONF_FILE)?;
    }
    let cfg = Config::load();
    let mut fresh_password = None;
    if let Some(pw) = password {
        crate::write_password(&pw)?;
        fresh_password = Some(pw);
    } else if !Path::new(PASSWORD_FILE).exists() {
        let pw = crate::random_password();
        crate::write_password(&pw)?;
        fresh_password = Some(pw);
    }

    let me = io(std::env::current_exe(), "current_exe")?;
    if me != Path::new(BIN_PATH) {
        let tmp = format!("{BIN_PATH}.new");
        io(fs::copy(&me, &tmp), "copying binary")?;
        io(fs::rename(&tmp, BIN_PATH), BIN_PATH)?;
    }

    // ---- nss ----
    step("making sure the system user database consults systemd");
    ensure_nss()?;

    // ---- homes ----
    step(&format!("preparing {}", cfg.home_base));
    setup_home(&cfg)?;

    // ---- sshd + PAM ----
    step("configuring sshd and PAM");
    configure_ssh()?;

    // ---- service ----
    step("starting the club service");
    io(write_if_changed(Path::new(UNIT_PATH), &unit(&cfg)), UNIT_PATH)?;
    daemon_reload();
    if !run("systemctl", &["enable", "club"]) {
        return Err("systemctl enable club failed".into());
    }
    if !run("systemctl", &["restart", "club"]) {
        return Err("starting club failed; see: journalctl -u club".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    run("systemctl", &["reload", ssh_service()]);

    // ---- self test ----
    step("self-test");
    let ok = Command::new("getent")
        .args(["passwd", "club-selftest"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("club-selftest:"))
        .unwrap_or(false);
    if ok {
        println!("    ok: the system now resolves any valid username");
    } else {
        warn("`getent passwd club-selftest` found nothing. Check that /etc/nsswitch.conf has 'systemd' on the passwd line and `journalctl -u club`.");
    }
    check_home_perms(&cfg);

    println!();
    println!("Done. Members connect with:   ssh -p 22 <any-username>@<this-server>");
    if let Some(pw) = fresh_password {
        println!("Shared password:             {pw}");
    } else {
        println!("Shared password:             (unchanged; show with `sudo club password`)");
    }
    println!("Open TCP 22 in your cloud firewall if you have not already.");
    println!("Keep this session open and test a login from another terminal before you disconnect.");
    Ok(())
}

fn ensure_nss() -> Result<(), String> {
    let path = "/etc/nsswitch.conf";
    let text = io(fs::read_to_string(path), path)?;
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            let key = l.split(':').next().unwrap_or("").trim();
            if (key == "passwd" || key == "group") && !l.split_whitespace().any(|w| w == "systemd") {
                changed = true;
                format!("{l} systemd")
            } else {
                l.to_string()
            }
        })
        .collect();
    if changed {
        let backup = format!("{path}.club-orig");
        if !Path::new(&backup).exists() {
            let _ = fs::copy(path, &backup);
        }
        io(fs::write(path, lines.join("\n") + "\n"), path)?;
    }
    Ok(())
}

fn setup_home(cfg: &Config) -> Result<(), String> {
    let base = &cfg.home_base;
    io(fs::create_dir_all(base), base)?;
    if cfg.home_pool_gb == 0 {
        println!("    using a plain directory (no quotas, shares the host disk)");
    } else if is_mounted(base) {
        println!("    already mounted");
    } else {
        let img = format!("{STATE_DIR}/home.img");
        if !Path::new(&img).exists() {
            println!("    creating {} GB sparse image", cfg.home_pool_gb);
            let f = io(fs::File::create(&img), &img)?;
            io(f.set_len(cfg.home_pool_gb << 30), &img)?;
            let with_quota = run("mkfs.ext4", &["-q", "-F", "-O", "quota", "-E", "quotatype=usrquota", &img]);
            if !with_quota && !run("mkfs.ext4", &["-q", "-F", &img]) {
                return Err("mkfs.ext4 failed".into());
            }
        }
        let fstab_line = |opts: &str| format!("{img} {base} ext4 {opts} 0 0 # club");
        set_fstab(&fstab_line("loop,nosuid,nodev,noatime,usrquota"))?;
        if !run("mount", &[base]) {
            warn("mounting with user quotas failed (kernel quota support missing?); falling back to no quotas");
            set_fstab(&fstab_line("loop,nosuid,nodev,noatime"))?;
            if !run("mount", &[base]) {
                return Err(format!("could not mount {img} on {base}"));
            }
        }
    }
    // traverse-only: members can reach their own home but cannot list each other's names
    let _ = fs::set_permissions(base, std::os::unix::fs::PermissionsExt::from_mode(0o711));
    Ok(())
}

fn set_fstab(line: &str) -> Result<(), String> {
    let text = fs::read_to_string("/etc/fstab").unwrap_or_default();
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim_end().ends_with("# club")).collect();
    lines.push(line);
    io(fs::write("/etc/fstab", lines.join("\n") + "\n"), "/etc/fstab")?;
    daemon_reload();
    Ok(())
}

fn strip_blocks(text: &str) -> String {
    let mut out = Vec::new();
    let mut skipping = false;
    for l in text.lines() {
        if l.starts_with("# BEGIN club") {
            skipping = true;
        }
        if !skipping {
            out.push(l);
        }
        if l.starts_with("# END club") {
            skipping = false;
        }
    }
    out.join("\n") + "\n"
}

fn insert_before(text: &str, needle: &str, block: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for l in text.lines() {
        if !done && !l.trim_start().starts_with('#') && l.contains(needle) {
            out.push_str(block);
            done = true;
        }
        out.push_str(l);
        out.push('\n');
    }
    if !done {
        return format!("{block}{out}");
    }
    out
}

pub fn patch_pam(text: &str) -> String {
    let clean = strip_blocks(text);
    let with_auth = insert_before(&clean, "common-auth", PAM_AUTH);
    insert_before(&with_auth, "common-account", PAM_ACCOUNT)
}

fn configure_ssh() -> Result<(), String> {
    let main = "/etc/ssh/sshd_config";
    let text = io(fs::read_to_string(main), main)?;
    if !text.lines().any(|l| l.trim_start().starts_with("Include") && l.contains("sshd_config.d")) {
        let backup = format!("{main}.club-orig");
        if !Path::new(&backup).exists() {
            let _ = fs::copy(main, &backup);
        }
        io(fs::write(main, format!("Include /etc/ssh/sshd_config.d/*.conf\n{text}")), main)?;
    }
    io(write_if_changed(Path::new(SSHD_DROPIN_PATH), SSHD_DROPIN), SSHD_DROPIN_PATH)?;

    let pam = io(fs::read_to_string(PAM_PATH), PAM_PATH)?;
    if !Path::new(PAM_BACKUP).exists() {
        io(fs::write(PAM_BACKUP, &pam), PAM_BACKUP)?;
    }
    io(write_if_changed(Path::new(PAM_PATH), &patch_pam(&pam)), PAM_PATH)?;

    // `sshd -T` refuses to run without this; normally the service creates it.
    let _ = fs::create_dir_all("/run/sshd");
    let sshd = if Path::new("/usr/sbin/sshd").exists() { "/usr/sbin/sshd" } else { "sshd" };
    let out = Command::new(sshd).arg("-T").output().map_err(|e| format!("{sshd}: {e}"))?;
    if !out.status.success() {
        let _ = fs::remove_file(SSHD_DROPIN_PATH);
        return Err(format!("sshd rejected the config: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let eff = String::from_utf8_lossy(&out.stdout).to_lowercase();
    if !eff.lines().any(|l| l.trim() == "passwordauthentication yes") {
        warn("sshd still reports PasswordAuthentication no; another file overrides ours. Check `sshd -T` and /etc/ssh/sshd_config.d/");
    }
    Ok(())
}

fn check_home_perms(cfg: &Config) {
    use std::os::unix::fs::MetadataExt;
    let Ok(rd) = fs::read_dir("/home") else { return };
    for e in rd.flatten() {
        if e.path() == Path::new(&cfg.home_base) {
            continue;
        }
        if let Ok(m) = e.metadata() {
            if m.is_dir() && m.mode() & 0o005 != 0 {
                warn(&format!(
                    "{} is readable by other users, so workspaces can read it. Fix: chmod o-rwx {}",
                    e.path().display(),
                    e.path().display()
                ));
            }
        }
    }
}

pub fn uninstall(args: &[String]) -> Result<(), String> {
    if !is_root() {
        return Err("run with sudo".into());
    }
    let purge = args.iter().any(|a| a == "--purge");
    let cfg = Config::load();
    step("stopping the service and removing sshd/PAM hooks");
    run("systemctl", &["disable", "--now", "club"]);
    let _ = fs::remove_file(UNIT_PATH);
    let _ = fs::remove_file(SSHD_DROPIN_PATH);
    if let Ok(pam) = fs::read_to_string(PAM_PATH) {
        let _ = fs::write(PAM_PATH, strip_blocks(&pam));
    }
    let _ = fs::remove_file(socket_file());
    run("systemctl", &["reload", ssh_service()]);
    daemon_reload();
    if purge {
        step("purging data");
        if is_mounted(&cfg.home_base) {
            run("umount", &[&cfg.home_base]);
        }
        if let Ok(text) = fs::read_to_string("/etc/fstab") {
            let kept: Vec<&str> = text.lines().filter(|l| !l.trim_end().ends_with("# club")).collect();
            let _ = fs::write("/etc/fstab", kept.join("\n") + "\n");
        }
        if let Ok(rd) = fs::read_dir("/etc/systemd/system") {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("user-") && e.path().join("50-club.conf").exists() {
                    let _ = fs::remove_file(e.path().join("50-club.conf"));
                    let _ = fs::remove_dir(e.path());
                }
            }
        }
        let _ = fs::remove_dir_all(CONF_DIR);
        let _ = fs::remove_dir_all(STATE_DIR);
        let _ = fs::remove_dir(&cfg.home_base);
        let _ = fs::remove_file(BIN_PATH);
        println!("    removed config, state and the home image. Plain-directory homes (if any) were left in {}.", cfg.home_base);
        daemon_reload();
    } else {
        println!("    kept /etc/club, /var/lib/club and all workspaces. Re-run `club install` to restore, or `club uninstall --purge` to erase.");
    }
    Ok(())
}

fn socket_file() -> String {
    crate::varlink::socket_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_SSHD: &str = "\
# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so

# Standard Un*x authorization.
@include common-account

session    required     pam_loginuid.so
";

    #[test]
    fn pam_patch_places_blocks_and_is_idempotent() {
        let once = patch_pam(UBUNTU_SSHD);
        let auth = once.find("club pam-auth").unwrap();
        let common_auth = once.find("@include common-auth").unwrap();
        let nologin = once.find("pam_nologin").unwrap();
        let acct = once.find("club pam-account").unwrap();
        let common_acct = once.find("@include common-account").unwrap();
        assert!(auth < common_auth, "auth hook goes before common-auth");
        assert!(nologin < acct && acct < common_acct, "account hook after nologin, before common-account");
        assert_eq!(patch_pam(&once), once, "second run changes nothing");
        assert_eq!(strip_blocks(&once).trim(), UBUNTU_SSHD.trim(), "uninstall restores the original");
    }

    #[test]
    fn unit_mentions_paths() {
        let u = unit(&Config::default());
        assert!(u.contains("ExecStart=/usr/local/bin/club serve"));
        assert!(u.contains("RequiresMountsFor=/home/club"));
    }
}
