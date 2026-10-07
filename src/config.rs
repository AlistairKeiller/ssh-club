//! Fixed paths, and the few settings in /etc/club/club.conf.

use std::path::PathBuf;

pub const SERVICE: &str = "io.systemd.Club";
pub const SOCKET: &str = "/run/systemd/userdb/io.systemd.Club";
pub const CONF_DIR: &str = "/etc/club";
pub const CONF_FILE: &str = "/etc/club/club.conf";
pub const PASSWORD_FILE: &str = "/etc/club/password";
pub const STATE_DIR: &str = "/var/lib/club";
pub const BIN: &str = "/usr/local/bin/club";
pub const HOME_BASE: &str = "/home/club";
/// The uids club hands out (also what the firewall rule matches).
pub const UID_RANGE: (u32, u32) = (20_000, 29_999);

#[derive(Clone)]
pub struct Config {
    pub max_users: usize,
    pub mem_high: String,
    pub mem_max: String,
    pub disk_quota_gb: u64,
    pub home_pool_gb: u64,
    pub idle_delete_days: u64,
    // overridable so tests never touch the host
    pub state_dir: PathBuf,
    pub password_file: PathBuf,
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_users: 500,
            mem_high: "2G".into(),
            mem_max: "3G".into(),
            disk_quota_gb: 5,
            home_pool_gb: 100,
            idle_delete_days: 0,
            state_dir: STATE_DIR.into(),
            password_file: PASSWORD_FILE.into(),
            dry_run: false,
        }
    }
}

impl Config {
    pub fn load() -> Config {
        let mut c = Config::default();
        let text = std::fs::read_to_string(CONF_FILE).unwrap_or_default();
        for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "max_users" => c.max_users = v.parse().unwrap_or(c.max_users),
                "mem_high" => c.mem_high = v.into(),
                "mem_max" => c.mem_max = v.into(),
                "disk_quota_gb" => c.disk_quota_gb = v.parse().unwrap_or(c.disk_quota_gb),
                "home_pool_gb" => c.home_pool_gb = v.parse().unwrap_or(c.home_pool_gb),
                "idle_delete_days" => c.idle_delete_days = v.parse().unwrap_or(0),
                other => eprintln!("club: ignoring unknown setting '{other}'"),
            }
        }
        c
    }
}

pub const CONF_TEMPLATE: &str = "\
# Restart after editing:  sudo systemctl restart club

# Most workspaces that may exist.
max_users = 500

# Per-user memory: throttled above mem_high, killed above mem_max.
mem_high = 2G
mem_max = 3G

# Per-user disk quota in GB (0 = none; also skips ext4 quota setup).
disk_quota_gb = 5

# Size of the sparse image holding every home, in GB. Members can fill this
# but never the host disk. 0 = plain directory on the host disk.
# Changing it needs a manual reformat; see the README.
home_pool_gb = 100

# Delete workspaces unused for this many days (0 = never).
idle_delete_days = 0
";
