//! Settings, read from /etc/club/club.conf (`key = value`, `#` comments).

use std::path::PathBuf;

pub const SERVICE: &str = "io.systemd.Club";
pub const SOCKET_DIR: &str = "/run/systemd/userdb";
pub const CONF_DIR: &str = "/etc/club";
pub const CONF_FILE: &str = "/etc/club/club.conf";
pub const PASSWORD_FILE: &str = "/etc/club/password";
pub const STATE_DIR: &str = "/var/lib/club";
pub const BIN_PATH: &str = "/usr/local/bin/club";

/// Width of the uid window owned by club (used for firewall rules).
pub const UID_SPAN: u32 = 10_000;

#[derive(Clone, Debug)]
pub struct Config {
    pub home_base: String,
    pub uid_min: u32,
    pub max_users: usize,
    pub mem_high: String,
    pub mem_max: String,
    pub tasks_max: String,
    pub cpu_quota: String,
    pub disk_quota_gb: u64,
    pub home_pool_gb: u64,
    pub idle_delete_days: u64,
    pub shell: String,
    pub block_cidrs: Vec<String>,
    pub state_dir: PathBuf,
    pub password_file: PathBuf,
    /// Skip every side effect outside our own state (tests).
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            home_base: "/home/club".into(),
            uid_min: 20_000,
            max_users: 500,
            mem_high: "2G".into(),
            mem_max: "3G".into(),
            tasks_max: "1500".into(),
            cpu_quota: String::new(),
            disk_quota_gb: 5,
            home_pool_gb: 100,
            idle_delete_days: 0,
            shell: "/bin/bash".into(),
            block_cidrs: Vec::new(),
            state_dir: STATE_DIR.into(),
            password_file: PASSWORD_FILE.into(),
            dry_run: false,
        }
    }
}

impl Config {
    pub fn load() -> Config {
        match std::fs::read_to_string(CONF_FILE) {
            Ok(text) => Config::parse(&text),
            Err(_) => Config::default(),
        }
    }

    pub fn parse(text: &str) -> Config {
        let mut c = Config::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "home_base" => c.home_base = v.trim_end_matches('/').into(),
                "uid_min" => c.uid_min = v.parse().unwrap_or(c.uid_min),
                "max_users" => c.max_users = v.parse().unwrap_or(c.max_users),
                "mem_high" => c.mem_high = v.into(),
                "mem_max" => c.mem_max = v.into(),
                "tasks_max" => c.tasks_max = v.into(),
                "cpu_quota" => c.cpu_quota = v.into(),
                "disk_quota_gb" => c.disk_quota_gb = v.parse().unwrap_or(c.disk_quota_gb),
                "home_pool_gb" => c.home_pool_gb = v.parse().unwrap_or(c.home_pool_gb),
                "idle_delete_days" => c.idle_delete_days = v.parse().unwrap_or(0),
                "shell" => c.shell = v.into(),
                "block_cidrs" => {
                    c.block_cidrs = v
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
                _ => eprintln!("club: ignoring unknown config key '{k}'"),
            }
        }
        c.max_users = c.max_users.min((UID_SPAN as usize) - 500);
        c
    }

    pub fn uid_max(&self) -> u32 {
        self.uid_min + UID_SPAN - 1
    }
}

pub const CONF_TEMPLATE: &str = "\
# club settings. Restart after editing:  sudo systemctl restart club
# Run `club install` again to re-apply sshd/PAM/mount changes.

# Where workspaces live. A loopback filesystem is mounted here (see home_pool_gb).
home_base = /home/club

# First uid handed out. Club owns uid_min .. uid_min+9999.
uid_min = 20000

# Most workspaces that may exist at once.
max_users = 500

# Per-user memory: throttle above mem_high, hard kill above mem_max.
mem_high = 2G
mem_max = 3G

# Per-user process limit.
tasks_max = 1500

# Optional per-user CPU cap, e.g. 200% for two cores. Empty = fair share only.
cpu_quota =

# Per-user disk quota in GB (0 = off). Needs ext4 quota support in the kernel.
disk_quota_gb = 5

# Size of the sparse loopback filesystem holding all homes, in GB. Fills up
# without hurting the host. 0 = just use a normal directory (no quotas).
home_pool_gb = 100

# Delete workspaces unused for this many days (0 = never delete).
idle_delete_days = 0

shell = /bin/bash

# Networks workspaces may NOT reach, comma separated (e.g. your VCN: 10.0.0.0/16).
# The cloud metadata service and outbound SMTP are always blocked.
block_cidrs =
";
