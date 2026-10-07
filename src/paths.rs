//! Fixed installation paths. There is no configuration file.

pub const SERVICE: &str = "io.systemd.Club";
pub const SOCKET: &str = "/run/systemd/userdb/io.systemd.Club";
pub const CONF_DIR: &str = "/etc/club";
pub const PASSWORD_FILE: &str = "/etc/club/password";
pub const STATE_DIR: &str = "/var/lib/club";
pub const USERS_FILE: &str = "/var/lib/club/users";
pub const BIN: &str = "/usr/local/bin/club";
pub const HOME_BASE: &str = "/home/club";
/// The uids club hands out.
pub const UID_RANGE: (u32, u32) = (20_000, 29_999);
