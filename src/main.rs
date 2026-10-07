//! club: any username + one shared password = your own Linux account.
//! One binary: the daemon, the PAM hook, and the installer.

mod host;
mod install;
mod paths;
mod users;
mod varlink;

use std::io::Read;
use std::sync::Arc;

const HELP: &str = "\
club - any username + one shared password = your own account

  sudo club install     set everything up (safe to re-run)
  sudo club uninstall   remove the hooks (members' files stay)
";

fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("serve") => serve(),
        Some("pam-auth") => std::process::exit(pam_auth()),
        Some("install") => install::install(),
        Some("uninstall") => install::uninstall(),
        _ => return print!("{HELP}"),
    };
    if let Err(e) = result {
        eprintln!("club: {e}");
        std::process::exit(1);
    }
}

/// The daemon, run by systemd.
fn serve() -> Result<(), String> {
    let users = users::Users::new(paths::USERS_FILE.into(), paths::PASSWORD_FILE.into())?;
    varlink::serve(Arc::new(users)).map_err(|e| e.to_string())
}

/// sshd runs this (as root, through PAM) with the typed password on stdin.
fn pam_auth() -> i32 {
    let mut raw = Vec::new();
    if std::io::stdin().take(4096).read_to_end(&mut raw).is_err() {
        return 1;
    }
    let password = String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
    let name = std::env::var("PAM_USER").unwrap_or_default();
    if varlink::check_password(&name, &password) { 0 } else { 1 }
}
