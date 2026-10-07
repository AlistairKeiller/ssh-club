//! club: any username + one shared password = your own Linux account.
//! One binary: the daemon, the PAM hook, the installer and the admin tool.

mod config;
mod host;
mod install;
mod users;
mod varlink;

use config::*;
use serde_json::json;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

const HELP: &str = "\
club - on-demand SSH workspaces

  sudo club install              set everything up (safe to re-run)
  sudo club uninstall            remove the hooks (keeps members' files)
  sudo club list                 members and when they last logged in
  sudo club delete NAME          remove a member and their files
  sudo club password [--rotate]  show or change the shared password
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("pam-auth") => std::process::exit(pam_auth()),
        Some("install") => install::install(),
        Some("uninstall") => install::uninstall(),
        Some("list") => list(),
        Some("delete") => delete(args.get(1)),
        Some("password") => password(args.get(1).is_some_and(|a| a == "--rotate")),
        _ => return print!("{HELP}"),
    };
    if let Err(e) = result {
        eprintln!("club: {e}");
        std::process::exit(1);
    }
}

fn serve() -> Result<(), String> {
    let users = Arc::new(users::Users::new(Config::load()));
    host::block_metadata(&users.cfg);
    if users.cfg.idle_delete_days > 0 {
        let users = Arc::clone(&users);
        std::thread::spawn(move || loop {
            users.reap();
            std::thread::sleep(std::time::Duration::from_secs(3600));
        });
    }
    varlink::serve(users).map_err(|e| e.to_string())
}

/// sshd runs this (as root, via PAM) with the typed password on stdin.
fn pam_auth() -> i32 {
    let var = |k| std::env::var(k).unwrap_or_default();
    let mut raw = Vec::new();
    if std::io::stdin().take(4096).read_to_end(&mut raw).is_err() {
        return 1;
    }
    let password = String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
    let args = json!({"name": var("PAM_USER"), "password": password, "rhost": var("PAM_RHOST")});
    match varlink::call("Auth", args) {
        Ok(r) if r["ok"] == true => 0,
        _ => 1,
    }
}

pub fn need_root() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    match unsafe { libc::geteuid() } {
        0 => Ok(()),
        _ => Err("run this with sudo".into()),
    }
}

fn list() -> Result<(), String> {
    need_root()?;
    let reply = varlink::call("List", json!({}))?;
    let mut members: Vec<(String, u32, u64)> = serde_json::from_value(reply["members"].clone()).unwrap_or_default();
    members.sort_by_key(|m| std::cmp::Reverse(m.2));
    println!("{:<22} {:>6}  {:<7} LAST LOGIN", "NAME", "UID", "STATE");
    for (name, uid, last) in &members {
        let state = if host::online(*uid) { "online" } else { "-" };
        let age = users::now().saturating_sub(*last);
        let when = match age {
            0..=119 => "just now".into(),
            120..=7199 => format!("{}m ago", age / 60),
            7200..=172_799 => format!("{}h ago", age / 3600),
            _ => format!("{}d ago", age / 86_400),
        };
        println!("{name:<22} {uid:>6}  {state:<7} {when}");
    }
    println!("\n{} of {} members", members.len(), reply["max_users"]);
    Ok(())
}

fn delete(name: Option<&String>) -> Result<(), String> {
    need_root()?;
    let name = name.ok_or("usage: club delete NAME")?;
    match varlink::call("Delete", json!({ "name": name }))?["ok"] == true {
        true => Ok(println!("deleted {name}")),
        false => Err(format!("no such member: {name}")),
    }
}

/// Write a fresh random shared password (20 characters, no look-alikes).
pub fn rotate_password() -> Result<String, String> {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 56
    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut pw = String::new();
    while pw.len() < 20 {
        let mut b = [0u8; 1];
        urandom.read_exact(&mut b).map_err(|e| e.to_string())?;
        if b[0] < 224 {
            // 224 = 4 * 56, so the modulo below is unbiased
            pw.push(ALPHABET[b[0] as usize % 56] as char);
        }
    }
    std::fs::create_dir_all(CONF_DIR).map_err(|e| e.to_string())?;
    let opened = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(PASSWORD_FILE);
    std::io::Write::write_all(&mut opened.map_err(|e| e.to_string())?, format!("{pw}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(pw)
}

fn password(rotate: bool) -> Result<(), String> {
    need_root()?;
    let pw = if rotate {
        rotate_password()?
    } else {
        std::fs::read_to_string(PASSWORD_FILE).map_err(|e| format!("{PASSWORD_FILE}: {e}"))?.trim().into()
    };
    Ok(println!("{pw}"))
}
