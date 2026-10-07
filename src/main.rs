//! club: any username + one shared password = your own Linux account.
//!
//! One binary does everything:
//!   club install | uninstall      set up / remove the whole thing
//!   club serve                    the daemon (run by systemd)
//!   club list | delete | password | status | reap
//!   club pam-auth | pam-account   called by sshd's PAM stack

mod config;
mod install;
mod provision;
mod registry;
mod state;
mod varlink;

use config::{Config, PASSWORD_FILE};
use serde_json::json;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

const HELP: &str = "\
club - on-demand SSH workspaces

  sudo club install [--password PW] [--no-home-image]
  sudo club uninstall [--purge]
  sudo club list                 workspaces and when they were last used
  sudo club delete NAME          remove a workspace and its files
  sudo club password [--rotate]  show or change the shared password
  sudo club status
  sudo club reap                 delete workspaces idle past idle_delete_days
  club serve                     run the daemon (systemd does this)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("pam-auth") => pam_auth(),
        Some("pam-account") => pam_account(),
        Some("install") => report(install::install(&args[1..])),
        Some("uninstall") => report(install::uninstall(&args[1..])),
        Some("list") => report(list()),
        Some("delete") => report(delete(args.get(1))),
        Some("password") => report(password(&args[1..])),
        Some("status") => report(status()),
        Some("reap") => report(reap()),
        Some("version") | Some("--version") => {
            println!("club {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            print!("{HELP}");
            if args.is_empty() { 0 } else { 2 }
        }
    };
    std::process::exit(code);
}

fn report(r: Result<(), String>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("club: {e}");
            1
        }
    }
}

fn serve() -> i32 {
    let cfg = Config::load();
    let state = Arc::new(state::State::new(cfg));
    provision::apply_firewall(&state.cfg);
    state.sync_limits();

    if state.cfg.idle_delete_days > 0 {
        let st = Arc::clone(&state);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            let n = st.reap();
            if n > 0 {
                eprintln!("club: reaped {n} idle workspace(s)");
            }
        });
    }
    match varlink::serve(state) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("club: {e}");
            1
        }
    }
}

// ---- PAM: sshd runs these as root during login ------------------------------

fn pam_auth() -> i32 {
    let (Ok(name), rhost) = (std::env::var("PAM_USER"), std::env::var("PAM_RHOST").unwrap_or_default()) else {
        return 1;
    };
    let mut raw = Vec::new();
    if std::io::stdin().take(4096).read_to_end(&mut raw).is_err() {
        return 1;
    }
    // pam_exec terminates the token with NUL; be lenient about newlines too
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let password = String::from_utf8_lossy(&raw[..end]).trim_end_matches('\n').to_string();
    let reply = varlink::call("Auth", json!({"name": name, "password": password, "rhost": rhost}));
    match reply {
        Ok(v) if v["ok"] == true => 0,
        _ => 1,
    }
}

fn pam_account() -> i32 {
    let Ok(name) = std::env::var("PAM_USER") else { return 1 };
    match varlink::call("Known", json!({ "name": name })) {
        Ok(v) if v["ok"] == true => 0,
        _ => 1,
    }
}

// ---- admin commands ------------------------------------------------------------

fn need_root() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("this command needs root (use sudo)".into());
    }
    Ok(())
}

fn ago(ts: u64) -> String {
    if ts == 0 {
        return "never".into();
    }
    let d = registry::now().saturating_sub(ts);
    match d {
        0..=119 => "just now".into(),
        120..=7199 => format!("{}m ago", d / 60),
        7200..=172_799 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

fn list() -> Result<(), String> {
    need_root()?;
    let v = varlink::call("List", json!({}))?;
    let mut users: Vec<_> = v["users"].as_array().cloned().unwrap_or_default();
    users.sort_by_key(|u| std::cmp::Reverse(u["last_login"].as_u64().unwrap_or(0)));
    println!("{:<22} {:>6}  {:<10} {}", "NAME", "UID", "STATE", "LAST LOGIN");
    for u in &users {
        let uid = u["uid"].as_u64().unwrap_or(0) as u32;
        let state = if provision::session_active(uid) { "online" } else { "-" };
        println!(
            "{:<22} {:>6}  {:<10} {}",
            u["name"].as_str().unwrap_or("?"),
            uid,
            state,
            ago(u["last_login"].as_u64().unwrap_or(0))
        );
    }
    println!("\n{} workspace(s), limit {}", users.len(), v["max_users"]);
    Ok(())
}

fn delete(name: Option<&String>) -> Result<(), String> {
    need_root()?;
    let name = name.ok_or("usage: club delete NAME")?;
    let v = varlink::call("Delete", json!({ "name": name }))?;
    if v["ok"] == true {
        println!("deleted {name}");
        Ok(())
    } else {
        Err(format!("{name}: {}", v["reason"].as_str().unwrap_or("failed")))
    }
}

fn reap() -> Result<(), String> {
    need_root()?;
    let v = varlink::call("Reap", json!({}))?;
    println!("deleted {} idle workspace(s)", v["deleted"]);
    Ok(())
}

pub fn random_password() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 56, no look-alikes
    let mut out = String::new();
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    let mut b = [0u8; 1];
    while out.len() < 20 {
        f.read_exact(&mut b).expect("urandom");
        if b[0] < 224 {
            out.push(ALPHABET[(b[0] % 56) as usize] as char);
        }
    }
    out
}

pub fn write_password(pw: &str) -> Result<(), String> {
    std::fs::create_dir_all(config::CONF_DIR).map_err(|e| e.to_string())?;
    let tmp = format!("{PASSWORD_FILE}.tmp");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, format!("{pw}\n").as_bytes()))
        .and_then(|_| std::fs::rename(&tmp, PASSWORD_FILE))
        .map_err(|e| format!("writing {PASSWORD_FILE}: {e}"))
}

fn password(args: &[String]) -> Result<(), String> {
    need_root()?;
    if args.iter().any(|a| a == "--rotate") {
        let pw = random_password();
        write_password(&pw)?;
        println!("new password: {pw}");
        println!("(takes effect immediately; existing sessions and workspaces are untouched)");
    } else {
        let pw = std::fs::read_to_string(PASSWORD_FILE).map_err(|e| format!("{PASSWORD_FILE}: {e}"))?;
        println!("{}", pw.trim());
    }
    Ok(())
}

fn status() -> Result<(), String> {
    need_root()?;
    let cfg = Config::load();
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "club"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    println!("daemon:      {active}");
    match varlink::call("List", json!({})) {
        Ok(v) => println!(
            "workspaces:  {} of {}",
            v["users"].as_array().map(|a| a.len()).unwrap_or(0),
            v["max_users"]
        ),
        Err(e) => println!("workspaces:  ? ({e})"),
    }
    println!("homes:       {}", cfg.home_base);
    let _ = std::process::Command::new("df").args(["-h", &cfg.home_base]).status();
    Ok(())
}
