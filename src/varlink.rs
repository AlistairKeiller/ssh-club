//! Varlink over a Unix socket: JSON messages, each ended by a NUL byte.
//! sshd (through nss-systemd) asks io.systemd.UserDatabase.* "does this user
//! exist?"; the PAM hook asks io.systemd.Club.Auth "is this password right?".

use crate::paths::*;
use crate::users::Users;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

const MAX_MESSAGE: u64 = 64 * 1024; // any local user can reach this socket
const TIMEOUT: Duration = Duration::from_secs(10);

fn error(name: &str) -> Value {
    json!({"error": name, "parameters": {}})
}

fn not_found() -> Value {
    error("io.systemd.UserDatabase.NoRecordFound")
}

/// Answer one request.
pub fn handle(users: &Users, req: &Value) -> Value {
    let p = &req["parameters"];
    match req["method"].as_str().unwrap_or("") {
        "io.systemd.Club.Auth" => {
            let ok = users.auth(p["name"].as_str().unwrap_or(""), p["password"].as_str().unwrap_or(""));
            json!({"parameters": {"ok": ok}})
        }
        "io.systemd.UserDatabase.GetUserRecord" => lookup(users, p, false),
        "io.systemd.UserDatabase.GetGroupRecord" => lookup(users, p, true),
        m if m.starts_with("io.systemd.UserDatabase.") => not_found(), // a user is only in their own group
        _ => error("org.varlink.service.MethodNotFound"),
    }
}

/// GetUserRecord / GetGroupRecord. Enumeration (no name, no id) is not supported.
fn lookup(users: &Users, p: &Value, group: bool) -> Value {
    // nss-systemd names the service after the socket.
    if !matches!(p["service"].as_str(), Some(SERVICE | "io.systemd.Multiplexer")) {
        return error("io.systemd.UserDatabase.BadService");
    }
    let name = p[if group { "groupName" } else { "userName" }].as_str();
    let id = p[if group { "gid" } else { "uid" }].as_u64();
    let found = match (name, id) {
        // user lookups may create a placeholder; group lookups never do
        (Some(n), _) => if group { users.uid_of(n) } else { users.lookup(n) }.map(|u| (n.to_string(), u)),
        (None, Some(i)) => users.name_of(i as u32).map(|n| (n, i as u32)),
        _ => None,
    };
    let Some((name, uid)) = found else { return not_found() };
    if id.is_some_and(|i| i != uid as u64) {
        return error("io.systemd.UserDatabase.ConflictingRecordFound");
    }
    let record = if group {
        json!({"groupName": name, "gid": uid, "disposition": "regular", "service": SERVICE})
    } else {
        json!({
            "userName": name, "uid": uid, "gid": uid, "realName": name,
            "homeDirectory": format!("{HOME_BASE}/{name}"), "shell": "/bin/bash",
            "disposition": "regular", "service": SERVICE,
        })
    };
    json!({"parameters": {"record": record, "incomplete": false}})
}

fn serve_connection(users: Arc<Users>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    let Ok(mut out) = stream.try_clone() else { return };
    let mut input = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = (&mut input).take(MAX_MESSAGE).read_until(0, &mut buf);
        if read.is_err() || buf.pop() != Some(0) {
            return; // closed, timed out, or longer than a message can be
        }
        let Ok(req) = serde_json::from_slice::<Value>(&buf) else { return };
        let mut reply = handle(&users, &req).to_string().into_bytes();
        reply.push(0);
        if out.write_all(&reply).is_err() {
            return;
        }
    }
}

pub fn serve(users: Arc<Users>) -> std::io::Result<()> {
    std::fs::create_dir_all(std::path::Path::new(SOCKET).parent().unwrap())?;
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    eprintln!("club: listening on {SOCKET}");
    for conn in listener.incoming().flatten() {
        let users = Arc::clone(&users);
        std::thread::spawn(move || serve_connection(users, conn));
    }
    Ok(())
}

/// Ask the running daemon whether this is the right password for `name`.
pub fn check_password(name: &str, password: &str) -> bool {
    let ask = || -> std::io::Result<Value> {
        let mut s = UnixStream::connect(SOCKET)?;
        // sshd waits on this during logins; a stuck daemon must not stall it forever
        s.set_read_timeout(Some(TIMEOUT))?;
        s.set_write_timeout(Some(TIMEOUT))?;
        let req = json!({"method": "io.systemd.Club.Auth", "parameters": {"name": name, "password": password}});
        s.write_all(format!("{req}\0").as_bytes())?;
        let mut buf = Vec::new();
        BufReader::new(s).read_until(0, &mut buf)?;
        buf.pop();
        Ok(serde_json::from_slice(&buf)?)
    };
    ask().is_ok_and(|reply| reply["parameters"]["ok"] == true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::test_users;

    fn ask(u: &Users, method: &str, p: Value) -> Value {
        handle(u, &json!({"method": method, "parameters": p}))
    }
    const GET_USER: &str = "io.systemd.UserDatabase.GetUserRecord";
    const GET_GROUP: &str = "io.systemd.UserDatabase.GetGroupRecord";
    const NOT_FOUND: &str = "io.systemd.UserDatabase.NoRecordFound";

    #[test]
    fn user_by_name_then_by_uid() {
        let u = test_users("vl-user");
        let r = ask(&u, GET_USER, json!({"userName": "alice", "service": SERVICE}));
        let rec = &r["parameters"]["record"];
        assert_eq!((rec["userName"].as_str(), rec["homeDirectory"].as_str()), (Some("alice"), Some("/home/club/alice")));
        let uid = rec["uid"].as_u64().unwrap();

        let r = ask(&u, GET_USER, json!({"uid": uid, "service": SERVICE}));
        assert_eq!(r["parameters"]["record"]["userName"], "alice");
        let r = ask(&u, GET_USER, json!({"userName": "alice", "uid": uid + 1, "service": SERVICE}));
        assert_eq!(r["error"], "io.systemd.UserDatabase.ConflictingRecordFound");
    }

    #[test]
    fn rejects_wrong_service_invalid_and_local_names() {
        let u = test_users("vl-bad");
        let e = |name: &str, svc: &str| ask(&u, GET_USER, json!({"userName": name, "service": svc}))["error"].clone();
        assert_eq!(e("alice", "io.systemd.Home"), "io.systemd.UserDatabase.BadService");
        assert_eq!(e("Not Valid!", SERVICE), NOT_FOUND);
        assert_eq!(e("root", SERVICE), NOT_FOUND);
        assert_eq!(ask(&u, GET_USER, json!({"service": SERVICE}))["error"], NOT_FOUND, "no enumeration");
    }

    #[test]
    fn group_lookups_never_create_placeholders() {
        let u = test_users("vl-grp");
        let group = |u: &Users| ask(u, GET_GROUP, json!({"groupName": "ghost", "service": SERVICE}));
        assert_eq!(group(&u)["error"], NOT_FOUND);
        ask(&u, GET_USER, json!({"userName": "ghost", "service": SERVICE}));
        assert_eq!(group(&u)["parameters"]["record"]["groupName"], "ghost");
    }

    #[test]
    fn auth_needs_the_password_and_a_prior_lookup() {
        let u = test_users("vl-auth");
        let auth = |pw: &str| ask(&u, "io.systemd.Club.Auth", json!({"name": "alice", "password": pw}))["parameters"]["ok"].clone();
        assert_eq!(auth("pw"), false, "sshd has not asked about alice yet");
        ask(&u, GET_USER, json!({"userName": "alice", "service": SERVICE}));
        assert_eq!(auth("wrong"), false);
        assert_eq!(auth("pw"), true);
    }
}
