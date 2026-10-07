//! Varlink over a Unix socket: JSON messages, each ended by a NUL byte.
//! One socket, two audiences:
//!   io.systemd.UserDatabase.*  what nss-systemd/sshd ask (anyone may call)
//!   io.systemd.Club.*          what PAM and the admin commands ask (root only)

use crate::config::*;
use crate::users::Users;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

fn error(name: &str) -> Value {
    json!({"error": name, "parameters": {}})
}

fn udb_error(name: &str) -> Value {
    error(&format!("io.systemd.UserDatabase.{name}"))
}

/// Answer one request. Pure apart from the Users it is given, so it is testable.
pub fn handle(users: &Users, peer_uid: Option<u32>, req: &Value) -> Value {
    let method = req["method"].as_str().unwrap_or("");
    let p = &req["parameters"];

    if let Some(kind) = method.strip_prefix("io.systemd.UserDatabase.") {
        // nss-systemd names the service after the socket.
        if !matches!(p["service"].as_str(), Some(SERVICE | "io.systemd.Multiplexer")) {
            return udb_error("BadService");
        }
        return match kind {
            "GetUserRecord" => lookup(users, p, false),
            "GetGroupRecord" => lookup(users, p, true),
            _ => udb_error("NoRecordFound"), // memberships: a user is only in their own group
        };
    }

    if peer_uid != Some(0) || !method.starts_with("io.systemd.Club.") {
        return error("org.varlink.service.PermissionDenied");
    }
    let name = p["name"].as_str().unwrap_or("");
    let reply = match &method["io.systemd.Club.".len()..] {
        "Auth" => {
            let r = users.auth(name, p["password"].as_str().unwrap_or(""), p["rhost"].as_str().unwrap_or("-"));
            json!({"ok": r.is_ok(), "reason": r.err()})
        }
        "Delete" => json!({"ok": users.delete(name)}),
        "List" => json!({"members": users.members(), "max_users": users.cfg.max_users}),
        _ => return error("org.varlink.service.MethodNotFound"),
    };
    json!({"parameters": reply})
}

/// GetUserRecord / GetGroupRecord. Enumeration (no name, no id) is not supported.
fn lookup(users: &Users, p: &Value, group: bool) -> Value {
    let name = p[if group { "groupName" } else { "userName" }].as_str();
    let id = p[if group { "gid" } else { "uid" }].as_u64();
    let found = match (name, id) {
        // user lookups may create a placeholder; group lookups never do
        (Some(n), _) => if group { users.uid_of(n) } else { users.lookup(n) }.map(|u| (n.to_string(), u)),
        (None, Some(i)) => users.name_of(i as u32).map(|n| (n, i as u32)),
        _ => None,
    };
    let Some((name, uid)) = found else { return udb_error("NoRecordFound") };
    if id.is_some_and(|i| i != uid as u64) {
        return udb_error("ConflictingRecordFound");
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

#[cfg(target_os = "linux")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len outlive the call and have the sizes getsockopt expects.
    let rc = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut len)
    };
    (rc == 0).then_some(cred.uid)
}

/// No SO_PEERCRED off Linux; lets the tests run on a Mac. Club only ships for Linux.
#[cfg(not(target_os = "linux"))]
fn peer_uid(_: &UnixStream) -> Option<u32> {
    Some(0)
}

fn serve_connection(users: Arc<Users>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let peer = peer_uid(&stream);
    let Ok(mut out) = stream.try_clone() else { return };
    let mut input = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if !matches!(input.read_until(0, &mut buf), Ok(n) if n > 0) {
            return;
        }
        buf.pop(); // the NUL
        let Ok(req) = serde_json::from_slice::<Value>(&buf) else { return };
        let mut reply = serde_json::to_vec(&handle(&users, peer, &req)).unwrap_or_default();
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

/// Call the running daemon (admin methods). Returns the reply's parameters.
pub fn call(method: &str, params: Value) -> Result<Value, String> {
    let mut s = UnixStream::connect(SOCKET).map_err(|e| format!("cannot reach the club daemon ({e})"))?;
    let mut req = json!({"method": format!("io.systemd.Club.{method}"), "parameters": params}).to_string().into_bytes();
    req.push(0);
    s.write_all(&req).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    BufReader::new(s).read_until(0, &mut buf).map_err(|e| e.to_string())?;
    buf.pop();
    let reply: Value = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
    match reply["error"].as_str() {
        Some(e) => Err(e.to_string()),
        None => Ok(reply["parameters"].clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::test_users;

    fn ask(u: &Users, peer: Option<u32>, method: &str, p: Value) -> Value {
        handle(u, peer, &json!({"method": method, "parameters": p}))
    }
    const GET_USER: &str = "io.systemd.UserDatabase.GetUserRecord";
    const GET_GROUP: &str = "io.systemd.UserDatabase.GetGroupRecord";

    #[test]
    fn user_by_name_then_by_uid() {
        let u = test_users("vl-user");
        let r = ask(&u, Some(1000), GET_USER, json!({"userName": "alice", "service": SERVICE}));
        let rec = &r["parameters"]["record"];
        assert_eq!((rec["userName"].as_str(), rec["homeDirectory"].as_str()), (Some("alice"), Some("/home/club/alice")));
        let uid = rec["uid"].as_u64().unwrap();

        let r = ask(&u, None, GET_USER, json!({"uid": uid, "service": SERVICE}));
        assert_eq!(r["parameters"]["record"]["userName"], "alice");
        let r = ask(&u, None, GET_USER, json!({"userName": "alice", "uid": uid + 1, "service": SERVICE}));
        assert_eq!(r["error"], "io.systemd.UserDatabase.ConflictingRecordFound");
    }

    #[test]
    fn rejects_wrong_service_invalid_and_local_names() {
        let u = test_users("vl-bad");
        let e = |name: &str, svc: &str| ask(&u, None, GET_USER, json!({"userName": name, "service": svc}))["error"].clone();
        assert_eq!(e("alice", "io.systemd.Home"), "io.systemd.UserDatabase.BadService");
        assert_eq!(e("Not Valid!", SERVICE), "io.systemd.UserDatabase.NoRecordFound");
        assert_eq!(e("root", SERVICE), "io.systemd.UserDatabase.NoRecordFound");
        let r = ask(&u, None, GET_USER, json!({"service": SERVICE}));
        assert_eq!(r["error"], "io.systemd.UserDatabase.NoRecordFound", "enumeration is unsupported");
    }

    #[test]
    fn group_lookups_never_allocate() {
        let u = test_users("vl-grp");
        let group = |u: &Users| ask(u, None, GET_GROUP, json!({"groupName": "ghost", "service": SERVICE}));
        assert_eq!(group(&u)["error"], "io.systemd.UserDatabase.NoRecordFound");
        ask(&u, None, GET_USER, json!({"userName": "ghost", "service": SERVICE}));
        assert_eq!(group(&u)["parameters"]["record"]["groupName"], "ghost");
    }

    #[test]
    fn club_methods_are_root_only() {
        let u = test_users("vl-admin");
        ask(&u, None, GET_USER, json!({"userName": "alice", "service": SERVICE}));
        let args = json!({"name": "alice", "password": "pw", "rhost": "1.2.3.4"});
        let denied = ask(&u, Some(1000), "io.systemd.Club.Auth", args.clone());
        assert_eq!(denied["error"], "org.varlink.service.PermissionDenied");
        let ok = ask(&u, Some(0), "io.systemd.Club.Auth", args);
        assert_eq!(ok["parameters"]["ok"], true);
        assert_eq!(ask(&u, Some(0), "io.systemd.Club.List", json!({}))["parameters"]["members"][0][0], "alice");
    }
}
