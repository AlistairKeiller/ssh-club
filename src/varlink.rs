//! Minimal Varlink over a Unix socket: JSON messages terminated by NUL.
//!
//! The same socket speaks two dialects:
//!   io.systemd.UserDatabase.*  - what nss-systemd/sshd ask (anyone may call)
//!   io.systemd.Club.*          - admin/PAM calls (root only)

use crate::config::{SERVICE, SOCKET_DIR};
use crate::state::State;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

const UDB: &str = "io.systemd.UserDatabase";
const ADMIN: &str = "io.systemd.Club";

pub fn socket_path() -> String {
    format!("{SOCKET_DIR}/{SERVICE}")
}

fn err(name: &str) -> Vec<Value> {
    vec![json!({"error": name, "parameters": {}})]
}

fn udb_err(name: &str) -> Vec<Value> {
    err(&format!("{UDB}.{name}"))
}

fn reply(params: Value) -> Value {
    json!({"parameters": params})
}

/// Turn one request into the replies to send. Pure, so it is easy to test.
pub fn handle(state: &State, peer_uid: Option<u32>, req: &Value) -> Vec<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let p = req.get("parameters").cloned().unwrap_or(json!({}));
    let more = req.get("more").and_then(|m| m.as_bool()).unwrap_or(false);
    let s = |k: &str| p.get(k).and_then(|v| v.as_str());

    if let Some(m) = method.strip_prefix(&format!("{UDB}.")) {
        // nss-systemd names the service after the socket; userdbd forwards as such.
        match s("service") {
            Some(svc) if svc == SERVICE || svc == "io.systemd.Multiplexer" => {}
            _ => return udb_err("BadService"),
        }
        return match m {
            "GetUserRecord" => get_user(state, &p, more),
            "GetGroupRecord" => get_group(state, &p, more),
            "GetMemberships" => udb_err("NoRecordFound"),
            _ => err("org.varlink.service.MethodNotFound"),
        };
    }

    if let Some(m) = method.strip_prefix(&format!("{ADMIN}.")) {
        if peer_uid != Some(0) {
            return err("org.varlink.service.PermissionDenied");
        }
        return match m {
            "Auth" => {
                let name = s("name").unwrap_or("");
                let ok = state.auth(name, s("password").unwrap_or(""), s("rhost").unwrap_or(""));
                vec![reply(match ok {
                    Ok(()) => json!({"ok": true}),
                    Err(why) => json!({"ok": false, "reason": why}),
                })]
            }
            "Known" => vec![reply(json!({"ok": state.is_known(s("name").unwrap_or(""))}))],
            "Delete" => vec![reply(match state.delete(s("name").unwrap_or("")) {
                Ok(()) => json!({"ok": true}),
                Err(why) => json!({"ok": false, "reason": why}),
            })],
            "Reap" => vec![reply(json!({"deleted": state.reap()}))],
            "List" => {
                let users: Vec<Value> = state
                    .authed_users()
                    .iter()
                    .map(|u| json!({"name": u.name, "uid": u.uid, "last_login": u.last_login}))
                    .collect();
                let pending = state.reg.lock().unwrap().pending_count();
                vec![reply(json!({"users": users, "pending": pending, "max_users": state.cfg.max_users}))]
            }
            _ => err("org.varlink.service.MethodNotFound"),
        };
    }

    err("org.varlink.service.MethodNotFound")
}

fn user_reply(state: &State, name: &str, uid: u32) -> Value {
    reply(json!({"record": state.user_record(name, uid), "incomplete": false}))
}

fn group_reply(state: &State, name: &str, uid: u32) -> Value {
    reply(json!({"record": state.group_record(name, uid), "incomplete": false}))
}

fn in_range(p: &Value, uid: u32) -> bool {
    let min = p.get("uidMin").and_then(|v| v.as_u64()).unwrap_or(0);
    let max = p.get("uidMax").and_then(|v| v.as_u64()).unwrap_or(u32::MAX as u64);
    (uid as u64) >= min && (uid as u64) <= max
}

fn get_user(state: &State, p: &Value, more: bool) -> Vec<Value> {
    let name = p.get("userName").and_then(|v| v.as_str());
    let uid = p.get("uid").and_then(|v| v.as_u64());
    match (name, uid) {
        (Some(name), uid) => {
            let Some(found) = state.lookup_name(name) else { return udb_err("NoRecordFound") };
            if matches!(uid, Some(u) if u != found as u64) {
                return udb_err("ConflictingRecordFound");
            }
            if !in_range(p, found) {
                return udb_err("NonMatchingRecordFound");
            }
            vec![user_reply(state, name, found)]
        }
        (None, Some(uid)) => match state.find_uid(uid as u32) {
            Some(name) if in_range(p, uid as u32) => vec![user_reply(state, &name, uid as u32)],
            _ => udb_err("NoRecordFound"),
        },
        (None, None) => {
            if !more {
                return udb_err("EnumerationNotSupported");
            }
            let all: Vec<Value> = state
                .authed_users()
                .iter()
                .filter(|u| in_range(p, u.uid))
                .map(|u| user_reply(state, &u.name, u.uid))
                .collect();
            if all.is_empty() { udb_err("NoRecordFound") } else { all }
        }
    }
}

fn get_group(state: &State, p: &Value, more: bool) -> Vec<Value> {
    let name = p.get("groupName").and_then(|v| v.as_str());
    let gid = p.get("gid").and_then(|v| v.as_u64());
    match (name, gid) {
        (Some(name), gid) => {
            // never allocate for group lookups; the user lookup already did
            let Some(found) = state.find_name(name) else { return udb_err("NoRecordFound") };
            if matches!(gid, Some(g) if g != found as u64) {
                return udb_err("ConflictingRecordFound");
            }
            vec![group_reply(state, name, found)]
        }
        (None, Some(gid)) => match state.find_uid(gid as u32) {
            Some(name) => vec![group_reply(state, &name, gid as u32)],
            None => udb_err("NoRecordFound"),
        },
        (None, None) => {
            if !more {
                return udb_err("EnumerationNotSupported");
            }
            let all: Vec<Value> = state
                .authed_users()
                .iter()
                .map(|u| group_reply(state, &u.name, u.uid))
                .collect();
            if all.is_empty() { udb_err("NoRecordFound") } else { all }
        }
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len are valid for the duration of the call.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0).then_some(cred.uid)
}

/// Development hosts (macOS) have no SO_PEERCRED; club only ships on Linux.
#[cfg(not(target_os = "linux"))]
fn peer_uid(_: &UnixStream) -> Option<u32> {
    Some(0)
}

fn serve_conn(state: Arc<State>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let peer = peer_uid(&stream);
    let mut out = match stream.try_clone() {
        Ok(o) => o,
        Err(_) => return,
    };
    let mut rd = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match rd.read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        let Ok(req) = serde_json::from_slice::<Value>(&buf) else { return };
        if req.get("oneway").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        let mut replies = handle(&state, peer, &req);
        let last = replies.len().saturating_sub(1);
        for (i, r) in replies.iter_mut().enumerate() {
            if i < last {
                r["continues"] = json!(true);
            }
            let mut bytes = serde_json::to_vec(r).unwrap_or_default();
            bytes.push(0);
            if out.write_all(&bytes).is_err() {
                return;
            }
        }
    }
}

pub fn serve(state: Arc<State>) -> std::io::Result<()> {
    let path = socket_path();
    std::fs::create_dir_all(SOCKET_DIR)?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    eprintln!("club: listening on {path}");
    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || serve_conn(st, c));
            }
            Err(e) => eprintln!("club: accept: {e}"),
        }
    }
    Ok(())
}

/// One call to the running daemon. Returns the `parameters` of the reply.
pub fn call(method: &str, params: Value) -> Result<Value, String> {
    let mut s = UnixStream::connect(socket_path()).map_err(|e| format!("cannot reach club daemon ({e}); is `club` running?"))?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let mut req = serde_json::to_vec(&json!({"method": format!("{ADMIN}.{method}"), "parameters": params}))
        .map_err(|e| e.to_string())?;
    req.push(0);
    s.write_all(&req).map_err(|e| e.to_string())?;
    let mut rd = BufReader::new(s);
    let mut buf = Vec::new();
    rd.read_until(0, &mut buf).map_err(|e| e.to_string())?;
    if buf.last() == Some(&0) {
        buf.pop();
    }
    let v: Value = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
    if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
        return Err(e.to_string());
    }
    Ok(v.get("parameters").cloned().unwrap_or(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state;

    fn state(tag: &str) -> State {
        let d = std::env::temp_dir().join(format!("club-vl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        test_state(&d, "pw")
    }

    fn req(method: &str, params: Value) -> Value {
        json!({"method": method, "parameters": params})
    }

    #[test]
    fn user_by_name_then_uid() {
        let s = state("user");
        let r = handle(&s, Some(1000), &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "alice", "service": SERVICE})));
        assert_eq!(r.len(), 1);
        let rec = &r[0]["parameters"]["record"];
        assert_eq!(rec["userName"], "alice");
        assert_eq!(rec["homeDirectory"], "/home/club/alice");
        assert_eq!(rec["disposition"], "regular");
        let uid = rec["uid"].as_u64().unwrap();

        let r = handle(&s, Some(1000), &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"uid": uid, "service": SERVICE})));
        assert_eq!(r[0]["parameters"]["record"]["userName"], "alice");

        let r = handle(&s, Some(1000), &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "alice", "uid": uid + 1, "service": SERVICE})));
        assert_eq!(r[0]["error"], "io.systemd.UserDatabase.ConflictingRecordFound");
    }

    #[test]
    fn rejects_bad_service_and_bad_names() {
        let s = state("bad");
        let r = handle(&s, None, &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "alice", "service": "io.systemd.Home"})));
        assert_eq!(r[0]["error"], "io.systemd.UserDatabase.BadService");
        let r = handle(&s, None, &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "Not Valid!", "service": SERVICE})));
        assert_eq!(r[0]["error"], "io.systemd.UserDatabase.NoRecordFound");
        let r = handle(&s, None, &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "root", "service": SERVICE})));
        assert_eq!(r[0]["error"], "io.systemd.UserDatabase.NoRecordFound");
    }

    #[test]
    fn groups_never_allocate() {
        let s = state("grp");
        let r = handle(&s, None, &req(
            "io.systemd.UserDatabase.GetGroupRecord",
            json!({"groupName": "ghost", "service": SERVICE})));
        assert_eq!(r[0]["error"], "io.systemd.UserDatabase.NoRecordFound");
        handle(&s, None, &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "ghost", "service": SERVICE})));
        let r = handle(&s, None, &req(
            "io.systemd.UserDatabase.GetGroupRecord",
            json!({"groupName": "ghost", "service": SERVICE})));
        assert_eq!(r[0]["parameters"]["record"]["groupName"], "ghost");
    }

    #[test]
    fn admin_methods_need_root() {
        let s = state("adm");
        let r = handle(&s, Some(1000), &req("io.systemd.Club.Auth", json!({"name": "a", "password": "pw"})));
        assert_eq!(r[0]["error"], "org.varlink.service.PermissionDenied");
        handle(&s, None, &req(
            "io.systemd.UserDatabase.GetUserRecord",
            json!({"userName": "alice", "service": SERVICE})));
        let r = handle(&s, Some(0), &req("io.systemd.Club.Auth", json!({"name": "alice", "password": "pw", "rhost": "1.2.3.4"})));
        assert_eq!(r[0]["parameters"]["ok"], true);
        let r = handle(&s, Some(0), &req("io.systemd.Club.Known", json!({"name": "alice"})));
        assert_eq!(r[0]["parameters"]["ok"], true);
    }

    #[test]
    fn enumeration_streams_authed_users() {
        let s = state("enum");
        for n in ["amy", "ben"] {
            s.lookup_name(n).unwrap();
            s.auth(n, "pw", "x").unwrap();
        }
        let mut q = req("io.systemd.UserDatabase.GetUserRecord", json!({"service": SERVICE}));
        q["more"] = json!(true);
        assert_eq!(handle(&s, None, &q).len(), 2);
        q["more"] = json!(false);
        assert_eq!(handle(&s, None, &q)[0]["error"], "io.systemd.UserDatabase.EnumerationNotSupported");
    }
}
