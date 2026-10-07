//! Shared daemon state and the rules of the system: who exists, who may log
//! in, when workspaces are created and removed.

use crate::config::Config;
use crate::provision;
use crate::registry::{local_names, now, valid_name, Entry, Registry, PENDING_MAX};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW: u64 = 60;

pub struct State {
    pub cfg: Config,
    pub reg: Mutex<Registry>,
    fails: Mutex<HashMap<String, (u32, u64)>>,
}

pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub last_login: u64,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

impl State {
    pub fn new(cfg: Config) -> State {
        let reg = Registry::load(&cfg.state_dir);
        State { cfg, reg: Mutex::new(reg), fails: Mutex::new(HashMap::new()) }
    }

    pub fn user_record(&self, name: &str, uid: u32) -> Value {
        json!({
            "userName": name,
            "uid": uid,
            "gid": uid,
            "realName": name,
            "homeDirectory": format!("{}/{}", self.cfg.home_base, name),
            "shell": self.cfg.shell,
            "disposition": "regular",
            "service": crate::config::SERVICE,
            "locked": false,
        })
    }

    pub fn group_record(&self, name: &str, uid: u32) -> Value {
        json!({
            "groupName": name,
            "gid": uid,
            "disposition": "regular",
            "service": crate::config::SERVICE,
        })
    }

    /// uid for `name`, creating a short-lived pending entry for unknown but
    /// valid names so sshd will let the login attempt proceed to the password.
    pub fn lookup_name(&self, name: &str) -> Option<u32> {
        if !valid_name(name) {
            return None;
        }
        let mut reg = self.reg.lock().unwrap();
        if let Some(e) = reg.users.get(name) {
            return Some(e.uid);
        }
        if local_names().contains(name) {
            return None;
        }
        let t = now();
        reg.prune_pending(t);
        if reg.pending_count() >= PENDING_MAX || reg.authed_count() >= self.cfg.max_users {
            return None;
        }
        let uid = reg.alloc_uid(self.cfg.uid_min, self.cfg.uid_max())?;
        reg.users.insert(
            name.to_string(),
            Entry { uid, authed: false, created: 0, last_login: 0, seen: t },
        );
        Some(uid)
    }

    /// Existing entries only; never allocates.
    pub fn find_name(&self, name: &str) -> Option<u32> {
        self.reg.lock().unwrap().users.get(name).map(|e| e.uid)
    }

    pub fn find_uid(&self, uid: u32) -> Option<String> {
        self.reg.lock().unwrap().name_of(uid).cloned()
    }

    pub fn authed_users(&self) -> Vec<UserInfo> {
        let reg = self.reg.lock().unwrap();
        reg.users
            .iter()
            .filter(|(_, e)| e.authed)
            .map(|(n, e)| UserInfo { name: n.clone(), uid: e.uid, last_login: e.last_login })
            .collect()
    }

    pub fn is_known(&self, name: &str) -> bool {
        self.reg.lock().unwrap().users.get(name).map(|e| e.authed).unwrap_or(false)
    }

    fn throttled(&self, rhost: &str) -> bool {
        let t = now();
        let mut f = self.fails.lock().unwrap();
        if f.len() > 10_000 {
            f.clear();
        }
        match f.get(rhost) {
            Some(&(n, start)) if t.saturating_sub(start) < FAIL_WINDOW => n >= FAIL_LIMIT,
            _ => false,
        }
    }

    fn note_failure(&self, rhost: &str) {
        let t = now();
        let mut f = self.fails.lock().unwrap();
        let e = f.entry(rhost.to_string()).or_insert((0, t));
        if t.saturating_sub(e.1) >= FAIL_WINDOW {
            *e = (0, t);
        }
        e.0 += 1;
    }

    /// Check the shared password; on success create/refresh the workspace.
    pub fn auth(&self, name: &str, password: &str, rhost: &str) -> Result<(), &'static str> {
        let rhost = if rhost.is_empty() { "-" } else { rhost };
        if self.throttled(rhost) {
            eprintln!("club: throttled {rhost} (login as '{name}')");
            return Err("throttled");
        }
        let expected = std::fs::read_to_string(&self.cfg.password_file).map_err(|_| "no-password-file")?;
        let expected = expected.trim();
        if expected.is_empty() || !ct_eq(password.as_bytes(), expected.as_bytes()) {
            self.note_failure(rhost);
            eprintln!("club: wrong password for '{name}' from {rhost}");
            return Err("denied");
        }

        let (uid, newly) = {
            let mut reg = self.reg.lock().unwrap();
            let authed = reg.authed_count();
            let Some(e) = reg.users.get_mut(name) else { return Err("unknown-user") };
            let mut newly = false;
            if !e.authed {
                if authed >= self.cfg.max_users {
                    return Err("full");
                }
                e.authed = true;
                e.created = now();
                newly = true;
            }
            e.last_login = now();
            let uid = e.uid;
            reg.save();
            (uid, newly)
        };

        if let Err(e) = provision::provision_user(&self.cfg, name, uid) {
            eprintln!("club: provisioning '{name}' failed: {e}");
            return Err("provision-failed");
        }
        if newly {
            eprintln!("club: created workspace '{name}' (uid {uid}) for {rhost}");
        }
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<(), &'static str> {
        let uid = {
            let mut reg = self.reg.lock().unwrap();
            let Some(e) = reg.users.remove(name) else { return Err("no-such-workspace") };
            reg.save();
            e.uid
        };
        provision::remove_user(&self.cfg, name, uid);
        eprintln!("club: deleted workspace '{name}'");
        Ok(())
    }

    /// Delete workspaces idle for longer than `idle_delete_days`.
    pub fn reap(&self) -> usize {
        if self.cfg.idle_delete_days == 0 {
            return 0;
        }
        let cutoff = now().saturating_sub(self.cfg.idle_delete_days * 86_400);
        let stale: Vec<UserInfo> = self
            .authed_users()
            .into_iter()
            .filter(|u| u.last_login < cutoff && !provision::session_active(u.uid))
            .collect();
        let mut n = 0;
        for u in stale {
            if self.delete(&u.name).is_ok() {
                n += 1;
            }
        }
        n
    }

    pub fn sync_limits(&self) {
        let uids: Vec<u32> = self.authed_users().iter().map(|u| u.uid).collect();
        provision::sync_limits(&self.cfg, &uids);
    }
}

#[cfg(test)]
pub fn test_state(dir: &std::path::Path, password: &str) -> State {
    let mut cfg = Config::default();
    cfg.dry_run = true;
    cfg.uid_min = 40_000;
    cfg.state_dir = dir.to_path_buf();
    cfg.password_file = dir.join("password");
    std::fs::write(&cfg.password_file, format!("{password}\n")).unwrap();
    State::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("club-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lookup_is_stable_and_sequential() {
        let s = test_state(&tmp("lookup"), "pw");
        let a = s.lookup_name("alice").unwrap();
        let b = s.lookup_name("bob").unwrap();
        assert_ne!(a, b);
        assert_eq!(s.lookup_name("alice"), Some(a));
        assert_eq!(s.lookup_name("Bad Name"), None);
        assert_eq!(s.lookup_name("root"), None, "local names are reserved");
    }

    #[test]
    fn auth_flow() {
        let s = test_state(&tmp("auth"), "s3cret");
        assert_eq!(s.auth("alice", "s3cret", "1.1.1.1"), Err("unknown-user"));
        s.lookup_name("alice").unwrap();
        assert_eq!(s.auth("alice", "wrong", "1.1.1.1"), Err("denied"));
        assert!(!s.is_known("alice"));
        assert_eq!(s.auth("alice", "s3cret", "1.1.1.1"), Ok(()));
        assert!(s.is_known("alice"));
        assert_eq!(s.authed_users().len(), 1);
    }

    #[test]
    fn authed_users_persist() {
        let d = tmp("persist");
        let s = test_state(&d, "pw");
        let uid = s.lookup_name("carol").unwrap();
        s.auth("carol", "pw", "x").unwrap();
        s.lookup_name("pending-only").unwrap();
        let s2 = State::new(s.cfg.clone());
        assert_eq!(s2.find_name("carol"), Some(uid));
        assert_eq!(s2.find_name("pending-only"), None, "pending entries are not persisted");
    }

    #[test]
    fn brute_force_is_throttled() {
        let s = test_state(&tmp("throttle"), "pw");
        s.lookup_name("dave").unwrap();
        for _ in 0..FAIL_LIMIT {
            assert_eq!(s.auth("dave", "nope", "9.9.9.9"), Err("denied"));
        }
        // even the right password is refused from that host now
        assert_eq!(s.auth("dave", "pw", "9.9.9.9"), Err("throttled"));
        // other hosts are unaffected
        assert_eq!(s.auth("dave", "pw", "8.8.8.8"), Ok(()));
    }

    #[test]
    fn capacity_limits() {
        let d = tmp("cap");
        let mut s = test_state(&d, "pw");
        s.cfg.max_users = 2;
        for n in ["u1", "u2", "u3"] {
            let _ = s.lookup_name(n);
        }
        s.auth("u1", "pw", "x").unwrap();
        s.auth("u2", "pw", "x").unwrap();
        assert_eq!(s.auth("u3", "pw", "x"), Err("full"));
        assert_eq!(s.lookup_name("u4"), None, "no new names once full");
        assert!(s.lookup_name("u1").is_some(), "existing users still resolve");
    }

    #[test]
    fn delete_and_reap() {
        let d = tmp("reap");
        let mut s = test_state(&d, "pw");
        s.lookup_name("old").unwrap();
        s.auth("old", "pw", "x").unwrap();
        s.reg.lock().unwrap().users.get_mut("old").unwrap().last_login = 1;
        assert_eq!(s.reap(), 0, "reaping is off by default");
        s.cfg.idle_delete_days = 30;
        assert_eq!(s.reap(), 1);
        assert!(!s.is_known("old"));
        assert_eq!(s.delete("old"), Err("no-such-workspace"));
    }
}
