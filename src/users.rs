//! Who exists and who may log in. Only names that authenticated are saved;
//! a name that is merely looked up (a scanner guessing usernames) gets a
//! short-lived in-memory placeholder so sshd proceeds to the password check.

use crate::config::*;
use crate::host;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::{fs, time::SystemTime};

const PENDING_TTL: u64 = 600;
const PENDING_MAX: usize = 200;
const FAIL_LIMIT: u32 = 10; // wrong passwords allowed per client address...
const FAIL_WINDOW: u64 = 60; // ...per this many seconds

struct Entry {
    uid: u32,
    authed: bool,
    /// Last login (authed) or when the placeholder was handed out (pending).
    ts: u64,
}

#[derive(Default)]
struct Db {
    users: BTreeMap<String, Entry>,
    fails: HashMap<String, (u32, u64)>,
}

pub struct Users {
    pub cfg: Config,
    db: Mutex<Db>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 1-20 chars of a-z 0-9 -, starting with a letter, not ending in a hyphen.
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=20).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[b.len() - 1] != b'-'
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Parsed by hand: getpwnam() here would ask this very daemon and deadlock.
fn taken_locally(name: &str) -> bool {
    ["/etc/passwd", "/etc/group"].iter().any(|f| {
        fs::read_to_string(f).is_ok_and(|t| t.lines().any(|l| l.split(':').next() == Some(name)))
    })
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).unwrap_or(&0) ^ b.get(i).unwrap_or(&0);
    }
    diff == 0
}

impl Users {
    /// The saved file has one line per member: `name uid last_login`.
    pub fn new(cfg: Config) -> Users {
        let mut db = Db::default();
        for line in fs::read_to_string(cfg.state_dir.join("users")).unwrap_or_default().lines() {
            let mut f = line.split(' ');
            if let (Some(n), Some(Ok(uid)), Some(Ok(ts))) =
                (f.next(), f.next().map(str::parse), f.next().map(str::parse))
            {
                db.users.insert(n.into(), Entry { uid, authed: true, ts });
            }
        }
        Users { cfg, db: Mutex::new(db) }
    }

    fn save(&self, db: &Db) {
        let text: String = db
            .users
            .iter()
            .filter(|(_, e)| e.authed)
            .map(|(n, e)| format!("{n} {} {}\n", e.uid, e.ts))
            .collect();
        let path = self.cfg.state_dir.join("users");
        let tmp = path.with_extension("tmp");
        if let Err(e) = fs::write(&tmp, text).and_then(|_| fs::rename(&tmp, &path)) {
            eprintln!("club: cannot save {}: {e}", path.display());
        }
    }

    /// The uid for `name`, handing out a placeholder to a new valid name.
    pub fn lookup(&self, name: &str) -> Option<u32> {
        if !valid_name(name) {
            return None;
        }
        let mut db = self.db.lock().unwrap();
        if let Some(e) = db.users.get(name) {
            return Some(e.uid);
        }
        let t = now();
        db.users.retain(|_, e| e.authed || t.saturating_sub(e.ts) < PENDING_TTL);
        let authed = db.users.values().filter(|e| e.authed).count();
        if db.users.len() - authed >= PENDING_MAX || authed >= self.cfg.max_users || taken_locally(name) {
            return None;
        }
        let uid = (UID_RANGE.0..=UID_RANGE.1).find(|u| db.users.values().all(|e| e.uid != *u))?;
        db.users.insert(name.into(), Entry { uid, authed: false, ts: t });
        Some(uid)
    }

    /// Existing names only; never allocates.
    pub fn uid_of(&self, name: &str) -> Option<u32> {
        self.db.lock().unwrap().users.get(name).map(|e| e.uid)
    }

    pub fn name_of(&self, uid: u32) -> Option<String> {
        self.db.lock().unwrap().users.iter().find(|(_, e)| e.uid == uid).map(|(n, _)| n.clone())
    }

    /// (name, uid, last login) of every member.
    pub fn members(&self) -> Vec<(String, u32, u64)> {
        let db = self.db.lock().unwrap();
        db.users.iter().filter(|(_, e)| e.authed).map(|(n, e)| (n.clone(), e.uid, e.ts)).collect()
    }

    /// Check the shared password; on success make sure the workspace exists.
    pub fn auth(&self, name: &str, password: &str, rhost: &str) -> Result<(), &'static str> {
        let expected = fs::read_to_string(&self.cfg.password_file).unwrap_or_default();
        let right = !expected.trim().is_empty() && ct_eq(password.as_bytes(), expected.trim().as_bytes());
        let t = now();

        let mut db = self.db.lock().unwrap();
        if db.fails.len() > 10_000 {
            db.fails.clear();
        }
        let f = db.fails.entry(rhost.into()).or_insert((0, t));
        if t.saturating_sub(f.1) >= FAIL_WINDOW {
            *f = (0, t);
        }
        if f.0 >= FAIL_LIMIT {
            eprintln!("club: throttled {rhost}");
            return Err("throttled");
        }
        if !right {
            f.0 += 1;
            eprintln!("club: wrong password for '{name}' from {rhost}");
            return Err("wrong password");
        }

        let authed = db.users.values().filter(|e| e.authed).count();
        let e = db.users.get_mut(name).ok_or("unknown user")?;
        if !e.authed {
            if authed >= self.cfg.max_users {
                return Err("full");
            }
            e.authed = true;
            eprintln!("club: new workspace '{name}' (uid {}) from {rhost}", e.uid);
        }
        e.ts = t;
        let uid = e.uid;
        self.save(&db);
        drop(db);

        host::provision(&self.cfg, name, uid).map_err(|e| {
            eprintln!("club: setting up '{name}' failed: {e}");
            "setup failed"
        })
    }

    pub fn delete(&self, name: &str) -> bool {
        let mut db = self.db.lock().unwrap();
        let Some(e) = db.users.remove(name) else { return false };
        self.save(&db);
        drop(db);
        host::remove(&self.cfg, name, e.uid);
        eprintln!("club: deleted '{name}'");
        true
    }

    /// Delete workspaces idle past `idle_delete_days`, unless logged in.
    pub fn reap(&self) {
        let days = self.cfg.idle_delete_days;
        for (name, uid, last) in self.members() {
            if days > 0 && last < now().saturating_sub(days * 86_400) && !host::online(uid) {
                self.delete(&name);
            }
        }
    }
}

#[cfg(test)]
pub fn test_users(tag: &str) -> Users {
    let dir = std::env::temp_dir().join(format!("club-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("password"), "pw\n").unwrap();
    Users::new(Config {
        dry_run: true,
        password_file: dir.join("password"),
        state_dir: dir,
        ..Config::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["alice", "a", "bob-2", &"a".repeat(20)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "Alice", "2bob", "bob-", "a b", "../x", &"a".repeat(21)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn lookup_is_stable_and_skips_local_names() {
        let u = test_users("lookup");
        let a = u.lookup("alice").unwrap();
        assert_ne!(a, u.lookup("bob").unwrap());
        assert_eq!(u.lookup("alice"), Some(a));
        assert_eq!(u.lookup("root"), None);
        assert_eq!(u.uid_of("nobody-yet"), None, "uid_of never allocates");
    }

    #[test]
    fn login_flow_and_persistence() {
        let u = test_users("auth");
        assert_eq!(u.auth("alice", "pw", "h"), Err("unknown user"));
        let uid = u.lookup("alice").unwrap();
        u.lookup("ghost").unwrap();
        assert_eq!(u.auth("alice", "bad", "h"), Err("wrong password"));
        assert_eq!(u.auth("alice", "pw", "h"), Ok(()));

        let again = Users::new(u.cfg.clone());
        assert_eq!(again.uid_of("alice"), Some(uid));
        assert_eq!(again.uid_of("ghost"), None, "placeholders are not saved");
    }

    #[test]
    fn brute_force_is_throttled_per_host() {
        let u = test_users("throttle");
        u.lookup("dave").unwrap();
        for _ in 0..FAIL_LIMIT {
            assert_eq!(u.auth("dave", "no", "1.1.1.1"), Err("wrong password"));
        }
        assert_eq!(u.auth("dave", "pw", "1.1.1.1"), Err("throttled"));
        assert_eq!(u.auth("dave", "pw", "2.2.2.2"), Ok(()));
    }

    #[test]
    fn capacity_and_cleanup() {
        let mut u = test_users("cap");
        u.cfg.max_users = 1;
        u.lookup("u1").unwrap();
        u.lookup("u2").unwrap();
        u.auth("u1", "pw", "h").unwrap();
        assert_eq!(u.auth("u2", "pw", "h"), Err("full"));
        assert_eq!(u.lookup("u3"), None, "no new names once full");

        u.db.lock().unwrap().users.get_mut("u1").unwrap().ts = 1;
        u.reap();
        assert!(u.uid_of("u1").is_some(), "reaping is off by default");
        u.cfg.idle_delete_days = 30;
        u.reap();
        assert_eq!(u.uid_of("u1"), None);
        assert!(!u.delete("u1"));
    }
}
