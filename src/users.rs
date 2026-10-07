//! Who exists and who may log in. Only names that authenticated are saved;
//! a name that is merely looked up (a scanner guessing usernames) gets a
//! short-lived in-memory placeholder so sshd proceeds to the password check.

use crate::config::*;
use crate::host;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::{fs, time::SystemTime};

const PENDING_TTL: u64 = 180; // longer than sshd's 120 s login grace time
const PENDING_MAX: usize = 2000; // scanners guess many usernames; this must not fill up
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
    /// A missing file means a fresh install; an unreadable one must stop us,
    /// or forgotten members would be given each other's uids (and files).
    pub fn new(cfg: Config) -> Result<Users, String> {
        let path = cfg.state_dir.join("users");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let mut db = Db::default();
        let mut uids = HashSet::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let mut f = line.split(' ');
            let parsed = (f.next(), f.next().map(str::parse), f.next().map(str::parse));
            let (Some(n), Some(Ok(uid)), Some(Ok(ts))) = parsed else {
                return Err(format!("{}: cannot parse line '{line}'", path.display()));
            };
            let ok = valid_name(n)
                && (UID_RANGE.0..=UID_RANGE.1).contains(&uid)
                && uids.insert(uid)
                && db.users.insert(n.into(), Entry { uid, authed: true, ts }).is_none();
            if !ok {
                return Err(format!("{}: invalid or duplicate entry '{line}'", path.display()));
            }
        }
        Ok(Users { cfg, db: Mutex::new(db) })
    }

    fn save(&self, db: &Db) -> std::io::Result<()> {
        let text: String = db
            .users
            .iter()
            .filter(|(_, e)| e.authed)
            .map(|(n, e)| format!("{n} {} {}\n", e.uid, e.ts))
            .collect();
        let path = self.cfg.state_dir.join("users");
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text).and_then(|_| fs::rename(&tmp, &path))
    }

    /// The uid for `name`, handing out a placeholder to a new valid name.
    pub fn lookup(&self, name: &str) -> Option<u32> {
        if !valid_name(name) {
            return None;
        }
        let mut db = self.db.lock().unwrap();
        let t = now();
        if let Some(e) = db.users.get_mut(name) {
            if !e.authed {
                e.ts = t; // still being used to log in: keep the placeholder alive
            }
            return Some(e.uid);
        }
        db.users.retain(|_, e| e.authed || t.saturating_sub(e.ts) < PENDING_TTL);
        let authed = db.users.values().filter(|e| e.authed).count();
        if authed >= self.cfg.max_users || taken_locally(name) {
            return None;
        }
        if db.users.len() - authed >= PENDING_MAX {
            // Never turn a new member away: drop the stalest placeholder instead.
            let stalest = db.users.iter().filter(|(_, e)| !e.authed).min_by_key(|(_, e)| e.ts).map(|(n, _)| n.clone());
            stalest.map(|n| db.users.remove(&n));
        }
        let used: HashSet<u32> = db.users.values().map(|e| e.uid).collect();
        let uid = (UID_RANGE.0..=UID_RANGE.1).find(|u| !used.contains(u))?;
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
        let (was_authed, was_ts, uid) = (e.authed, e.ts, e.uid);
        if !was_authed && authed >= self.cfg.max_users {
            return Err("full");
        }
        (e.authed, e.ts) = (true, t);
        // Refuse the login if we cannot remember the member (they would lose their uid),
        // and leave no trace of the attempt.
        if let Err(err) = self.save(&db) {
            eprintln!("club: cannot save members: {err}");
            (db.users.get_mut(name).unwrap().authed, db.users.get_mut(name).unwrap().ts) = (was_authed, was_ts);
            return Err("setup failed");
        }
        if !was_authed {
            eprintln!("club: new workspace '{name}' (uid {uid}) from {rhost}");
        }
        drop(db);

        host::provision(name, uid).map_err(|e| {
            eprintln!("club: setting up '{name}' failed: {e}");
            "setup failed"
        })
    }

    pub fn delete(&self, name: &str) -> bool {
        let Some(uid) = self.uid_of(name) else { return false };
        // Files and processes first, so the uid is never reusable while they exist.
        host::remove(name, uid);
        let mut db = self.db.lock().unwrap();
        db.users.remove(name);
        if let Err(e) = self.save(&db) {
            eprintln!("club: cannot save members: {e}");
        }
        eprintln!("club: deleted '{name}'");
        true
    }

    /// Delete members idle past `idle_delete_days` who have no running processes.
    pub fn reap(&self) {
        let days = self.cfg.idle_delete_days;
        for (name, uid, last) in self.members() {
            if days > 0 && last < now().saturating_sub(days * 86_400) && !host::busy(uid) {
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
        password_file: dir.join("password"),
        state_dir: dir,
        ..Config::default()
    })
    .unwrap()
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

        let again = Users::new(u.cfg.clone()).unwrap();
        assert_eq!(again.uid_of("alice"), Some(uid));
        assert_eq!(again.uid_of("ghost"), None, "placeholders are not saved");
    }

    #[test]
    fn unreadable_state_stops_startup() {
        let u = test_users("corrupt");
        fs::write(u.cfg.state_dir.join("users"), "alice not-a-number 5\n").unwrap();
        assert!(Users::new(u.cfg.clone()).is_err());
    }

    #[test]
    fn damaged_state_is_rejected() {
        let u = test_users("damaged");
        for bad in ["alice 0 5", "alice 5 5", "Bad_Name 20001 5", "a 20001 5\nb 20001 5", "a 20001 5\na 20002 5"] {
            fs::write(u.cfg.state_dir.join("users"), format!("{bad}\n")).unwrap();
            assert!(Users::new(u.cfg.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn failed_registration_leaves_no_trace() {
        let mut u = test_users("savefail");
        u.cfg.max_users = 1;
        u.lookup("first").unwrap();
        u.lookup("second").unwrap();
        let good = u.cfg.state_dir.clone();
        u.cfg.state_dir = "/nonexistent".into();
        assert_eq!(u.auth("first", "pw", "h"), Err("setup failed"));
        u.cfg.state_dir = good;
        assert_eq!(u.auth("second", "pw", "h"), Ok(()), "the failed attempt must not use up the slot");
    }

    #[test]
    fn full_placeholder_table_evicts_instead_of_refusing() {
        let u = test_users("evict");
        for i in 0..=PENDING_MAX {
            assert!(u.lookup(&format!("scan{i}")).is_some());
        }
        assert!(u.lookup("realmember").is_some());
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
