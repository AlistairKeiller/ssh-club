//! Who exists. A name becomes a member (and is saved) only after a correct
//! password. A name that is merely looked up gets a placeholder uid that
//! expires: sshd asks about the username before it asks for the password,
//! and scanners guess usernames all day.

use crate::host;
use crate::paths::*;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{fs, io};

/// Longer than sshd's 120 s login grace time, so a placeholder outlives the login it is for.
const PLACEHOLDER_TTL: Duration = Duration::from_secs(180);

struct Entry {
    uid: u32,
    /// When this placeholder was last asked about; None for a saved member.
    placeholder: Option<Instant>,
}

type Db = BTreeMap<String, Entry>;

pub struct Users {
    users_file: PathBuf,
    password_file: PathBuf,
    db: Mutex<Db>,
}

/// 1-31 letters, digits, `_` or `-`, starting with a letter or `_`.
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=31).contains(&b.len())
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

/// Parsed by hand: calling getpwnam() here would ask this very daemon and deadlock.
fn taken_locally(name: &str) -> bool {
    ["/etc/passwd", "/etc/group"].iter().any(|f| {
        fs::read_to_string(f).map_or(true, |t| t.lines().any(|l| l.split(':').next() == Some(name)))
    })
}

/// Compare without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).unwrap_or(&0) ^ b.get(i).unwrap_or(&0);
    }
    diff == 0
}

impl Users {
    /// The saved file has one `name uid` line per member. Missing means a fresh
    /// install. Anything unreadable or invalid must stop us: forgetting members
    /// would hand their uids, and so their files, to someone else.
    pub fn new(users_file: PathBuf, password_file: PathBuf) -> Result<Users, String> {
        let text = match fs::read_to_string(&users_file) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", users_file.display())),
        };
        let (mut db, mut uids) = (Db::new(), HashSet::new());
        for line in text.lines().filter(|l| !l.is_empty()) {
            let parsed = line.split_once(' ').and_then(|(n, u)| Some((n, u.parse::<u32>().ok()?)));
            let valid = parsed.is_some_and(|(n, uid)| {
                valid_name(n) && (UID_RANGE.0..=UID_RANGE.1).contains(&uid) && uids.insert(uid)
            });
            let (name, uid) = parsed.filter(|_| valid).ok_or(format!("{}: bad line '{line}'", users_file.display()))?;
            if db.insert(name.into(), Entry { uid, placeholder: None }).is_some() {
                return Err(format!("{}: '{name}' is listed twice", users_file.display()));
            }
        }
        Ok(Users { users_file, password_file, db: Mutex::new(db) })
    }

    fn save(&self, db: &Db) -> io::Result<()> {
        let text: String = db.iter().filter(|(_, e)| e.placeholder.is_none()).map(|(n, e)| format!("{n} {}\n", e.uid)).collect();
        host::write_atomic(&self.users_file, &text)
    }

    /// The uid for `name`; a new valid name gets a placeholder.
    pub fn lookup(&self, name: &str) -> Option<u32> {
        if !valid_name(name) {
            return None;
        }
        let (mut db, now) = (self.db.lock().unwrap(), Instant::now());
        if let Some(e) = db.get_mut(name) {
            if e.placeholder.is_some() {
                e.placeholder = Some(now); // still being used to log in: keep it alive
            }
            return Some(e.uid);
        }
        db.retain(|_, e| e.placeholder.map_or(true, |t| now.duration_since(t) < PLACEHOLDER_TTL));
        if taken_locally(name) {
            return None;
        }
        let used: HashSet<u32> = db.values().map(|e| e.uid).collect();
        let uid = (UID_RANGE.0..=UID_RANGE.1).find(|u| !used.contains(u))?;
        db.insert(name.into(), Entry { uid, placeholder: Some(now) });
        Some(uid)
    }

    /// Existing names only; never creates a placeholder.
    pub fn uid_of(&self, name: &str) -> Option<u32> {
        self.db.lock().unwrap().get(name).map(|e| e.uid)
    }

    pub fn name_of(&self, uid: u32) -> Option<String> {
        self.db.lock().unwrap().iter().find(|(_, e)| e.uid == uid).map(|(n, _)| n.clone())
    }

    /// Check the shared password; on success the member exists and has a home.
    pub fn auth(&self, name: &str, password: &str) -> bool {
        let expected = fs::read_to_string(&self.password_file).unwrap_or_default();
        if expected.trim().is_empty() || !same(password.as_bytes(), expected.trim().as_bytes()) {
            eprintln!("club: wrong password for '{name}'");
            return false;
        }
        let mut db = self.db.lock().unwrap();
        let Some(e) = db.get_mut(name) else { return false };
        let (uid, was_placeholder) = (e.uid, e.placeholder);
        if was_placeholder.is_some() {
            e.placeholder = None;
            // Not remembering a member would lose their uid, so refuse the login.
            if let Err(err) = self.save(&db) {
                eprintln!("club: cannot save members: {err}");
                db.get_mut(name).unwrap().placeholder = was_placeholder;
                return false;
            }
            eprintln!("club: new member '{name}' (uid {uid})");
        }
        drop(db);
        host::provision(name, uid).map_err(|e| eprintln!("club: setting up '{name}': {e}")).is_ok()
    }
}

#[cfg(test)]
pub fn test_users(tag: &str) -> Users {
    let dir = std::env::temp_dir().join(format!("club-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("password"), "pw\n").unwrap();
    Users::new(dir.join("users"), dir.join("password")).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reload(u: &Users) -> Result<Users, String> {
        Users::new(u.users_file.clone(), u.password_file.clone())
    }

    #[test]
    fn names() {
        for ok in ["alice", "a", "bob-2", "Alice_Smith", "_dev", &"a".repeat(31)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "2bob", "-bob", "a b", "../x", "a:b", "a.b", "é", &"a".repeat(32)] {
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
        assert_eq!(u.uid_of("never-asked"), None);
    }

    #[test]
    fn login_creates_a_saved_member() {
        let u = test_users("login");
        assert!(!u.auth("alice", "pw"), "unknown names cannot log in");
        let uid = u.lookup("alice").unwrap();
        u.lookup("ghost").unwrap();
        assert!(!u.auth("alice", "bad"));
        assert!(u.auth("alice", "pw"));

        let after_restart = reload(&u).unwrap();
        assert_eq!(after_restart.uid_of("alice"), Some(uid));
        assert_eq!(after_restart.uid_of("ghost"), None, "placeholders are not saved");
    }

    #[test]
    fn damaged_state_stops_startup() {
        let u = test_users("damaged");
        for bad in ["alice not-a-number", "alice 0", "alice 5", "../bad 20001", "a 20001\nb 20001", "a 20001\na 20002", "a 20001 extra", "garbage"] {
            fs::write(&u.users_file, format!("{bad}\n")).unwrap();
            assert!(reload(&u).is_err(), "{bad}");
        }
    }

    #[test]
    fn failed_save_leaves_no_trace() {
        let mut u = test_users("savefail");
        u.lookup("first").unwrap();
        let good = u.users_file.clone();
        u.users_file = "/nonexistent/users".into();
        assert!(!u.auth("first", "pw"));
        u.users_file = good;
        assert!(u.auth("first", "pw"), "and the login works once saving does");
    }

    #[test]
    fn only_expired_placeholders_are_recycled() {
        let u = test_users("expiry");
        let old = u.lookup("old").unwrap();
        let live = u.lookup("live").unwrap();
        u.db.lock().unwrap().get_mut("old").unwrap().placeholder = Some(Instant::now() - PLACEHOLDER_TTL);
        assert_eq!(u.lookup("new"), Some(old));
        assert_eq!(u.lookup("live"), Some(live));
        let alice = u.lookup("alice").unwrap();
        assert!(u.auth("alice", "pw"));
        assert!((0..50).all(|i| u.lookup(&format!("scan{i}")) != Some(alice)), "members keep their uid");
    }

    #[test]
    fn simultaneous_first_logins_share_one_identity() {
        let u = std::sync::Arc::new(test_users("concurrent"));
        let workers: Vec<_> = (0..6)
            .map(|_| {
                let u = u.clone();
                std::thread::spawn(move || {
                    let uid = u.lookup("alice").unwrap();
                    assert!(u.auth("alice", "pw"));
                    uid
                })
            })
            .collect();
        for w in workers {
            assert_eq!(w.join().unwrap(), UID_RANGE.0);
        }
        assert_eq!(reload(&u).unwrap().uid_of("alice"), Some(UID_RANGE.0));
    }
}
