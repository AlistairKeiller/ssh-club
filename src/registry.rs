//! Who exists. Only workspaces that have logged in successfully ("authed")
//! are written to disk; unauthenticated lookups (port scanners guessing
//! usernames) get a short-lived in-memory entry that expires.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const PENDING_TTL: u64 = 600;
pub const PENDING_MAX: usize = 200;

#[derive(Clone, Debug)]
pub struct Entry {
    pub uid: u32,
    pub authed: bool,
    pub created: u64,
    pub last_login: u64,
    /// When a pending entry was handed out.
    pub seen: u64,
}

pub struct Registry {
    pub users: BTreeMap<String, Entry>,
    path: PathBuf,
}

/// 1-20 chars, lowercase letters/digits/hyphen, starts with a letter,
/// does not end with a hyphen.
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    if b.is_empty() || b.len() > 20 || !b[0].is_ascii_lowercase() || b[b.len() - 1] == b'-' {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Names already taken by local users or groups. Parsed by hand: calling
/// getpwnam() from inside the provider would query ourselves and deadlock.
pub fn local_names() -> HashSet<String> {
    let mut set = HashSet::new();
    for f in ["/etc/passwd", "/etc/group"] {
        if let Ok(text) = fs::read_to_string(f) {
            for line in text.lines() {
                if let Some(name) = line.split(':').next() {
                    set.insert(name.to_string());
                }
            }
        }
    }
    set
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Registry {
    pub fn load(state_dir: &Path) -> Registry {
        let path = state_dir.join("users.json");
        let mut users = BTreeMap::new();
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(obj) = v.get("users").and_then(|u| u.as_object()) {
                    for (name, e) in obj {
                        let uid = e.get("uid").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                        if uid == 0 || !valid_name(name) {
                            continue;
                        }
                        users.insert(
                            name.clone(),
                            Entry {
                                uid,
                                authed: true,
                                created: e.get("created").and_then(|x| x.as_u64()).unwrap_or(0),
                                last_login: e.get("last_login").and_then(|x| x.as_u64()).unwrap_or(0),
                                seen: 0,
                            },
                        );
                    }
                }
            }
        }
        Registry { users, path }
    }

    pub fn save(&self) {
        let users: serde_json::Map<String, Value> = self
            .users
            .iter()
            .filter(|(_, e)| e.authed)
            .map(|(n, e)| {
                (
                    n.clone(),
                    json!({"uid": e.uid, "created": e.created, "last_login": e.last_login}),
                )
            })
            .collect();
        let text = serde_json::to_string_pretty(&json!({ "users": users })).unwrap_or_default();
        let tmp = self.path.with_extension("json.tmp");
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let ok = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .and_then(|_| fs::rename(&tmp, &self.path));
        if let Err(e) = ok {
            eprintln!("club: cannot save {}: {e}", self.path.display());
        }
    }

    pub fn authed_count(&self) -> usize {
        self.users.values().filter(|e| e.authed).count()
    }

    pub fn pending_count(&self) -> usize {
        self.users.values().filter(|e| !e.authed).count()
    }

    pub fn name_of(&self, uid: u32) -> Option<&String> {
        self.users.iter().find(|(_, e)| e.uid == uid).map(|(n, _)| n)
    }

    pub fn prune_pending(&mut self, now: u64) {
        self.users
            .retain(|_, e| e.authed || now.saturating_sub(e.seen) < PENDING_TTL);
    }

    /// Lowest unused uid at or above `min`.
    pub fn alloc_uid(&self, min: u32, max: u32) -> Option<u32> {
        let used: HashSet<u32> = self.users.values().map(|e| e.uid).collect();
        (min..=max).find(|u| !used.contains(u))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("alice"));
        assert!(valid_name("a"));
        assert!(valid_name("bob-2"));
        assert!(!valid_name(""));
        assert!(!valid_name("Alice"));
        assert!(!valid_name("2bob"));
        assert!(!valid_name("bob-"));
        assert!(!valid_name("a b"));
        assert!(!valid_name("../x"));
        assert!(!valid_name(&"a".repeat(21)));
        assert!(valid_name(&"a".repeat(20)));
    }

    #[test]
    fn uid_alloc_fills_gaps() {
        let mut r = Registry { users: BTreeMap::new(), path: "/nonexistent/users.json".into() };
        let e = |uid| Entry { uid, authed: true, created: 0, last_login: 0, seen: 0 };
        r.users.insert("a".into(), e(100));
        r.users.insert("b".into(), e(102));
        assert_eq!(r.alloc_uid(100, 200), Some(101));
        r.users.insert("c".into(), e(101));
        assert_eq!(r.alloc_uid(100, 200), Some(103));
        assert_eq!(r.alloc_uid(100, 102), None);
    }
}
