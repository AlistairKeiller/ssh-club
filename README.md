# club

**Any username + one shared password = your own Linux account.** For a club dev
server: members `ssh alice@server` (or use VS Code Remote-SSH), type the club
password, and get a private home directory. Same username next time, same files.
One static Rust binary does everything, including installing itself.

```
$ ssh alice@server        # first time: account created in about a second
$ ssh alice@server        # later: same account, same files
```

## Install

On a Debian or Ubuntu server with systemd (arm64 or x86_64):

```sh
cargo build --release && sudo target/release/club install     # needs cargo >= 1.75
```

or, once this repo is on GitHub and a release is tagged (the included workflow
builds static binaries), on any fresh machine:

```sh
curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-club/main/install.sh | sudo sh
```

The same line works as a cloud-init script (`#cloud-config` / `runcmd:`), so a
new VM can set itself up on first boot. Afterwards `sudo club password` shows the
shared password.

From your laptop to a server called `oracle`:

```sh
rsync -a --exclude target ~/git/ssh-club/ oracle:ssh-club/
ssh oracle 'cd ssh-club && sudo apt-get install -y cargo && cargo build --release && sudo target/release/club install'
```

Members use the normal SSH port, so there is nothing new to open in a cloud
firewall. The installer edits `/etc/pam.d/sshd`: **test a login from a second
terminal before you close your own session.**

## Members

In VS Code: Remote-SSH, "Connect to Host", `alice@your-server`, enter the club
password (VS Code does not remember SSH passwords, so it asks each time). Pick one
username and keep it; the name is the workspace. Names are 1-20 characters of
`a-z`, `0-9` and `-`, starting with a letter.

## Running it

```sh
sudo club list                  # members, whether they have processes running, last login
sudo club delete alice          # remove a member and their files
sudo club password --rotate     # new shared password; existing members unaffected
sudo club uninstall             # remove the hooks (files stay)
```

Settings are in `/etc/club/club.conf`; restart with `sudo systemctl restart club`:

| key | default | meaning |
|---|---|---|
| `max_users` | 500 | most members that can exist |
| `memory_gb` | 3 | hard memory limit per member (they are slowed down at 3/4 of it) |
| `idle_delete_days` | 0 | delete members unused this long (0 = never); anyone with running processes is kept |

Limits are enforced by systemd-logind from each member's user record, so a changed setting applies at their next login.

## How it works

No custom SSH server and no containers. OpenSSH does the SSH; `club` only makes
the system believe in users that do not exist yet.

1. **`club serve`** listens on `/run/systemd/userdb/io.systemd.Club`, a plugin
   socket that systemd's `nss-systemd` asks about users. It answers "that user
   exists" for any valid name, handing out uids from 20000. So sshd sees every
   valid name as a real local user.
2. **One PAM line** in `/etc/pam.d/sshd` runs `club pam-auth`, which asks the
   daemon to check the shared password (constant-time compare; after 10 wrong
   guesses a client address is refused for a minute).
3. **First good login** creates `/home/club/<name>` (mode 0700, copied from
   `/etc/skel`; built under a temporary name and renamed into place, so it is
   never half-made). The member's record also carries memory and process limits,
   which systemd-logind applies to their slice. A name that never logs in leaves
   nothing behind.
4. **Plain directories** on the host's disk. There is no per-member disk quota.
5. **One firewall rule** stops members reaching the cloud metadata service
   (`169.254.169.254`), where instance credentials live.

Files: `/etc/club/{club.conf,password}`, `/var/lib/club/users`, `/home/club/`,
`/usr/local/bin/club`, `club.service`, `/etc/ssh/sshd_config.d/10-club.conf`, and
one block in `/etc/pam.d/sshd`. If club ever stops running, that PAM block simply
falls through to normal logins; it cannot lock you out.

## What members get, and what they do not

Members are ordinary unprivileged Linux accounts on one shared host, the classic
shell-server model. It is small, fast, and an idle member costs nothing, but it
is not a container sandbox:

- No root, no `apt install`. Install what the club needs system-wide; per-user
  tools (`uv`, `nvm`, `rustup`) work in a home directory.
- Homes are private (0700) and `/home/club` is not listable, but members can see
  each other's processes (`ps`) and share `/tmp`, `localhost` and the network.
- **Disk is shared.** Nothing stops a member filling the host disk (their home,
  or `/tmp`). If that matters, mount a separate volume at `/home/club` before
  installing and give `/tmp` its own size-limited tmpfs.
- A kernel bug affects everyone. Keep the host patched.
- Anyone with the club password can log in as any username. Rotate it when a
  member leaves.
- Password login is enabled server-wide. Keep your own accounts key-only (cloud
  images ship with locked passwords). Other users' home directories under `/home`
  that are world-readable are readable by members; tighten them with `chmod o-rwx`.

Capacity: an idle member costs no RAM; active members cost whatever they run (a
VS Code server alone is several hundred MB, and compilers can use much more).
There is no measured user count; watch real use and adjust `memory_gb`.
`systemd-zram-generator` helps absorb bursts.

## Troubleshooting

| symptom | check |
|---|---|
| install says the self-test failed | `getent passwd club-selftest` must print a line; `passwd:` in `/etc/nsswitch.conf` needs `systemd`; see `journalctl -u club` |
| the daemon will not start | `journalctl -u club`. If it reports an unreadable `/var/lib/club/users`, restore that file: starting without it would reissue members' uids |
| every login is "Permission denied" | `journalctl -u club -f` shows each attempt and why (`wrong password`, `throttled`, `full`); `sudo sshd -T \| grep passwordauth` must say yes |
| one person is locked out | 10 wrong passwords block that client address for a minute; members behind one NAT share it |

**Erase everything:** `sudo club uninstall; sudo rm -rf /etc/club /var/lib/club /home/club /usr/local/bin/club`

## Development

`cargo test` covers the user database, the protocol and the PAM edit (no root
needed). The real chain (sshd, PAM, nss-systemd) needs a systemd Linux machine;
an OrbStack VM (`orb create ubuntu:24.04 t`) works well.

Code map: `users.rs` who exists and who may log in, `varlink.rs` the protocol,
`host.rs` homes, cleanup, firewall, `install.rs` the installer (all config
embedded), `main.rs` the commands.
