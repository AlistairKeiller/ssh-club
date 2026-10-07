# club

**Any username + one shared password = your own Linux account.** Built for a club
dev server: members `ssh alice@server` (or use VS Code Remote-SSH), type the
club password, and get a private home directory. Same username next time, same
files. One static Rust binary does the whole job, including setting itself up.

```
$ ssh alice@server          # first time: account created in ~1 second
$ ssh alice@server          # later: same account, same files
```

## Quick start

On the server (Ubuntu/Debian, systemd, arm64 or x86_64):

```sh
# build from a checkout (needs cargo >= 1.75; `apt install cargo` on Ubuntu 24.04, else rustup)
cargo build --release && sudo target/release/club install
```

or, once you have pushed this repo and tagged a release (the included GitHub
Action builds static binaries):

```sh
curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-club/main/install.sh | sudo sh
```

or hand `cloud-init.yaml` to a new VM and it sets itself up on first boot.

`club install` prints the shared password. It is safe to run again at any time.
SSH already listens on port 22 and members use that same port, so there is
nothing to open in a cloud firewall if you can already SSH in.

**Keep your own SSH session open and test a login from a second terminal before
you disconnect.** The installer edits `/etc/pam.d/sshd`; `club uninstall` puts
it back exactly.

### From your laptop to the server in two commands

```sh
rsync -a --exclude target ~/git/ssh-club/ oracle:ssh-club/
ssh oracle 'cd ssh-club && sudo apt-get install -y cargo && cargo build --release && sudo target/release/club install'
```

## What members do

1. Install the **Remote - SSH** extension in VS Code.
2. **Remote-SSH: Connect to Host…** and enter `alice@your-server`.
3. Enter the club password. VS Code does not remember SSH passwords, so expect
   the prompt on each connect.

Pick one username and keep using it; the name *is* the workspace. Usernames are
1-20 characters: lowercase letters, digits and hyphens, starting with a letter.

## Running it

```sh
sudo club list                 # workspaces, who is online, last login
sudo club delete alice         # remove a workspace and its files
sudo club password --rotate    # new shared password; existing workspaces untouched
sudo club status               # daemon, counts, disk
sudo club reap                 # delete workspaces idle past idle_delete_days
sudo club uninstall [--purge]  # remove hooks (keeps data unless --purge)
```

Settings live in `/etc/club/club.conf` (restart with `sudo systemctl restart club`;
re-run `sudo club install` if you change `home_base` or `home_pool_gb`):

| key | default | meaning |
|---|---|---|
| `max_users` | 500 | most workspaces that can exist |
| `mem_high` / `mem_max` | 2G / 3G | per-user memory: throttled above the first, killed above the second |
| `tasks_max` | 1500 | per-user process limit |
| `cpu_quota` | (none) | e.g. `200%` caps a user at two cores; empty means fair share |
| `disk_quota_gb` | 5 | per-user disk quota (needs ext4 quota support; see below) |
| `home_pool_gb` | 100 | size of the sparse loopback filesystem holding all homes (0 = plain directory) |
| `idle_delete_days` | 0 | delete workspaces unused this long (0 = never). Users currently logged in are never deleted. |
| `block_cidrs` | (none) | networks workspaces may not reach, e.g. your cloud VCN `10.0.0.0/16` |

## How it works

No custom SSH server and no containers: stock OpenSSH does the SSH. `club` only
teaches the system about users that do not exist yet.

1. **`club serve`** listens on `/run/systemd/userdb/io.systemd.Club`, the plugin
   socket that systemd's `nss-systemd` consults. It answers "yes, that user
   exists" for any valid name, handing out the next free uid (20000 and up).
   sshd therefore treats every valid username as a real local user.
2. **PAM**: two lines in `/etc/pam.d/sshd` run `club pam-auth` / `pam-account`.
   `pam-auth` asks the daemon to check the shared password (constant-time
   compare, 10 failures per minute per client IP, then refused).
3. **First successful login** creates the home directory from `/etc/skel`
   (mode 0700), sets a disk quota, and writes a systemd resource-limit drop-in for
   the user's slice. Names that never authenticate leave nothing on disk;
   their in-memory placeholder expires after ten minutes.
4. **Homes** live on a sparse ext4 image mounted `nosuid,nodev` at `/home/club`, so
   a runaway user can fill the club's pool but never the host's disk.
5. **Firewall**: an `iptables` OUTPUT rule per club uid range blocks the cloud
   metadata service (`169.254.169.254`) and outbound SMTP, plus any `block_cidrs`.

Everything the installer touches: `/etc/club/`, `/var/lib/club/`, the unit
`club.service`, `/etc/ssh/sshd_config.d/10-club.conf`, the club blocks in
`/etc/pam.d/sshd`, `systemd` appended to `passwd:`/`group:` in `nsswitch.conf` if missing,
one `/etc/fstab` line, and `/usr/local/bin/club`.

## Be clear-eyed about isolation

Workspaces are ordinary unprivileged Linux accounts on **one shared host**, the
same model as classic shell servers. That makes it small, fast and cheap (an idle
member costs nothing), but it is not a container sandbox:

- Members have **no root** and cannot `apt install`. Preinstall what the club
  needs (compilers, Python, Node, git) system-wide; per-user tools like `uv`,
  `nvm` and `rustup` work fine in a home directory.
- Members **can see each other's processes** (`ps`) and share `/tmp`, the network
  namespace and `localhost`. Home directories are 0700, so files are private.
  `hidepid=2` on `/proc` hides processes if you want it.
- A **kernel bug** is a bug for everyone. Keep the host patched.
- Anyone with the club password can log in as **any** username, so treat
  workspaces as club-visible. Rotate the password when a member leaves.
- `PasswordAuthentication` is on for the whole server. Your own admin accounts
  should keep key-only access (locked passwords, which is the cloud default).
- Existing home directories under `/home` readable by "others" are readable by
  members; the installer warns about any it finds.

If you need real root and hard isolation per member, use containers (Incus) instead.

## Capacity

An idle account costs no RAM. Active cost is whatever members run: a VS Code
server with extensions is typically 400-600 MB. On 4 cores and 24 GB expect
roughly 30-40 people actively using VS Code at once and far more using plain
SSH. `mem_high`/`mem_max` stop one member from taking the machine; compressed
swap helps absorb bursts (`sudo apt install systemd-zram-generator`).

## Disk quotas

`club install` formats the home image with ext4's built-in user quota. If the
kernel has no quota support the installer says so and falls back to no per-user
quotas (the pool is still isolated from the host). Check with `sudo quota -u alice`.

## Troubleshooting

| symptom | check |
|---|---|
| installer self-test warns | `getent passwd club-selftest` should print a line. Make sure `passwd:` in `/etc/nsswitch.conf` includes `systemd`, and look at `journalctl -u club`. |
| every login says "Permission denied" | `sudo sshd -T \| grep -i passwordauth` must say `yes`; `journalctl -u club -f` shows each attempt and why it was refused (`wrong password`, `throttled`, `full`). |
| one person is locked out | after 10 wrong passwords a client IP is refused for a minute (members behind one NAT share that budget). |
| a name is rejected | 1-20 chars, `a-z 0-9 -`, starts with a letter, must not match an existing local user or group. |
| backing out | `sudo club uninstall` restores PAM and sshd exactly; workspaces stay on disk until `--purge`. |

## Development

```sh
cargo test        # state machine, protocol, PAM patching (no root needed)
```

Real end-to-end testing (sshd + PAM + nss-systemd) needs a Linux machine with
systemd; an OrbStack or multipass Ubuntu VM works well:

```sh
orb create ubuntu:24.04 clubtest
orb -m clubtest bash -c 'sudo apt-get install -y cargo && cd /path/to/ssh-club && cargo build --release && sudo target/release/club install'
```

The code is small: `src/varlink.rs` (the userdb protocol), `src/state.rs`
(who exists and who may log in), `src/provision.rs` (homes, limits, quotas,
firewall), `src/install.rs` (the installer with all config embedded).
