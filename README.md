# club

**`ssh anyname@server` just works.** Anyone who knows the shared password gets their
own Linux account, created on first login, with a private home directory that is
there again next time. One small static binary does all of it, including setting
itself up.

```
$ ssh alice@server        # first time: account and home created automatically
$ ssh alice@server        # later: same account, same files
```

## Install

On a Debian or Ubuntu server with systemd (arm64 or x86_64):

```sh
cargo build --release && sudo target/release/club install     # needs cargo >= 1.75
```

It prints the shared password. Or, once this repo is on GitHub with a tagged release
(the included workflow builds the binaries), on any fresh machine or as a cloud-init
`runcmd`:

```sh
curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-club/main/install.sh | sudo sh
```

Members use the normal SSH port, so there is nothing new to open in a cloud firewall.
The installer edits `/etc/pam.d/sshd`: **test a login from a second terminal before you
close your own session.**

## Members

`ssh yourname@server` and enter the club password. In VS Code: Remote-SSH, "Connect to
Host", `yourname@server` (VS Code asks for the password on each connect). Names are 1-31
letters, digits, `_` or `-`, starting with a letter or `_`. The name *is* the workspace,
and capitals count (`Alice` is not `alice`).

## Running it

```sh
sudo cat /etc/club/password                     # the shared password
echo 'new password' | sudo tee /etc/club/password   # change it (takes effect immediately)
sudo ls /home/club                              # who has an account
sudo club uninstall                             # remove the hooks (files stay)
```

Remove one member: `sudo pkill -u NAME; sudo rm -rf /home/club/NAME`, then delete their
line from `/var/lib/club/users` and `sudo systemctl restart club`. Erase everything:
`sudo club uninstall; sudo rm -rf /etc/club /var/lib/club /home/club /usr/local/bin/club`.

## How it works

No custom SSH server, no containers: OpenSSH does the SSH, and `club` only makes the
system believe in users that do not exist yet.

1. **`club serve`** listens on `/run/systemd/userdb/io.systemd.Club`, a plugin socket
   that systemd's `nss-systemd` asks about users. It answers "that user exists" for any
   valid name, handing out uids from 20000. So sshd treats every valid name as a real
   local user.
2. **One PAM line** in `/etc/pam.d/sshd` runs `club pam-auth`, which asks the daemon
   whether the typed password is the shared one.
3. **First good login** saves the name and uid in `/var/lib/club/users` and creates
   `/home/club/<name>` (mode 0700, from `/etc/skel`). A name that never logs in is
   forgotten after three minutes. An unreadable members file stops the daemon rather than
   risk giving someone else's uid (and so their files) to a new member.

Files: `/etc/club/password`, `/var/lib/club/users`, `/home/club/`, `/usr/local/bin/club`,
`club.service`, `/etc/ssh/sshd_config.d/10-club.conf`, and one block in `/etc/pam.d/sshd`.
If the daemon is ever not running, that block falls through to normal logins; it cannot
lock you out.

## What this does not do

Members are ordinary unprivileged accounts on **one shared host**. Deliberately absent:

- **No resource limits.** A member can use all the CPU, memory and disk, in their home or
  in `/tmp`. (Per-member caps can be added later with `systemctl set-property
  user-<uid>.slice MemoryMax=...`.)
- **No cloud-metadata block.** Members can reach `169.254.169.254`. If your instance has
  credentials attached (e.g. OCI instance principals), block it:
  `sudo iptables -I OUTPUT -m owner --uid-owner 20000-29999 -d 169.254.169.254 -j REJECT`
  (not persistent across reboots).
- **No root, no isolation beyond file permissions.** Members cannot `apt install`; they see
  each other's processes and share `/tmp` and `localhost`. Homes are private, and
  `/home/club` cannot be listed.
- **One shared password:** anyone who knows it can log in under any member's name. Change it
  when someone leaves. Password login is on for the whole server; keep your own accounts
  key-only, and `chmod o-rwx` any home directory under `/home` you want private.

## Troubleshooting

| symptom | check |
|---|---|
| install's self-test fails | `getent passwd club-selftest` must print a line: `passwd:` in `/etc/nsswitch.conf` needs `systemd`; see `journalctl -u club` |
| every login is "Permission denied" | `journalctl -u club -f` shows each attempt; `sudo sshd -T \| grep passwordauth` must say yes |
| `adduser` says the user "already exists" | club answers for every valid name while it runs: `sudo systemctl stop club`, add the user, start it again |
| daemon will not start | `journalctl -u club`; if `/var/lib/club/users` is damaged, repair it and the daemon recovers by itself |

## Development

`cargo test` (no root needed). The real chain (sshd, PAM, nss-systemd) needs a systemd
Linux machine; an OrbStack VM (`orb create ubuntu:24.04 t`) works well. The code is five
small files: `users.rs` (who exists), `varlink.rs` (the protocol), `host.rs` (homes),
`install.rs` (the installer, all config embedded), `main.rs`.
