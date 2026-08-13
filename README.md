# server-setup

An interactive Go CLI that hardens a fresh Ubuntu server, then gets you working on it.

Every new box starts the same way: SSH accepts passwords, root can log in, there's no
firewall, system mail goes nowhere, and nothing is watching the filesystem. This walks
through that checklist once, in a fixed order, and — importantly — **proves each change
took effect** rather than assuming it did.

Single static binary, Go standard library only, no runtime dependencies.

## ⚠️ Disclaimer — read before running this

**Try this on a throwaway server first.**

This tool makes sweeping, privileged changes to a live system: it rewrites SSH
configuration, enables a default-deny firewall, changes kernel parameters, alters PAM
password policy, installs and removes packages, and can restrict how you authenticate.
Any one of those can leave you unable to reach the server — a mistyped port, a key that
isn't where you think it is, a firewall rule that doesn't match your setup.

It is provided **as is, without warranty of any kind**, as set out in [LICENSE](LICENSE).
You run it at your own risk, and you are responsible for the state of your systems.

Before running it against anything you care about:

- Try it on a disposable VM or snapshot that matches your real environment.
- Make sure you have **out-of-band access** — a provider web console (DigitalOcean,
  Hetzner, AWS), IPMI, or physical access. Do not let SSH be your only way in.
- Take a snapshot or backup first.
- Read the steps below and understand what each will change. Choose the **in-use
  server** mode on anything running real workloads.
- Never close the session that ran it until you have opened a *new* one and confirmed
  you can still log in.

The SSH steps include an automatic rollback timer (see [Safety model](#safety-model))
precisely because this category of change goes wrong. It reduces the risk; it does not
remove it. Nothing here is a substitute for testing, backups, and a second way in.

This tool is not a compliance control, an audit, or a guarantee of security. It applies
a reasonable set of defaults. It does not make a server "secure", and it is no
replacement for keeping systems patched and understanding your own threat model.

## Requirements

- Ubuntu (checked from `/etc/os-release`; the tool exits on anything else)
- Root — `sudo ./server-setup`
- Go 1.24+ to build
- OpenSSH 8.2+ for the YubiKey option (Ubuntu 20.04 and newer)

## Build and run

Build on your machine, copy the binary across:

```bash
GOOS=linux GOARCH=amd64 go build -o server-setup .
scp server-setup you@your-server:
ssh you@your-server 'sudo ./server-setup'
```

On first launch it asks whether this is a **new** server (apply defaults, minimal
prompting) or one **already in use** (confirm before every disruptive step). Pick
*in-use* on anything running real workloads — several steps behave more cautiously,
notably the Docker step, which will otherwise remove conflicting packages including
`containerd` and `runc` without asking.

If no non-root sudo user exists, the tool refuses to reach the main menu until you
create one. SSH hardening without a sudo account is a guaranteed lockout.

## Safety model

This is a tool that can lock you out of your own server, so three things guard every
SSH change:

1. **`sshd -t`** — syntax check before anything reloads.
2. **`sshd -T`** — asks sshd what it will *actually* do, and fails the step if a
   setting didn't take. This matters more than it sounds: Ubuntu 22.04+ reads
   `/etc/ssh/sshd_config.d/*.conf` *first*, and sshd keeps the **first** value it
   sees. Cloud images ship a `50-cloud-init.conf` containing
   `PasswordAuthentication yes`. Appending to the bottom of `sshd_config` — the
   obvious approach — silently does nothing. Settings are written to a drop-in that
   sorts first, conflicting global directives elsewhere are commented out, and the
   result is verified.
3. **Auto-rollback** — after a successful reload, a `systemd-run` timer is armed to
   restore the previous config in 10 minutes. Confirm you can still log in from a
   **new** terminal, then keep the changes:

   ```bash
   sudo systemctl stop ssh-rollback.timer
   ```

   Do nothing and the old config comes back on its own.

Directives inside `Match` blocks are never touched — they're connection-scoped and a
global drop-in couldn't override them anyway.

Password authentication is only disabled once a **non-root sudo user** has a real key
in `authorized_keys`. A root key doesn't count: root login is exactly what's being
turned off.

## Main menu

`1` runs everything in order. `2`–`17` run one step each. The rest are separate tools.

| Category | Step |
|---|---|
| User accounts | Create non-root sudo user |
| System updates | APT update + upgrade |
| System updates | unattended-upgrades (auto security patches) |
| Time sync | chrony |
| Network | UFW firewall (default-deny in, allow SSH) |
| Network | Fail2ban (SSH brute-force protection) |
| SSH | SSH hardening (sshd_config) |
| Auth | libpam-pwquality (password policy) |
| Kernel | Kernel hardening (sysctl) |
| Kernel | AppArmor (verify enabled) |
| Monitoring | AIDE (file integrity) |
| Monitoring | auditd (syscall auditing) |
| Scanners | rkhunter + chkrootkit |
| Scanners | Lynis (security audit) |
| Containers | Docker CE (official repo, GPG fingerprint verified) |
| Containers | ufw-docker (make UFW actually filter container traffic) |

The full run prints a per-step summary — done / skipped / failed — and failed steps can
be re-run individually.

A few details worth knowing:

- **UFW** allows the ports sshd actually listens on, read from `sshd -T`, not a
  hardcoded 22. Enabling a firewall that only opens port 22 on a server that moved SSH
  elsewhere is an instant lockout.
- **Docker** bypasses UFW by default — containers publishing ports are reachable
  regardless of firewall rules. The `ufw-docker` step closes that. It downloads a
  third-party script pinned to an immutable commit and verified against a SHA-256
  before it is ever made executable.
- **AIDE** relies on the packaged `/etc/cron.daily/aide`, which mails root. Set up mail
  below or you'll never see the reports.

## Extras

**Postfix smarthost relay** — routes system mail (cron, AIDE, fail2ban, Lynis) to a
real inbox via an external SMTP relay. Writes SASL credentials `0600` and rewrites the
sender so providers like SES and Mailgun don't reject mismatched From headers.

**Neovim + LSP starter** — Neovim from the stable PPA plus the toolchain for gopls,
intelephense, dockerls, bashls, jsonls and lua_ls. Drops a lazy.nvim config into a
chosen user's home; Mason installs the servers on first launch.

**GitHub login + clone** — stores a personal access token in git's `store` credential
helper so clones and pushes stop asking. The token is verified against the GitHub API
before it's saved, and read via `net/http` rather than `curl` so it never appears in a
command line where `ps` could expose it. Accepts `owner/repo`, HTTPS or SSH URLs
(normalised to HTTPS so the token applies), clones as the target user, and offers to
set the commit identity. Re-running offers replace / remove / clone-only.

> The token is stored **in plain text** at `~/.git-credentials` (mode `0600`). That's
> inherent to git's `store` helper — there's no keyring on a headless server. Use a
> fine-grained token scoped to the repos this server needs, `Contents: Read` unless it
> must push, with an expiry. Removing it locally does **not** revoke it; do that at
> <https://github.com/settings/tokens>.

**YubiKey / FIDO2** — the server half of hardware-key SSH. The key itself is generated
on your laptop (`ssh-keygen -t ed25519-sk`) and the private half never leaves the
YubiKey; the server only stores the public key. This option prints the exact laptop
commands, installs the pasted public key, and can optionally restrict SSH to
hardware-backed keys — auditing first and showing you every key that would stop
working. It refuses if no sudo user has a hardware key yet, and the change goes through
the same verify-and-rollback path as the rest of the SSH config.

`libpam-u2f` for sudo is deliberately **not** included: it needs the YubiKey physically
plugged into the machine doing the authenticating, which on a remote server is a
lockout rather than a security control.

## After a run

```bash
# 1. From a NEW terminal, confirm you can still log in, then:
sudo systemctl stop ssh-rollback.timer

# 2. Confirm sshd is really doing what you think:
sudo sshd -T | grep -Ei 'passwordauth|permitroot|port '

# 3. Review the hardening score:
sudo lynis audit system
```

Reboot if the kernel was upgraded. The first AIDE report arrives in root's mail the
following day.

## Upgrading from an earlier version

If you ran a pre-fix build on a server, two things are worth checking. Its SSH
hardening may never have applied (the drop-in ordering bug above), and its Fail2ban
config needed a package that wasn't installed:

```bash
sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin'
systemctl status fail2ban
```

Re-running fixes both. Older builds also left two things behind that current versions
no longer create and won't clean up:

```bash
sudo systemctl disable --now inotify-watch.service
sudo rm -f /etc/systemd/system/inotify-watch.service /usr/local/sbin/inotify-watch.sh
sudo rm -f /etc/cron.daily/aide-check          # duplicates the packaged job
sudo systemctl daemon-reload
```

## Development

```bash
go test ./...     # config rewriting, key parsing, URL handling
go vet ./...
gofmt -l .
```

Tests cover the logic that would be dangerous to get wrong: sshd_config rewriting
(including `Match` blocks and `Key=value` forms), SSH key type and comment parsing,
credential-file filtering, and repo URL normalisation. The rest is command
orchestration that only means anything on a live server.

To bump the pinned `ufw-docker`, download the new file, run `sha256sum` on it, and
update both `ufwDockerCommit` and `ufwDockerSHA256` in `ufw_docker.go` together.

| File | Contains |
|---|---|
| `main.go` | Entry point, signal handling, menu dispatch |
| `secure.go` | Step list, the all-flow, most hardening steps |
| `ssh.go` | sshd_config rewriting, verification, rollback |
| `user.go` | Account creation, authorized_keys, key parsing |
| `docker.go` / `ufw_docker.go` | Docker CE and UFW integration |
| `mail.go` | Postfix smarthost |
| `nvim.go` | Neovim + LSP |
| `github.go` | Token storage and cloning |
| `yubikey.go` | FIDO2 keys and policy |
| `ui.go` / `exec.go` / `types.go` | Prompts, command running, shared types |

## License

MIT — see [LICENSE](LICENSE).

The "AS IS" and limitation-of-liability terms in that file are not boilerplate here.
Please read the disclaimer at the top of this file.
