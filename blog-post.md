# Hardening Ubuntu droplets with a single Go binary

> Every fresh Ubuntu droplet ships open: SSH accepts passwords, root can log in, the firewall is off, system mail goes nowhere, and there's no intrusion detection. The first hour on every new box looks identical — and after working through the same hardening checklist from a notes file for the hundredth time, I built a small Go CLI to drive the whole flow.
>
> It's a single static binary you `scp` to a server and run as root. After choosing new-server or in-use mode, you get a categorised menu: create a sudo user, harden SSH, enable UFW, install Fail2ban, AIDE, inotify-tools, auditd, rkhunter, Lynis, apply kernel sysctls, configure unattended-upgrades, and wire up Postfix as a smarthost relay so AIDE and fail2ban can actually email you. Pick "Install ALL" to run the lot in the right order, or run steps one at a time and check each before moving on.
>
> This post walks through what each step does, why the order matters (user creation has to come before SSH hardening, or you'll lock yourself out), how to build and deploy the binary, and which steps you absolutely shouldn't run on a production server without thinking first.

---

Every sysadmin knows the routine. Spin up a fresh server, then spend the next hour running through the same hardening checklist: disable root SSH, lock down the firewall, install file integrity monitoring, set up time sync, configure auto-updates, wire up outbound mail. After working from a notes file for the hundredth time, I built a small Go CLI to drive the whole flow.

This post walks through what it does, how it's structured, and how to actually use it.

## The problem with a fresh droplet

A bare Ubuntu droplet — DigitalOcean, Linode, Hetzner, AWS Lightsail, it doesn't really matter — ships open. SSH accepts passwords, root can log in, the firewall is off, there's no intrusion detection, time sync may or may not be running, and system mail goes nowhere useful. None of that is *wrong*; it's a minimal base for you to build on. But it means the first hour on every new box looks identical.

The usual options for solving this are:

- **A long shell script.** Works, but eventually turns into a wall of `sed -i` calls that nobody wants to maintain.
- **A configuration management tool** (Ansible, Salt, Chef). Great if you've already adopted one. Heavy for a single box.
- **Pasting commands from a hardening guide.** Error-prone — you forget the order, miss a flag, lock yourself out, redeploy.

I wanted something between the shell script and the full config-management setup: a single static binary you `scp` to a box and run. Interactive enough to be safe, scripted enough to be quick.

## What it looks like

After running the binary as root, it asks two questions: is this a new server or one already in use, and which distro (only Ubuntu is supported right now). Then you get a menu:

```
Main menu
   1) Install ALL (run full secure flow)

   ── User accounts ──
   2) Create non-root sudo user

   ── System updates ──
   3) APT update + upgrade
   4) unattended-upgrades (auto security patches)

   ── Time sync ──
   5) chrony (time sync)

   ── Network ──
   6) UFW firewall (default-deny in, allow SSH)
   7) Fail2ban (SSH brute-force protection)

   ── SSH ──
   8) SSH hardening (sshd_config)

   ── Auth ──
   9) libpam-pwquality (password policy)

   ── Kernel ──
  10) Kernel hardening (sysctl)
  11) AppArmor (verify enabled)

   ── Monitoring ──
  12) AIDE (file integrity)
  13) inotify-tools + watcher service
  14) auditd (syscall auditing)

   ── Scanners ──
  15) rkhunter + chkrootkit
  16) Lynis (security audit)

   ── Mail ──
  17) Configure Postfix smarthost relay

   0) Exit
```

Option 1 runs everything in the right order. Options 2 through 17 run individual steps standalone. After each, you're returned to the menu — install one, check it, install the next.

## What each step does

**Create non-root sudo user.** Asks for a username, creates the account, adds it to `sudo`. You can set a password or lock it for key-only login. It offers to copy the existing root SSH key, paste a new one, or skip. Permissions and ownership on `.ssh/` are set correctly so SSHd actually honours the key.

This step is first deliberately — every other step assumes there's already a non-root sudo account, especially the SSH hardening step that disables root login.

**APT update + upgrade.** The boring but essential bit.

**unattended-upgrades.** Configures daily auto-install of security updates. Most people forget this and discover six months later they've been running an unpatched kernel.

**chrony.** Audit logs, AIDE reports, fail2ban bans, log correlation across hosts — all of those need accurate clocks to be useful. Chrony is more accurate than systemd-timesyncd and slews the clock smoothly under load.

**UFW.** Default-deny incoming, allow OpenSSH, then enable. This is the step that catches people out on existing servers — more on that in a moment.

**Fail2ban.** Bans IPs that hammer SSH with bad logins. Default jail config tuned for SSH only; you can add more jails in `/etc/fail2ban/jail.d/` later.

**SSH hardening.** Backs up `sshd_config` with a timestamp, then enforces a set of safer defaults: no root login, no password auth (only if a key is already authorised — we check first to avoid locking you out), no X11 or TCP forwarding, lower `MaxAuthTries`, sensible client keepalives. Critically, the tool runs `sshd -t` to validate the new config *before* reloading. If validation fails, the reload is skipped so you can review.

**libpam-pwquality.** 12-character minimum, three character classes, no repeats. Existing weak passwords keep working; only new ones are checked.

**sysctl hardening.** Network and kernel toggles: SYN cookies on, source routing off, IP redirects off, `dmesg_restrict`, ASLR, protected symlinks/hardlinks.

**AppArmor.** Installed and verified — usually default-on in Ubuntu, but worth confirming.

**AIDE.** File integrity database. The tool installs the package, runs `aideinit`, promotes the new database, and installs a daily cron job that diffs the filesystem against the baseline. The initial scan is slow — minutes on a small box, longer on busy ones.

**inotify-tools + watcher service.** A small systemd service that runs `inotifywait` against `/etc`, `/bin`, `/usr/bin`, `/sbin` recursively and appends every event to `/var/log/inotify-watch.log`. Real-time alerts to complement AIDE's daily snapshots.

**auditd.** Linux syscall auditing. Installed only; add your own rules to `/etc/audit/rules.d/`.

**rkhunter + chkrootkit.** Two rootkit scanners. Install only — running them is your call.

**Lynis.** A hardening audit tool. Run `sudo lynis audit system` after the install pass for a scored report on what's still loose.

**Postfix smarthost.** This is the one that ties everything together. AIDE cron, fail2ban notifications, Lynis reports, logwatch — they all want to email you. Without a working MTA, those notifications go nowhere. The tool prompts for an external SMTP relay (Gmail app password, Mailgun, SES, SendGrid, your own server) and a real inbox for root mail. It preseeds the Postfix install, writes SASL credentials with `0600` permissions, sets sender canonical rewriting (so `root@host` becomes your verified address — important for Mailgun and SES, which reject mismatched From headers), updates `/etc/aliases`, and offers to send a test mail.

## How the all-flow reports back

When "Install ALL" finishes, the tool prints a categorised summary so you can see at a glance what happened:

```
Summary
═══════

  User accounts
    ✓  Create non-root sudo user

  System updates
    ✓  APT update + upgrade
    ✓  unattended-upgrades (auto security patches)

  Monitoring
    ✓  AIDE (file integrity)
    ✓  inotify-tools + watcher service
    ✗  auditd (syscall auditing)  (failed: exit status 100)

  ...

  13 done · 0 skipped · 1 failed

Recommended follow-ups
  • Test SSH from a NEW terminal as the new sudo user before closing this one.
  • Reboot if the kernel was upgraded.
  • Run `sudo lynis audit system` and review the hardening score.
  • Tail /var/log/inotify-watch.log to see filesystem alerts in real time.
  • Check /var/log/aide/ tomorrow morning for the first daily AIDE report.

! 1 step(s) failed — re-run them individually from the main menu.
```

Failures don't crash the run; they're collected and shown at the end with the actual error, and you can re-pick the individual step from the menu after fixing the cause.

## Building and deploying

The tool is a single static Go binary. On macOS:

```sh
cd ServerSetup
GOOS=linux GOARCH=amd64 go build -o server-setup .
scp server-setup root@your-server:~
ssh root@your-server
./server-setup
```

For ARM servers (Graviton, Ampere, Raspberry Pi) use `GOARCH=arm64`. Check with `uname -m` on the target — `x86_64` is amd64, `aarch64` is arm64.

There are no runtime dependencies. The binary is statically linked: no Go on the server, no shared libraries to manage, no Python version drama.

## A word about running this on production

This tool was built with fresh servers in mind, and a couple of steps will cause an outage on a busy production box if you blindly pick "Install ALL":

- **UFW** is the big one. Default-deny incoming plus only-allow-SSH means your web ports, database ports, and custom service ports all go dark the moment UFW enables.
- **APT upgrade** restarts services and may pull a new kernel.
- **Postfix smarthost** reconfigures any existing Postfix install — fine if the box doesn't run a real mail server, problematic if it does.

On a fresh droplet, "Install ALL" is the right answer. On an in-use server, switch to in-use mode when prompted (it gates each step with a confirm) and pick steps individually. The genuinely safe-on-anything options are: pwquality, AppArmor verify, auditd, rkhunter, chkrootkit, Lynis, and AIDE.

## What's next

A few things on the roadmap:

- A `Makefile` with `build`, `deploy HOST=...`, and `run` targets
- Logrotate config for the inotify watcher log
- An "open additional ports" prompt before UFW enable, so you can keep web traffic flowing
- Optional non-default SSH port
- A per-host config file so you can drive the tool non-interactively from CI

The tool is a small Go module with no third-party dependencies. The whole thing is around 800 lines split across a handful of files: one per concern (menu, exec helpers, SSH editor, mail config, user creation, secure-server flow). Easy to read, easy to extend.

If a step is missing that you'd want, it's about a dozen lines to add: write the function, append a `Step` to the slice, and both the menu and the all-flow pick it up automatically.
