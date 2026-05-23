package main

import (
	"fmt"
	"os"
)

// Step is one hardening action. Category groups related steps in the menu.
// Prompt is shown only when the all-flow asks before running on an in-use server.
type Step struct {
	Title    string
	Category string
	Prompt   string
	Fn       func(Config) error
}

// SecureSteps is the canonical list of hardening steps. Order matters: this
// is also the order used by the all-flow, and creating a sudo user must come
// before SSH hardening or you'll lock yourself out of a root-only droplet.
var SecureSteps = []Step{
	{Category: "User accounts", Title: "Create non-root sudo user", Prompt: "Create a new sudo user?", Fn: stepCreateUser},

	{Category: "System updates", Title: "APT update + upgrade", Prompt: "Run apt-get update && upgrade?", Fn: stepUpgrade},
	{Category: "System updates", Title: "unattended-upgrades (auto security patches)", Prompt: "Enable automatic security updates?", Fn: stepUnattendedUpgrades},

	{Category: "Time sync", Title: "chrony (time sync)", Prompt: "Install chrony?", Fn: stepChrony},

	{Category: "Network", Title: "UFW firewall (default-deny in, allow SSH)", Prompt: "Enable UFW?", Fn: stepUFW},
	{Category: "Network", Title: "Fail2ban (SSH brute-force protection)", Prompt: "Install Fail2ban?", Fn: stepFail2ban},

	{Category: "SSH", Title: "SSH hardening (sshd_config)", Prompt: "Apply SSH hardening?", Fn: stepSSH},

	{Category: "Auth", Title: "libpam-pwquality (password policy)", Prompt: "Install password complexity policy?", Fn: stepPwquality},

	{Category: "Kernel", Title: "Kernel hardening (sysctl)", Prompt: "Apply hardened sysctl defaults?", Fn: stepSysctl},
	{Category: "Kernel", Title: "AppArmor (verify enabled)", Prompt: "Confirm AppArmor is enabled?", Fn: stepAppArmor},

	{Category: "Monitoring", Title: "AIDE (file integrity)", Prompt: "Install and initialise AIDE? (slow on large filesystems)", Fn: stepAIDE},
	{Category: "Monitoring", Title: "inotify-tools + watcher service", Prompt: "Install inotify-tools and watcher for /etc, /bin, /usr/bin, /sbin?", Fn: stepInotify},
	{Category: "Monitoring", Title: "auditd (syscall auditing)", Prompt: "Install auditd?", Fn: stepAuditd},

	{Category: "Scanners", Title: "rkhunter + chkrootkit", Prompt: "Install rootkit scanners?", Fn: stepRootkit},
	{Category: "Scanners", Title: "Lynis (security audit)", Prompt: "Install Lynis?", Fn: stepLynis},

	{Category: "Containers", Title: "Docker CE (latest from docker.com)", Prompt: "Install the latest Docker from the official repo?", Fn: stepDocker},
	{Category: "Containers", Title: "ufw-docker (gate Docker ports via UFW)", Prompt: "Install ufw-docker so UFW actually filters container traffic?", Fn: stepUfwDocker},
}

type stepStatus int

const (
	stepOk stepStatus = iota
	stepSkipped
	stepFailed
)

type stepResult struct {
	Step   Step
	Status stepStatus
	Err    error
}

// runStep runs a single step directly. Used when the user picks one from the menu.
func runStep(cfg Config, s Step) error {
	return task(s.Title, func() error { return s.Fn(cfg) })
}

// runStepCollect runs a step as part of the all-flow and returns a result we
// can summarise at the end. In-use stage prompts before each step; new-stage
// runs through.
func runStepCollect(cfg Config, s Step) stepResult {
	fmt.Println()
	fmt.Println(step(s.Title))

	if cfg.interactive() && !confirm(s.Prompt, true) {
		fmt.Println(warn("skipped"))
		return stepResult{Step: s, Status: stepSkipped}
	}
	if err := s.Fn(cfg); err != nil {
		fmt.Println(errMsg(fmt.Sprintf("%s failed: %v", s.Title, err)))
		return stepResult{Step: s, Status: stepFailed, Err: err}
	}
	fmt.Println(ok(s.Title + " — done"))
	return stepResult{Step: s, Status: stepOk}
}

// SecureServer runs the full hardening flow and prints a summary.
func SecureServer(cfg Config) error {
	fmt.Println()
	fmt.Println(head(fmt.Sprintf("Securing %s Ubuntu server…", cfg.Stage)))

	results := make([]stepResult, 0, len(SecureSteps))
	for _, s := range SecureSteps {
		results = append(results, runStepCollect(cfg, s))
	}

	printSummary(results)
	return nil
}

func printSummary(results []stepResult) {
	fmt.Println()
	fmt.Println(head("Summary"))
	fmt.Println(cCyan + "═══════" + cReset)

	var okN, skipN, failN int
	prevCat := ""
	for _, r := range results {
		if r.Step.Category != prevCat {
			fmt.Println()
			fmt.Println("  " + cBold + r.Step.Category + cReset)
			prevCat = r.Step.Category
		}
		switch r.Status {
		case stepOk:
			fmt.Printf("    %s%s%s  %s\n", cGreen, "✓", cReset, r.Step.Title)
			okN++
		case stepSkipped:
			fmt.Printf("    %s%s%s  %s  %s(skipped)%s\n", cYellow, "○", cReset, r.Step.Title, cYellow, cReset)
			skipN++
		case stepFailed:
			fmt.Printf("    %s%s%s  %s  %s(failed: %v)%s\n", cRed, "✗", cReset, r.Step.Title, cRed, r.Err, cReset)
			failN++
		}
	}

	fmt.Println()
	fmt.Printf("  %s%d done%s · %s%d skipped%s · %s%d failed%s\n",
		cGreen, okN, cReset, cYellow, skipN, cReset, cRed, failN, cReset)

	fmt.Println()
	fmt.Println(head("Recommended follow-ups"))
	fmt.Println("  • Test SSH from a NEW terminal as the new sudo user before closing this one.")
	fmt.Println("  • Reboot if the kernel was upgraded.")
	fmt.Println("  • Run `sudo lynis audit system` and review the hardening score.")
	fmt.Println("  • Tail /var/log/inotify-watch.log to see filesystem alerts in real time.")
	fmt.Println("  • Check /var/log/aide/ tomorrow morning for the first daily AIDE report.")
	if failN > 0 {
		fmt.Println()
		fmt.Println(warn(fmt.Sprintf("%d step(s) failed — re-run them individually from the main menu after fixing the cause.", failN)))
	}
}

func stepUpgrade(cfg Config) error {
	if err := run("apt-get", "update"); err != nil {
		return err
	}
	return run("apt-get", "-y", "upgrade")
}

func stepUnattendedUpgrades(cfg Config) error {
	if err := aptInstall("unattended-upgrades", "apt-listchanges"); err != nil {
		return err
	}
	conf := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`
	return os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(conf), 0o644)
}

func stepUFW(cfg Config) error {
	if err := aptInstall("ufw"); err != nil {
		return err
	}
	if err := run("ufw", "default", "deny", "incoming"); err != nil {
		return err
	}
	if err := run("ufw", "default", "allow", "outgoing"); err != nil {
		return err
	}
	if err := run("ufw", "allow", "OpenSSH"); err != nil {
		return err
	}
	return run("ufw", "--force", "enable")
}

func stepFail2ban(cfg Config) error {
	if err := aptInstall("fail2ban"); err != nil {
		return err
	}
	jail := `[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
`
	if err := os.WriteFile("/etc/fail2ban/jail.local", []byte(jail), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "fail2ban"); err != nil {
		return err
	}
	return run("systemctl", "restart", "fail2ban")
}

func stepSSH(cfg Config) error {
	hasKey := hasAuthorizedKeys()
	disablePassword := false

	if hasKey {
		fmt.Println(ok("authorized_keys found — safe to disable password auth"))
		if cfg.interactive() {
			disablePassword = confirm("Disable SSH password authentication?", true)
		} else {
			disablePassword = true
		}
	} else {
		fmt.Println(warn("No authorized_keys found on any user. Leaving password auth ENABLED to avoid lockout."))
		fmt.Println(warn("Add a key with: ssh-copy-id user@this-host  — then re-run this step."))
	}

	return hardenSSH(disablePassword)
}

func stepAIDE(cfg Config) error {
	if err := aptInstall("aide", "aide-common"); err != nil {
		return err
	}
	fmt.Println(step("initialising AIDE database (this may take several minutes)…"))
	if err := run("aideinit", "-y", "-f"); err != nil {
		return err
	}
	if _, err := os.Stat("/var/lib/aide/aide.db.new"); err == nil {
		if err := os.Rename("/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db"); err != nil {
			return err
		}
	}
	cron := `#!/bin/sh
/usr/bin/aide.wrapper --check | tee /var/log/aide/aide-$(date +\%Y\%m\%d).log
`
	if err := os.MkdirAll("/var/log/aide", 0o750); err != nil {
		return err
	}
	return os.WriteFile("/etc/cron.daily/aide-check", []byte(cron), 0o755)
}

func stepInotify(cfg Config) error {
	if err := aptInstall("inotify-tools"); err != nil {
		return err
	}
	script := `#!/bin/sh
# Logs filesystem events on sensitive paths to /var/log/inotify-watch.log
exec /usr/bin/inotifywait -m -r \
  --timefmt '%Y-%m-%dT%H:%M:%S' \
  --format '%T %w%f %e' \
  -e modify,create,delete,move,attrib \
  /etc /bin /usr/bin /sbin
`
	if err := os.WriteFile("/usr/local/sbin/inotify-watch.sh", []byte(script), 0o755); err != nil {
		return err
	}
	unit := `[Unit]
Description=inotify watcher for sensitive paths
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/inotify-watch.sh
StandardOutput=append:/var/log/inotify-watch.log
StandardError=append:/var/log/inotify-watch.log
Restart=on-failure
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/inotify-watch.service", []byte(unit), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "inotify-watch.service"); err != nil {
		return err
	}
	return run("systemctl", "restart", "inotify-watch.service")
}

func stepAuditd(cfg Config) error {
	return aptInstall("auditd", "audispd-plugins")
}

func stepRootkit(cfg Config) error {
	return aptInstall("rkhunter", "chkrootkit")
}

func stepLynis(cfg Config) error {
	return aptInstall("lynis")
}

func stepChrony(cfg Config) error {
	if err := aptInstall("chrony"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "chrony"); err != nil {
		return err
	}
	return run("systemctl", "restart", "chrony")
}

func stepPwquality(cfg Config) error {
	if err := aptInstall("libpam-pwquality"); err != nil {
		return err
	}
	conf := `# Set by server-setup
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
`
	return os.WriteFile("/etc/security/pwquality.conf", []byte(conf), 0o644)
}

func stepSysctl(cfg Config) error {
	conf := `# Hardened defaults written by server-setup
# Network
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Kernel
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
`
	if err := os.WriteFile("/etc/sysctl.d/99-server-setup.conf", []byte(conf), 0o644); err != nil {
		return err
	}
	return run("sysctl", "--system")
}

func stepAppArmor(cfg Config) error {
	if err := aptInstall("apparmor", "apparmor-utils"); err != nil {
		return err
	}
	out, _ := runCapture("aa-status", "--enabled")
	fmt.Println(out)
	return run("systemctl", "enable", "--now", "apparmor")
}
