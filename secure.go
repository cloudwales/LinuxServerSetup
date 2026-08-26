package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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

	{Category: "Monitoring", Title: "AIDE (file integrity + emailed daily report)", Prompt: "Install and initialise AIDE? (slow on large filesystems)", Fn: stepAIDE},
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

	// Last thing on a fresh server: get the code onto it.
	fmt.Println()
	if confirm("Set up GitHub access and clone a repository now?", true) {
		if err := ConfigureGitHub(cfg); err != nil {
			fmt.Println(errMsg(fmt.Sprintf("GitHub setup failed: %v", err)))
			fmt.Println(warn("re-run it any time from the main menu"))
		}
	}
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
	fmt.Println("  • Test SSH from a NEW terminal as the sudo user, THEN cancel the rollback:")
	fmt.Println("      " + cBold + "systemctl stop " + sshRollbackUnit + ".timer" + cReset)
	fmt.Println("  • Confirm what sshd is really doing: `sudo sshd -T | grep -Ei 'passwordauth|permitroot'`.")
	fmt.Println("  • Reboot if the kernel was upgraded.")
	fmt.Println("  • Run `sudo lynis audit system` and review the hardening score.")
	fmt.Println("  • Running a web server? UFW now blocks 80/443 — open them from the main menu.")
	fmt.Println("  • Watch for the first AIDE report in root's mail tomorrow (`mail` / your relay inbox).")
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
	if err := os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(conf), 0o644); err != nil {
		return err
	}
	return run("systemctl", "enable", "--now", "unattended-upgrades")
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
	// Allow the ports sshd actually listens on. The "OpenSSH" app profile is
	// port 22 only — on a server that has moved SSH elsewhere, enabling UFW
	// with that profile is an instant lockout.
	for _, p := range sshPorts() {
		if err := run("ufw", "allow", fmt.Sprintf("%d/tcp", p)); err != nil {
			return err
		}
		fmt.Println(ok(fmt.Sprintf("allowed SSH on port %d/tcp", p)))
	}
	if err := run("ufw", "--force", "enable"); err != nil {
		return err
	}
	// The single most common surprise after this step: SSH is the only thing
	// open, so Caddy/nginx and every ACME challenge start failing.
	fmt.Println(warn("Only SSH is open now — 80/443 are blocked. Use the web ports option to open them."))
	return nil
}

func stepFail2ban(cfg Config) error {
	// python3-systemd is only a Recommends, and aptInstall passes
	// --no-install-recommends — without it the systemd backend below cannot
	// start and the whole jail silently fails.
	if err := aptInstall("fail2ban", "python3-systemd"); err != nil {
		return err
	}
	var ports []string
	for _, p := range sshPorts() {
		ports = append(ports, strconv.Itoa(p))
	}
	jail := fmt.Sprintf(`[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = %s
`, strings.Join(ports, ","))
	if err := os.WriteFile("/etc/fail2ban/jail.local", []byte(jail), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "fail2ban"); err != nil {
		return err
	}
	return run("systemctl", "restart", "fail2ban")
}

func stepSSH(cfg Config) error {
	disablePassword := false

	// The key has to belong to a non-root sudo user. Root nearly always has one
	// and root login is exactly what this step disables, so a root key is no
	// evidence at all that anyone can still get in.
	if user, hasKey := authorizedKeyUser(); hasKey {
		fmt.Println(ok("sudo user " + user + " has an authorized key — safe to disable password auth"))
		if cfg.interactive() {
			disablePassword = confirm("Disable SSH password authentication?", true)
		} else {
			disablePassword = true
		}
	} else {
		fmt.Println(warn("No non-root sudo user has an authorized_keys entry."))
		fmt.Println(warn("Leaving password auth ENABLED to avoid lockout (root login is still disabled)."))
		fmt.Println(warn("Add a key with: ssh-copy-id user@this-host  — then re-run this step."))
	}

	fmt.Println(warn("Note: TCP and agent forwarding are disabled — this breaks `ssh -L` tunnels,"))
	fmt.Println(warn("jump hosts (`ssh -J`) and some IDE remote features. Re-enable per-user with a"))
	fmt.Println(warn("Match block if you need them."))

	return hardenSSH(disablePassword)
}

const aideDefaultsPath = "/etc/default/aide"

func stepAIDE(cfg Config) error {
	if err := aptInstall("aide", "aide-common"); err != nil {
		return err
	}

	// Wire up the report before the database build: aideinit takes minutes on
	// a real filesystem and nobody should be sat waiting on it for a prompt.
	if err := configureAIDEMail(cfg); err != nil {
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
	// No custom cron here: aide-common already ships /etc/cron.daily/aide,
	// which runs the check and mails $MAILTO. A second job would just scan the
	// filesystem twice a night and write a logfile nothing rotates.
	fmt.Println(ok("daily check runs via the packaged /etc/cron.daily/aide"))
	return nil
}

// configureAIDEMail points the packaged daily check at an inbox someone reads.
// An integrity monitor whose report lands in /var/mail/root on a box no one
// logs into is a monitor in name only, so this also offers to set up the relay
// when there isn't one.
func configureAIDEMail(cfg Config) error {
	relay := mailRelayHost()
	if relay == "" {
		fmt.Println()
		fmt.Println(warn("No outgoing mail relay is configured — AIDE reports would sit in root's local mailbox."))
		if confirm("Set up the relay now (Postmark by default)?", true) {
			if err := ConfigureMail(cfg); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("mail setup failed: %v", err)))
				fmt.Println(warn("continuing — re-run mail setup from the main menu, AIDE will pick it up automatically"))
			}
			relay = mailRelayHost()
		}
	} else {
		fmt.Println(ok("outgoing relay: " + relay))
	}

	def := rootAliasTarget()
	if def == "" {
		def = "root"
	}
	addr := readLine(fmt.Sprintf("Email AIDE reports to [%s]: ", def))
	if addr == "" {
		addr = def
	}

	if err := writeAIDEDefaults(addr); err != nil {
		return err
	}
	fmt.Println(ok("daily AIDE report will be mailed to " + addr))

	if relay == "" {
		fmt.Println(warn("no relay yet — reports will queue locally until one is configured"))
		return nil
	}
	if confirm("Send a test email to "+addr+" now?", true) {
		if err := sendTestMailTo(addr, "", "server-setup: AIDE reports will arrive here"); err != nil {
			fmt.Println(errMsg(fmt.Sprintf("test mail failed: %v", err)))
			fmt.Println(warn("check /var/log/mail.log — AIDE itself is still configured"))
			return nil
		}
		fmt.Println(ok("test mail queued — check the inbox and /var/log/mail.log"))
	}
	return nil
}

// writeAIDEDefaults sets the mail-related knobs in /etc/default/aide, which
// /etc/cron.daily/aide sources.
func writeAIDEDefaults(mailto string) error {
	if _, err := os.Stat(aideDefaultsPath); err != nil {
		return fmt.Errorf("%s is missing — is aide-common installed?: %w", aideDefaultsPath, err)
	}
	return setShellVars(aideDefaultsPath, map[string]string{
		"CRON_DAILY_RUN": "yes",
		"MAILTO":         mailto,
		"MAILSUBJ":       `"AIDE report for $FQDN"`,
		// A silent job is indistinguishable from a broken one, so mail the
		// report even on a night with no changes.
		"QUIETREPORTS": "no",
	})
}

// setShellVars rewrites KEY=value assignments in a shell-sourced defaults
// file: existing assignments are replaced in place (comments left alone) and
// anything missing is appended.
func setShellVars(path string, vars map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	for i, l := range lines {
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		k, _, found := strings.Cut(trim, "=")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v, want := vars[k]
		if !want {
			continue
		}
		lines[i] = k + "=" + v
		seen[k] = true
	}
	// Drop the empty element the final newline leaves behind, so appended
	// assignments don't land after a blank line.
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	for _, k := range sortedKeys(vars) {
		if !seen[k] {
			lines = append(lines, k+"="+vars[k])
		}
	}

	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o644)
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
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
# Kernel
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
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
	if _, err := runCapture("aa-status", "--enabled"); err != nil {
		fmt.Println(warn("AppArmor is not enabled in this kernel — profiles will not be enforced"))
	}
	return run("systemctl", "enable", "--now", "apparmor")
}
