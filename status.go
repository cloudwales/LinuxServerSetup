package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// checkState is how a single observation reads at a glance. It is deliberately
// not "pass/fail": plenty of what this report shows (kernel version, open
// ports) is neither good nor bad, it is just what the operator needs to see.
type checkState int

const (
	stateGood checkState = iota
	stateWarn
	stateBad
	stateInfo
)

type checkItem struct {
	Name   string
	Detail string
	State  checkState
}

type checkSection struct {
	Title string
	Items []checkItem
}

func (s *checkSection) add(state checkState, name, detail string) {
	s.Items = append(s.Items, checkItem{Name: name, Detail: detail, State: state})
}

func (s *checkSection) addf(state checkState, name, format string, a ...any) {
	s.add(state, name, fmt.Sprintf(format, a...))
}

// installed is the common "is this package here or not" item, so every section
// reports a missing package the same way.
func (s *checkSection) installed(name, pkg string, absent checkState) bool {
	if pkgInstalled(pkg) {
		return true
	}
	s.add(absent, name, "not installed")
	return false
}

// ShowStatus prints what is actually on this server: installed, running, and
// in effect. It is strictly read-only — nothing here changes the machine, so
// it is safe to run on a box you did not set up.
func ShowStatus() error {
	fmt.Println()
	fmt.Println(step("collecting status…"))

	sections := []checkSection{
		statusSystem(),
		statusUsers(),
		statusUpdates(),
		statusTime(),
		statusNetwork(),
		statusWeb(),
		statusSSH(),
		statusAuth(),
		statusKernel(),
		statusMonitoring(),
		statusScanners(),
		statusMail(),
		statusContainers(),
		statusDevTools(),
	}
	renderStatus(sections)
	return nil
}

func renderStatus(sections []checkSection) {
	width := 0
	for _, sec := range sections {
		for _, it := range sec.Items {
			if len(it.Name) > width {
				width = len(it.Name)
			}
		}
	}

	fmt.Println()
	fmt.Println(head("Server status"))
	fmt.Println(cCyan + "═════════════" + cReset)

	var good, warnN, bad int
	var attention []string
	for _, sec := range sections {
		if len(sec.Items) == 0 {
			continue
		}
		fmt.Println()
		fmt.Println("  " + cBold + sec.Title + cReset)
		for _, it := range sec.Items {
			mark, colour := "·", cCyan
			switch it.State {
			case stateGood:
				mark, colour = "✓", cGreen
				good++
			case stateWarn:
				mark, colour = "!", cYellow
				warnN++
				attention = append(attention, sec.Title+" — "+it.Name+": "+it.Detail)
			case stateBad:
				mark, colour = "✗", cRed
				bad++
				attention = append(attention, sec.Title+" — "+it.Name+": "+it.Detail)
			}
			fmt.Printf("    %s%s%s  %-*s  %s\n", colour, mark, cReset, width, it.Name, it.Detail)
		}
	}

	fmt.Println()
	fmt.Printf("  %s%d ok%s · %s%d warning%s · %s%d problem%s\n",
		cGreen, good, cReset, cYellow, warnN, cReset, cRed, bad, cReset)

	if len(attention) > 0 {
		fmt.Println()
		fmt.Println(head("Needs attention"))
		for _, a := range attention {
			fmt.Println("  • " + a)
		}
	}
}

// ── sections ────────────────────────────────────────────────────────────────

func statusSystem() checkSection {
	s := checkSection{Title: "System"}

	host, _ := runOut("hostname", "-f")
	if host == "" {
		host, _ = runOut("hostname")
	}
	s.add(stateInfo, "Hostname", host)

	_, name := detectDistro()
	s.add(stateInfo, "OS", name)

	kernel, _ := runOut("uname", "-r")
	arch, _ := runOut("uname", "-m")
	s.add(stateInfo, "Kernel", kernel+" ("+arch+")")

	if up, err := runOut("uptime", "-p"); err == nil && up != "" {
		s.add(stateInfo, "Uptime", up)
	}

	if used, detail, err := rootDiskUsage(); err == nil {
		state := stateGood
		if used >= 90 {
			state = stateBad
		} else if used >= 80 {
			state = stateWarn
		}
		s.add(state, "Disk /", detail)
	}

	if fileExists("/var/run/reboot-required") {
		detail := "required"
		if pkgs := rebootRequiredPkgs(); pkgs != "" {
			detail += " (" + pkgs + ")"
		}
		s.add(stateWarn, "Reboot", detail)
	} else {
		s.add(stateGood, "Reboot", "not required")
	}

	return s
}

func statusUsers() checkSection {
	s := checkSection{Title: "User accounts"}

	sudoers := sudoGroupMembers()
	if len(sudoers) == 0 {
		s.add(stateBad, "Sudo users", "none besides root — SSH hardening would lock you out")
	} else {
		s.add(stateGood, "Sudo users", strings.Join(sudoers, ", "))
	}

	if u, has := authorizedKeyUser(); has {
		s.add(stateGood, "SSH key access", u+" has an authorized key")
	} else {
		s.add(stateBad, "SSH key access", "no non-root sudo user has an authorized_keys entry")
	}

	if hw, sw, err := auditSudoKeys(); err != nil {
		s.add(stateWarn, "Key inventory", "could not read: "+err.Error())
	} else {
		s.addf(stateInfo, "Key inventory", "%d hardware-backed, %d software key(s)", len(hw), len(sw))
	}

	if policyInstalled() {
		s.add(stateGood, "Hardware-key policy", "enforced (sshd drop-in present)")
	} else {
		s.add(stateInfo, "Hardware-key policy", "not enforced")
	}

	return s
}

func statusUpdates() checkSection {
	s := checkSection{Title: "System updates"}

	if s.installed("unattended-upgrades", "unattended-upgrades", stateBad) {
		periodic := aptPeriodicEnabled()
		switch {
		case svcEnabled("unattended-upgrades") && periodic:
			s.add(stateGood, "unattended-upgrades", "installed, enabled, APT::Periodic on")
		case periodic:
			s.add(stateWarn, "unattended-upgrades", "APT::Periodic on but the unit is not enabled")
		default:
			s.add(stateWarn, "unattended-upgrades", "installed but APT::Periodic is not switched on")
		}
	}

	total, sec := pendingUpgrades()
	switch {
	case total < 0:
		s.add(stateInfo, "Pending upgrades", "could not query apt")
	case sec > 0:
		s.addf(stateWarn, "Pending upgrades", "%d package(s), %d security (from the last apt-get update)", total, sec)
	case total > 0:
		s.addf(stateInfo, "Pending upgrades", "%d package(s), none security", total)
	default:
		s.add(stateGood, "Pending upgrades", "none")
	}

	return s
}

func statusTime() checkSection {
	s := checkSection{Title: "Time sync"}

	if s.installed("chrony", "chrony", stateWarn) {
		unit := "chrony"
		if !svcExists(unit) {
			unit = "chronyd"
		}
		if svcActive(unit) {
			s.add(stateGood, "chrony", "running")
		} else {
			s.add(stateBad, "chrony", "installed but not running")
		}
	}

	switch synced, _ := runOut("timedatectl", "show", "-p", "NTPSynchronized", "--value"); strings.TrimSpace(synced) {
	case "yes":
		s.add(stateGood, "Clock", "synchronised")
	case "no":
		s.add(stateWarn, "Clock", "not synchronised")
	}

	return s
}

func statusNetwork() checkSection {
	s := checkSection{Title: "Network"}

	if !haveCmd("ufw") {
		s.add(stateBad, "UFW", "not installed")
	} else {
		out, _ := runCapture("ufw", "status", "verbose")
		switch {
		case strings.Contains(out, "Status: active"):
			policy := "unknown default policy"
			if m := regexp.MustCompile(`(?m)^Default: (.+)$`).FindStringSubmatch(out); m != nil {
				policy = strings.TrimSpace(m[1])
			}
			state := stateGood
			if !strings.Contains(policy, "deny (incoming)") && !strings.Contains(policy, "reject (incoming)") {
				state = stateWarn
			}
			s.add(state, "UFW", "active — default "+policy)
			if allowed := ufwAllowed(out); allowed != "" {
				s.add(stateInfo, "UFW allows", allowed)
			}
		default:
			s.add(stateBad, "UFW", "installed but inactive")
		}
	}

	if s.installed("Fail2ban", "fail2ban", stateBad) {
		if !svcActive("fail2ban") {
			s.add(stateBad, "Fail2ban", "installed but not running")
		} else {
			jails := fail2banJails()
			if len(jails) == 0 {
				s.add(stateWarn, "Fail2ban", "running with no jails enabled")
			} else {
				s.add(stateGood, "Fail2ban", "running — jails: "+strings.Join(jails, ", "))
			}
			if n := fail2banBanned("sshd"); n > 0 {
				s.addf(stateInfo, "Fail2ban bans", "%d address(es) currently banned in sshd", n)
			}
		}
	}

	if l := publicListeners(); l != "" {
		s.add(stateInfo, "Listening", l)
	}

	return s
}

// statusWeb answers the question a reverse proxy actually raises: is 80/443
// open, and is anything behind it. Both halves have to be true, and each one
// fails in a way that looks like the other.
func statusWeb() checkSection {
	s := checkSection{Title: "Web (80/443)"}

	ufwOn := haveCmd("ufw") && ufwActive()
	rules, _ := runCapture("ufw", "status")
	ls := listeners()

	for _, p := range webPorts {
		label := fmt.Sprintf("%d/%s", p.Port, p.Proto)

		var bound []string
		for _, l := range ls {
			if l.Port == p.Port && l.Proto == p.Proto && !l.loopback() {
				bound = append(bound, l.describe())
			}
		}
		who := strings.Join(bound, ", ")
		allowed := ufwAllowsPort(rules, p.Port, p.Proto)

		switch {
		case !ufwOn && len(bound) == 0:
			s.add(stateInfo, label, "nothing listening (UFW is not active)")
		case !ufwOn:
			s.add(stateInfo, label, who+" (UFW is not active, so nothing is filtering it)")
		case !allowed && len(bound) == 0:
			s.add(stateInfo, label, "blocked by UFW, nothing listening")
		case !allowed:
			s.add(stateBad, label, who+" — but UFW has no rule for it, so it is unreachable")
		case len(bound) == 0:
			s.add(stateInfo, label, "allowed through UFW, nothing listening")
		default:
			s.add(stateGood, label, who)
		}
	}

	if haveCmd("docker") {
		if containers, err := webContainers(); err == nil && len(containers) > 0 {
			var names []string
			for _, c := range containers {
				names = append(names, c.Name+" ("+c.summary()+")")
			}
			state, detail := stateInfo, truncateList(names, 4)
			// ufw-docker filters the FORWARD chain, which plain `ufw allow`
			// never touches. Without a forward rule these ports stay blocked
			// no matter what the INPUT rules say — the exact case that looks
			// like "I opened the port and it still doesn't work".
			if fileExists(ufwDockerPath) && ufwOn && !strings.Contains(rules, "FWD") {
				state = stateBad
				detail += " — ufw-docker is filtering and no forward rule allows them"
			}
			s.add(state, "Container ports", detail)
		}
	}

	if state := caddyServiceState(); state != "" {
		if state == "active" {
			s.add(stateGood, "caddy.service", "running")
		} else {
			s.add(stateWarn, "caddy.service", state)
		}
	}

	return s
}

// ufwAllowsPort scans `ufw status` for a rule admitting this port. A rule
// added without a protocol shows as a bare port number and covers both, so
// matching only "443/udp" would miss it.
func ufwAllowsPort(status string, port int, proto string) bool {
	want := map[string]bool{
		fmt.Sprintf("%d/%s", port, proto): true,
		strconv.Itoa(port):                true,
	}
	for _, l := range strings.Split(status, "\n") {
		if !strings.Contains(l, "ALLOW") {
			continue
		}
		f := strings.Fields(l)
		if len(f) > 0 && want[f[0]] {
			return true
		}
	}
	return false
}

func statusSSH() checkSection {
	s := checkSection{Title: "SSH"}

	eff, err := sshdEffective()
	if err != nil {
		s.add(stateWarn, "sshd -T", "could not query sshd: "+err.Error())
		return s
	}

	s.add(stateInfo, "Ports", joinInts(sshPorts()))

	report := func(name, key, want string, mismatch checkState) {
		got, present := eff[strings.ToLower(key)]
		if !present {
			s.add(stateInfo, name, "not reported by sshd")
			return
		}
		if got == want {
			s.add(stateGood, name, got)
		} else {
			s.add(mismatch, name, got+" (hardened value is "+want+")")
		}
	}
	report("Root login", "permitrootlogin", "no", stateBad)
	report("Password auth", "passwordauthentication", "no", stateWarn)
	report("Pubkey auth", "pubkeyauthentication", "yes", stateBad)
	report("TCP forwarding", "allowtcpforwarding", "no", stateInfo)
	report("Agent forwarding", "allowagentforwarding", "no", stateInfo)
	report("X11 forwarding", "x11forwarding", "no", stateInfo)
	if v, present := eff["maxauthtries"]; present {
		s.add(stateInfo, "MaxAuthTries", v)
	}

	if dir, err := sshdIncludeDir(); err == nil && dir != "" {
		if fileExists(filepath.Join(dir, sshdDropInName)) {
			s.add(stateGood, "Hardening drop-in", filepath.Join(dir, sshdDropInName))
		} else {
			s.add(stateWarn, "Hardening drop-in", "not present — SSH hardening has not been applied")
		}
	}

	if svcActive(sshRollbackUnit+".timer") || svcEnabled(sshRollbackUnit+".timer") {
		s.add(stateWarn, "SSH rollback", "armed — it will revert sshd_config; stop it with: systemctl stop "+sshRollbackUnit+".timer")
	}

	return s
}

func statusAuth() checkSection {
	s := checkSection{Title: "Auth"}

	if s.installed("Password policy", "libpam-pwquality", stateWarn) {
		detail := "libpam-pwquality installed"
		if v := shellVar("/etc/security/pwquality.conf", "minlen"); v != "" {
			detail += " (minlen " + v + ")"
		}
		s.add(stateGood, "Password policy", detail)
	}

	return s
}

func statusKernel() checkSection {
	s := checkSection{Title: "Kernel"}

	const sysctlFile = "/etc/sysctl.d/99-server-setup.conf"
	if fileExists(sysctlFile) {
		s.add(stateGood, "sysctl profile", sysctlFile)
	} else {
		s.add(stateWarn, "sysctl profile", "not written — kernel hardening step has not run")
	}

	// Spot-check the live values rather than the file: a later drop-in or a
	// cloud-init snippet can override anything we wrote.
	want := map[string]string{
		"kernel.kptr_restrict":        "2",
		"kernel.dmesg_restrict":       "1",
		"kernel.randomize_va_space":   "2",
		"net.ipv4.tcp_syncookies":     "1",
		"net.ipv4.conf.all.rp_filter": "1",
	}
	var off []string
	for _, k := range sortedKeys(want) {
		out, err := runOut("sysctl", "-n", k)
		if err != nil {
			continue
		}
		f := strings.Fields(out)
		if len(f) == 0 {
			continue
		}
		if f[0] != want[k] {
			off = append(off, fmt.Sprintf("%s=%s (want %s)", k, f[0], want[k]))
		}
	}
	if len(off) == 0 {
		s.add(stateGood, "sysctl in effect", "spot-checked values match")
	} else {
		s.add(stateWarn, "sysctl in effect", strings.Join(off, ", "))
	}

	if _, err := runOut("aa-status", "--enabled"); err != nil {
		s.add(stateWarn, "AppArmor", "not enabled in this kernel")
	} else {
		detail := "enabled"
		if n, err := runOut("aa-status", "--enforced"); err == nil && n != "" {
			detail = n + " profile(s) enforcing"
		}
		s.add(stateGood, "AppArmor", detail)
	}

	return s
}

func statusMonitoring() checkSection {
	s := checkSection{Title: "Monitoring"}

	if s.installed("AIDE", "aide", stateWarn) {
		if fi, err := os.Stat("/var/lib/aide/aide.db"); err == nil {
			age := time.Since(fi.ModTime())
			s.addf(stateGood, "AIDE database", "initialised %s (%d day(s) ago)",
				fi.ModTime().Format("2006-01-02"), int(age.Hours()/24))
		} else {
			s.add(stateBad, "AIDE database", "/var/lib/aide/aide.db missing — the daily check has nothing to compare against")
		}

		if fileExists("/etc/cron.daily/aide") {
			s.add(stateGood, "AIDE daily check", "/etc/cron.daily/aide")
		} else {
			s.add(stateWarn, "AIDE daily check", "cron job missing — install aide-common")
		}

		mailto := shellVar(aideDefaultsPath, "MAILTO")
		switch {
		case mailto == "":
			s.add(stateWarn, "AIDE report goes to", "MAILTO unset in "+aideDefaultsPath)
		case mailto == "root":
			if alias := rootAliasTarget(); alias != "" {
				s.add(stateGood, "AIDE report goes to", "root → "+alias)
			} else {
				s.add(stateWarn, "AIDE report goes to", "root, with no alias to a real inbox — reports stay in /var/mail")
			}
		default:
			s.add(stateGood, "AIDE report goes to", mailto)
		}
	}

	if s.installed("auditd", "auditd", stateWarn) {
		if svcActive("auditd") {
			detail := "running"
			if out, err := runOut("auditctl", "-l"); err == nil {
				if strings.Contains(out, "No rules") || out == "" {
					detail = "running with no rules loaded"
				} else {
					detail = fmt.Sprintf("running, %d rule(s) loaded", len(strings.Split(out, "\n")))
				}
			}
			s.add(stateGood, "auditd", detail)
		} else {
			s.add(stateBad, "auditd", "installed but not running")
		}
	}

	return s
}

func statusScanners() checkSection {
	s := checkSection{Title: "Scanners"}
	for _, p := range []struct{ name, pkg string }{
		{"rkhunter", "rkhunter"},
		{"chkrootkit", "chkrootkit"},
		{"Lynis", "lynis"},
	} {
		if pkgInstalled(p.pkg) {
			s.add(stateGood, p.name, "installed")
		} else {
			s.add(stateInfo, p.name, "not installed")
		}
	}
	return s
}

func statusMail() checkSection {
	s := checkSection{Title: "Mail"}

	if !s.installed("Postfix", "postfix", stateWarn) {
		s.add(stateWarn, "System mail", "nothing will deliver cron, AIDE or fail2ban reports")
		return s
	}

	if svcActive("postfix") {
		s.add(stateGood, "Postfix", "running")
	} else {
		s.add(stateBad, "Postfix", "installed but not running")
	}

	relay := mailRelayHost()
	if relay == "" {
		s.add(stateWarn, "Relay", "no smarthost set — this server is trying to deliver mail itself")
	} else {
		s.add(stateGood, "Relay", relay+" ("+relayProvider(relay)+")")
	}

	if fi, err := os.Stat("/etc/postfix/sasl_passwd"); err != nil {
		s.add(stateWarn, "SASL credentials", "/etc/postfix/sasl_passwd missing")
	} else if fi.Mode().Perm() != 0o600 {
		s.addf(stateWarn, "SASL credentials", "present but world-readable (mode %04o, want 0600)", fi.Mode().Perm())
	} else {
		s.add(stateGood, "SASL credentials", "present, mode 0600")
	}

	if alias := rootAliasTarget(); alias == "" {
		s.add(stateWarn, "Root alias", "unset — root's mail stays in /var/mail/root")
	} else {
		s.add(stateGood, "Root alias", alias)
	}

	switch n := mailQueueDepth(); {
	case n < 0:
		s.add(stateInfo, "Mail queue", "could not read the queue")
	case n == 0:
		s.add(stateGood, "Mail queue", "empty")
	default:
		s.addf(stateWarn, "Mail queue", "%d message(s) queued — check /var/log/mail.log", n)
	}

	return s
}

func statusContainers() checkSection {
	s := checkSection{Title: "Containers"}

	if !haveCmd("docker") {
		s.add(stateInfo, "Docker", "not installed")
		return s
	}
	version, _ := runOut("docker", "--version")
	if svcActive("docker") {
		s.add(stateGood, "Docker", version)
		if out, err := runOut("docker", "ps", "-q"); err == nil {
			s.addf(stateInfo, "Containers", "%d running", len(nonEmptyLines(out)))
		}
	} else {
		s.add(stateWarn, "Docker", version+" — installed but not running")
	}

	afterRules, _ := os.ReadFile("/etc/ufw/after.rules")
	switch {
	case !fileExists(ufwDockerPath):
		s.add(stateBad, "ufw-docker", "not installed — published container ports bypass UFW entirely")
	case !strings.Contains(string(afterRules), "BEGIN UFW AND DOCKER"):
		s.add(stateBad, "ufw-docker", "binary present but its rules are not in /etc/ufw/after.rules")
	default:
		s.add(stateGood, "ufw-docker", "installed — container ports are filtered by UFW")
	}

	return s
}

func statusDevTools() checkSection {
	s := checkSection{Title: "Developer tools"}

	if haveCmd("nvim") {
		v, _ := runOut("nvim", "--version")
		s.add(stateGood, "Neovim", firstLine(v))
	} else {
		s.add(stateInfo, "Neovim", "not installed")
	}

	var logins []string
	for _, u := range sudoGroupMembers() {
		home := userHome(u)
		if home == "" {
			continue
		}
		if login := storedGitHubLogin(home); login != "" {
			logins = append(logins, u+" → "+login)
		}
	}
	if len(logins) == 0 {
		s.add(stateInfo, "GitHub credentials", "none stored")
	} else {
		s.add(stateGood, "GitHub credentials", strings.Join(logins, ", "))
	}

	return s
}

// ── helpers ─────────────────────────────────────────────────────────────────

// pkgInstalled reports whether dpkg considers the package fully installed.
// A package in "config-files" state (purged binaries, leftover conf) is not.
func pkgInstalled(name string) bool {
	out, err := runOut("dpkg-query", "-W", "-f=${db:Status-Status}", name)
	return err == nil && strings.TrimSpace(out) == "installed"
}

func haveCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// systemctlIs returns the state word systemctl prints. A non-zero exit is
// normal here ("inactive", "disabled") and the word is still on stdout.
func systemctlIs(verb, unit string) string {
	out, _ := runOut("systemctl", verb, unit)
	return strings.TrimSpace(out)
}

func svcActive(unit string) bool { return systemctlIs("is-active", unit) == "active" }

func svcEnabled(unit string) bool {
	switch systemctlIs("is-enabled", unit) {
	case "enabled", "enabled-runtime", "static", "indirect":
		return true
	}
	return false
}

// svcExists distinguishes "unit is off" from "unit is not a thing on this
// distro" — chrony ships as chrony on Ubuntu and chronyd elsewhere.
func svcExists(unit string) bool {
	return systemctlIs("is-enabled", unit) != ""
}

// shellVar reads one KEY=value out of a shell-sourced config file, stripping
// surrounding quotes. Comments are ignored.
func shellVar(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		k, v, found := strings.Cut(trim, "=")
		if !found || strings.TrimSpace(k) != key {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return ""
}

// aptPeriodicEnabled reports whether unattended-upgrades is actually switched
// on. The package being installed says nothing: the APT::Periodic keys are
// what the systemd timers read.
func aptPeriodicEnabled() bool {
	out, err := runOut("apt-config", "dump", "APT::Periodic::Unattended-Upgrade")
	if err != nil {
		return false
	}
	return strings.Contains(out, `"1"`) || strings.Contains(out, `"true"`)
}

// pendingUpgrades counts what apt would install right now, and how many of
// those come from a security pocket. Returns -1, -1 if apt cannot be queried.
func pendingUpgrades() (total, security int) {
	out, err := runOut("apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "upgrade")
	if err != nil {
		return -1, -1
	}
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "Inst ") {
			continue
		}
		total++
		if strings.Contains(l, "-security") || strings.Contains(l, "Security") {
			security++
		}
	}
	return total, security
}

func rootDiskUsage() (percent int, detail string, err error) {
	out, err := runOut("df", "-hP", "/")
	if err != nil {
		return 0, "", err
	}
	lines := nonEmptyLines(out)
	if len(lines) < 2 {
		return 0, "", fmt.Errorf("unexpected df output")
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 5 {
		return 0, "", fmt.Errorf("unexpected df output")
	}
	percent, err = strconv.Atoi(strings.TrimSuffix(f[4], "%"))
	if err != nil {
		return 0, "", err
	}
	return percent, fmt.Sprintf("%s used of %s (%s), %s free", f[2], f[1], f[4], f[3]), nil
}

func rebootRequiredPkgs() string {
	data, err := os.ReadFile("/var/run/reboot-required.pkgs")
	if err != nil {
		return ""
	}
	return truncateList(uniqueLines(string(data)), 4)
}

// ufwAllowed summarises the ports UFW lets in, so the report answers "what is
// open" without reprinting the whole rule table.
func ufwAllowed(status string) string {
	seen := map[string]bool{}
	var ports []string
	for _, l := range strings.Split(status, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.EqualFold(f[1], "ALLOW") {
			continue
		}
		if !seen[f[0]] {
			seen[f[0]] = true
			ports = append(ports, f[0])
		}
	}
	return truncateList(ports, 12)
}

func fail2banJails() []string {
	out, err := runOut("fail2ban-client", "status")
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, "Jail list:") {
			continue
		}
		_, list, _ := strings.Cut(l, "Jail list:")
		var jails []string
		for _, j := range strings.Split(list, ",") {
			if j = strings.TrimSpace(j); j != "" {
				jails = append(jails, j)
			}
		}
		return jails
	}
	return nil
}

func fail2banBanned(jail string) int {
	out, err := runOut("fail2ban-client", "status", jail)
	if err != nil {
		return 0
	}
	m := regexp.MustCompile(`Currently banned:\s+(\d+)`).FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// publicListeners lists sockets bound to something other than loopback — the
// ports the outside world could reach if the firewall let it through.
func publicListeners() string {
	seen := map[string]bool{}
	var ports []string
	for _, l := range listeners() {
		if l.loopback() {
			continue
		}
		key := fmt.Sprintf("%d/%s", l.Port, l.Proto)
		if !seen[key] {
			seen[key] = true
			ports = append(ports, key)
		}
	}
	return truncateList(ports, 12)
}

// truncateList keeps a status line to one line.
func truncateList(items []string, max int) string {
	if len(items) > max {
		return strings.Join(items[:max], ", ") + fmt.Sprintf(", +%d more", len(items)-max)
	}
	return strings.Join(items, ", ")
}

// relayProvider names the relay behind a Postfix relayhost value, so the
// report says "Postmark" rather than making the reader recognise a hostname.
func relayProvider(relay string) string {
	switch {
	case strings.Contains(relay, "postmarkapp.com"):
		return "Postmark"
	case strings.Contains(relay, "sendgrid"):
		return "SendGrid"
	case strings.Contains(relay, "mailgun"):
		return "Mailgun"
	case strings.Contains(relay, "amazonaws.com"):
		return "Amazon SES"
	case strings.Contains(relay, "gmail") || strings.Contains(relay, "google"):
		return "Google"
	}
	return "custom relay"
}

// mailQueueDepth counts messages waiting to go out. Returns -1 if the queue
// cannot be read.
func mailQueueDepth() int {
	out, err := runOut("postqueue", "-p")
	if err != nil {
		return -1
	}
	if strings.Contains(out, "Mail queue is empty") {
		return 0
	}
	if m := regexp.MustCompile(`in (\d+) Request`).FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

func joinInts(ns []int) string {
	var s []string
	for _, n := range ns {
		s = append(s, strconv.Itoa(n))
	}
	return strings.Join(s, ", ")
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func uniqueLines(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range nonEmptyLines(s) {
		l = strings.TrimSpace(l)
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// lastCut splits on the LAST occurrence of sep — needed for socket addresses,
// where an IPv6 host is full of colons and only the final one is the port.
func lastCut(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
