package main

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sshdConfigPath    = "/etc/ssh/sshd_config"
	sshdDropInName    = "00-server-setup.conf"
	sshRollbackScript = "/usr/local/sbin/ssh-rollback.sh"
	sshRollbackUnit   = "ssh-rollback"
)

// sshdSettings is the set of options we want enforced.
var sshdSettings = map[string]string{
	"PermitRootLogin":              "no",
	"PermitEmptyPasswords":         "no",
	"X11Forwarding":                "no",
	"MaxAuthTries":                 "6",
	"LoginGraceTime":               "30",
	"ClientAliveInterval":          "300",
	"ClientAliveCountMax":          "2",
	"AllowAgentForwarding":         "no",
	"AllowTcpForwarding":           "no",
	"UsePAM":                       "yes",
	"KbdInteractiveAuthentication": "no",
}

// hardenSSH enforces sshdSettings and proves it worked.
//
// The subtle part is ordering: sshd keeps the FIRST value it sees for an
// option, and Ubuntu 22.04+ puts `Include /etc/ssh/sshd_config.d/*.conf` at the
// TOP of sshd_config. Cloud images drop 50-cloud-init.conf in there with
// `PasswordAuthentication yes`. Appending our settings to the bottom of the
// main file therefore does nothing at all. So we write a drop-in that sorts
// first, comment out conflicting global directives everywhere else, and then
// ask sshd itself (`sshd -T`) what it will actually do.
func hardenSSH(allowDisablePassword bool) error {
	settings := map[string]string{}
	for k, v := range sshdSettings {
		settings[k] = v
	}
	if allowDisablePassword {
		settings["PasswordAuthentication"] = "no"
		settings["PubkeyAuthentication"] = "yes"
	}
	return applySSHDConfig(sshdDropInName, settings)
}

// applySSHDConfig writes settings to one of our drop-ins and proves they took
// effect, arming the rollback timer on the way out. Every sshd change in this
// tool goes through here so none of them can skip the verification.
func applySSHDConfig(dropInName string, settings map[string]string) error {
	keys := sortedKeys(settings)

	includeDir, err := sshdIncludeDir()
	if err != nil {
		return err
	}

	dropIn := ""
	if includeDir != "" {
		dropIn = filepath.Join(includeDir, dropInName)
	}

	// Every file we modify is backed up so the rollback timer can undo it.
	var backups [][2]string

	targets := []string{sshdConfigPath}
	if includeDir != "" {
		others, err := filepath.Glob(filepath.Join(includeDir, "*.conf"))
		if err != nil {
			return err
		}
		for _, p := range others {
			// Skip our own drop-ins: they hold settings we put there
			// deliberately, and commenting them out would undo earlier steps.
			if !isManagedDropIn(p) {
				targets = append(targets, p)
			}
		}
	}
	for _, p := range targets {
		bak, err := neutraliseFile(p, keys)
		if err != nil {
			return fmt.Errorf("neutralise %s: %w", p, err)
		}
		if bak != "" {
			backups = append(backups, [2]string{p, bak})
		}
	}

	body := "# Managed by server-setup — edits here are overwritten.\n"
	for _, k := range keys {
		body += k + " " + settings[k] + "\n"
	}

	if dropIn != "" {
		if err := atomicWrite(dropIn, body, 0o600); err != nil {
			return err
		}
	} else {
		// Pre-Include distro: append to the main file. Conflicting directives
		// above have already been commented out, so ours are the only ones left.
		if err := appendToFile(sshdConfigPath, "\n"+body); err != nil {
			return err
		}
	}

	// Syntax check before reload — a broken config plus a reload is a lockout.
	if err := run("sshd", "-t"); err != nil {
		return fmt.Errorf("sshd config validation failed (changes left in place, review %s): %w", sshdConfigPath, err)
	}
	// Semantic check: did the settings actually win?
	if err := verifySSHD(settings); err != nil {
		return err
	}
	if err := reloadSSH(); err != nil {
		return err
	}

	armSSHRollback(backups, dropIn)
	return nil
}

// isManagedDropIn reports whether a drop-in is one this tool wrote.
func isManagedDropIn(path string) bool {
	return strings.Contains(filepath.Base(path), "server-setup")
}

// removeSSHDDropIn deletes one of our drop-ins and reloads, so a policy that
// locks someone out can be undone without hand-editing config.
func removeSSHDDropIn(dropInName string) error {
	includeDir, err := sshdIncludeDir()
	if err != nil || includeDir == "" {
		return fmt.Errorf("this server has no sshd_config.d — remove the settings from %s by hand", sshdConfigPath)
	}
	path := filepath.Join(includeDir, dropInName)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println(ok("nothing to remove — " + path + " does not exist"))
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := run("sshd", "-t"); err != nil {
		return fmt.Errorf("sshd config invalid after removal: %w", err)
	}
	if err := reloadSSH(); err != nil {
		return err
	}
	fmt.Println(ok("removed " + path))
	return nil
}

// sshdIncludeDir returns the directory targeted by the first Include glob in
// sshd_config, or "" when the distro predates drop-in support.
func sshdIncludeDir() (string, error) {
	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?im)^\s*Include\s+(\S+)`).FindStringSubmatch(string(data))
	if m == nil {
		return "", nil
	}
	dir := filepath.Dir(m[1])
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "", nil
	}
	return dir, nil
}

// neutraliseFile comments out conflicting directives in one config file,
// backing it up first. Returns the backup path, or "" if nothing changed.
func neutraliseFile(path string, keys []string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	out, changed := neutraliseSSHDKeys(string(data), keys)
	if !changed {
		return "", nil
	}
	bak, err := backupFile(path)
	if err != nil {
		return "", err
	}
	mode := fs.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return bak, atomicWrite(path, out, mode)
}

// neutraliseSSHDKeys comments out global-scope occurrences of keys. Directives
// inside a Match block are left alone: they are scoped to specific connections
// and a global drop-in could not override them anyway.
func neutraliseSSHDKeys(content string, keys []string) (string, bool) {
	res := make([]*regexp.Regexp, len(keys))
	for i, k := range keys {
		res[i] = regexp.MustCompile(`(?i)^\s*` + regexp.QuoteMeta(k) + `[\s=]`)
	}
	matchRe := regexp.MustCompile(`(?i)^\s*Match\s`)

	lines := strings.Split(content, "\n")
	inMatch, changed := false, false
	for i, l := range lines {
		if matchRe.MatchString(l) {
			inMatch = true
		}
		if inMatch {
			continue
		}
		for _, re := range res {
			if re.MatchString(l) {
				lines[i] = "# disabled by server-setup: " + l
				changed = true
				break
			}
		}
	}
	return strings.Join(lines, "\n"), changed
}

// verifySSHD asks sshd what it will actually do. This is the only check that
// accounts for Includes, first-value-wins ordering and Match blocks.
func verifySSHD(settings map[string]string) error {
	out, err := runOut("sshd", "-T")
	if err != nil {
		return fmt.Errorf("sshd -T (cannot verify hardening took effect): %w", err)
	}
	effective := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			effective[strings.ToLower(k)] = strings.ToLower(strings.TrimSpace(v))
		}
	}

	var bad []string
	for _, k := range sortedKeys(settings) {
		got, ok := effective[strings.ToLower(k)]
		if !ok {
			fmt.Println(warn("sshd -T does not report " + k + " — cannot verify this one"))
			continue
		}
		if got != strings.ToLower(settings[k]) {
			bad = append(bad, fmt.Sprintf("%s: wanted %q, sshd reports %q", k, settings[k], got))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("hardening did not take effect (something else overrides it):\n    %s",
			strings.Join(bad, "\n    "))
	}
	fmt.Println(ok(fmt.Sprintf("verified with sshd -T — %d settings in effect", len(settings))))
	return nil
}

// sshPorts returns the ports sshd actually listens on. UFW must allow these,
// not a hardcoded 22, or enabling the firewall locks you out.
func sshPorts() []int {
	out, err := runOut("sshd", "-T")
	if err != nil {
		return []int{22}
	}
	var ports []int
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) == 2 && strings.EqualFold(f[0], "port") {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 && n < 65536 {
				ports = append(ports, n)
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

func reloadSSH() error {
	if err := run("systemctl", "reload", "ssh"); err == nil {
		return nil
	}
	return run("systemctl", "reload", "sshd")
}

// armSSHRollback schedules an automatic undo of everything we just changed.
// If the operator can still log in they cancel it; if they can't, the server
// heals itself in ten minutes instead of needing a console session.
func armSSHRollback(backups [][2]string, dropIn string) {
	body := "#!/bin/sh\n# Written by server-setup: undoes the last SSH hardening run.\n"
	if dropIn != "" {
		body += "rm -f " + dropIn + "\n"
	}
	for _, p := range backups {
		body += "cp " + p[1] + " " + p[0] + "\n"
	}
	body += "systemctl reload ssh 2>/dev/null || systemctl reload sshd\n"

	if err := os.WriteFile(sshRollbackScript, []byte(body), 0o700); err != nil {
		fmt.Println(warn(fmt.Sprintf("could not write rollback script: %v", err)))
		return
	}
	// Clear any timer still pending from an earlier run, or systemd-run
	// refuses to reuse the unit name.
	_ = run("systemctl", "stop", sshRollbackUnit+".timer")
	if err := run("systemd-run", "--on-active=10min", "--unit="+sshRollbackUnit,
		"/bin/sh", sshRollbackScript); err != nil {
		fmt.Println(warn(fmt.Sprintf("could not arm auto-rollback: %v", err)))
		fmt.Println(warn("test your SSH login NOW, before closing this session"))
		return
	}

	fmt.Println()
	fmt.Println(warn("Auto-rollback armed: SSH config reverts in 10 minutes."))
	fmt.Println("  1. Open a NEW terminal and confirm you can log in.")
	fmt.Println("  2. Then keep these changes with:")
	fmt.Println("       " + cBold + "systemctl stop " + sshRollbackUnit + ".timer" + cReset)
	fmt.Println("  Do nothing and the old config comes back automatically.")
}

func atomicWrite(path, content string, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

// backupFile copies path alongside itself with a timestamp and returns the
// backup path.
func backupFile(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	base := fmt.Sprintf("%s.bak.%s", path, time.Now().Format("20060102-150405"))
	dstPath := base
	for i := 1; ; i++ {
		dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			dstPath = fmt.Sprintf("%s-%d", base, i)
			continue
		}
		if err != nil {
			return "", err
		}
		_, cerr := io.Copy(dst, src)
		if err := dst.Close(); err != nil && cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return "", cerr
		}
		break
	}
	fmt.Println(ok("backed up " + path + " → " + dstPath))
	return dstPath, nil
}

// authorizedKeyUser returns a non-root sudo user that has a usable
// authorized_keys file. Checking "any user on the box" is not good enough:
// root almost always has a key, and root login is exactly what we are about
// to disable — so a root key tells us nothing about whether anyone can still
// get in once password auth goes away.
func authorizedKeyUser() (string, bool) {
	for _, u := range sudoGroupMembers() {
		home := userHome(u)
		if home == "" {
			continue
		}
		if hasRealKey(filepath.Join(home, ".ssh", "authorized_keys")) {
			return u, true
		}
	}
	return "", false
}

// hasRealKey reports whether the file contains at least one actual key line.
// A non-zero file size is not enough — comments and blank lines are common.
func hasRealKey(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if looksLikeSSHKey(s.Text()) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
