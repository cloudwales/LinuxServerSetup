package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// sshdSettings is the set of options we want enforced. Empty value means the
// option will be removed (left to default).
var sshdSettings = map[string]string{
	"PermitRootLogin":        "no",
	"PermitEmptyPasswords":   "no",
	"X11Forwarding":          "no",
	"MaxAuthTries":           "6",
	"LoginGraceTime":         "30",
	"ClientAliveInterval":    "300",
	"ClientAliveCountMax":    "2",
	"AllowAgentForwarding":   "no",
	"AllowTcpForwarding":     "no",
	"Protocol":               "2",
	"UsePAM":                 "yes",
	"ChallengeResponseAuthentication": "no",
}

// hardenSSH rewrites sshd_config to enforce sshdSettings. Only sets
// PasswordAuthentication=no when allowDisablePassword is true (we only do that
// after verifying an authorised key exists, otherwise it's a lockout).
func hardenSSH(allowDisablePassword bool) error {
	if err := backupFile(sshdConfigPath); err != nil {
		return fmt.Errorf("backup sshd_config: %w", err)
	}

	settings := map[string]string{}
	for k, v := range sshdSettings {
		settings[k] = v
	}
	if allowDisablePassword {
		settings["PasswordAuthentication"] = "no"
		settings["PubkeyAuthentication"] = "yes"
	}

	if err := applySshdSettings(sshdConfigPath, settings); err != nil {
		return err
	}

	// Validate before reloading — broken config + reload = locked out.
	if err := run("sshd", "-t"); err != nil {
		return fmt.Errorf("sshd config validation failed (changes left in place, please review %s): %w", sshdConfigPath, err)
	}

	return run("systemctl", "reload", "ssh")
}

func applySshdSettings(path string, settings map[string]string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	type line struct{ raw string }
	var lines []line
	seen := map[string]bool{}

	keyRe := func(k string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)^\s*#?\s*` + regexp.QuoteMeta(k) + `\s+`)
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		l := scanner.Text()
		matched := false
		for k, v := range settings {
			if keyRe(k).MatchString(l) {
				matched = true
				if !seen[k] {
					lines = append(lines, line{raw: k + " " + v})
					seen[k] = true
				}
				break
			}
		}
		if !matched {
			lines = append(lines, line{raw: l})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for k, v := range settings {
		if !seen[k] {
			lines = append(lines, line{raw: k + " " + v})
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "sshd_config.*.tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(tmp)
	for _, l := range lines {
		fmt.Fprintln(w, l.raw)
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func backupFile(path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	dstPath := fmt.Sprintf("%s.bak.%s", path, time.Now().Format("20060102-150405"))
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer dst.Close()
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			break
		}
	}
	fmt.Println(ok("backed up " + path + " → " + dstPath))
	return nil
}

// hasAuthorizedKeys reports whether any local user has an authorized_keys
// file with at least one key in it. Used as a basic sanity check before
// disabling password auth.
func hasAuthorizedKeys() bool {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 6 {
			continue
		}
		home := fields[5]
		ak := filepath.Join(home, ".ssh", "authorized_keys")
		info, err := os.Stat(ak)
		if err != nil || info.Size() == 0 {
			continue
		}
		return true
	}
	return false
}
