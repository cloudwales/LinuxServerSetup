package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func stepCreateUser(cfg Config) error {
	username := readLine("New username: ")
	if username == "" {
		return fmt.Errorf("username required")
	}
	if !validUsername(username) {
		return fmt.Errorf("invalid username — use lowercase letters, digits, '_' or '-' (start with a letter or '_')")
	}

	exists := userExists(username)
	if exists {
		fmt.Println(warn("user " + username + " already exists — will ensure sudo + SSH key only"))
	} else {
		if err := run("useradd", "-m", "-s", "/bin/bash", username); err != nil {
			return fmt.Errorf("useradd: %w", err)
		}

		if confirm("Set a login password? (No = SSH-key-only, password locked)", true) {
			pw1 := readPassword("Password: ")
			pw2 := readPassword("Confirm: ")
			if pw1 == "" {
				return fmt.Errorf("empty password")
			}
			if pw1 != pw2 {
				return fmt.Errorf("passwords do not match")
			}
			if err := setPassword(username, pw1); err != nil {
				return fmt.Errorf("set password: %w", err)
			}
		} else {
			if err := run("passwd", "-l", username); err != nil {
				return fmt.Errorf("lock password: %w", err)
			}
		}
	}

	if err := run("usermod", "-aG", "sudo", username); err != nil {
		return fmt.Errorf("add to sudo group: %w", err)
	}

	if confirm("Allow passwordless sudo for "+username+"?", false) {
		body := username + " ALL=(ALL) NOPASSWD:ALL\n"
		path := "/etc/sudoers.d/90-" + username
		if err := os.WriteFile(path, []byte(body), 0o440); err != nil {
			return err
		}
		// visudo -cf checks this one file; remove it again if it doesn't parse.
		if err := run("visudo", "-cf", path); err != nil {
			os.Remove(path)
			return fmt.Errorf("sudoers validation failed (file removed): %w", err)
		}
	}

	if err := installSSHKeyForUser(username); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(ok("user " + username + " ready"))
	fmt.Println("  Before disabling root SSH, test from a NEW terminal:")
	fmt.Println("    ssh " + username + "@<this host>")
	return nil
}

func installSSHKeyForUser(username string) error {
	fmt.Println()
	fmt.Println(head("SSH public key for " + username))
	fmt.Println("  1) Copy from /root/.ssh/authorized_keys")
	fmt.Println("  2) Paste a public key now")
	fmt.Println("  3) Skip (key-based login won't work yet)")

	var keys []string
	switch promptInt("Choose: ", 1, 3) {
	case 1:
		data, err := os.ReadFile("/root/.ssh/authorized_keys")
		if err != nil {
			return fmt.Errorf("read /root/.ssh/authorized_keys: %w", err)
		}
		// root may have several keys; copy every one of them.
		for _, l := range strings.Split(string(data), "\n") {
			if looksLikeSSHKey(l) {
				keys = append(keys, strings.TrimSpace(l))
			}
		}
		if len(keys) == 0 {
			return fmt.Errorf("/root/.ssh/authorized_keys holds no usable key")
		}
	case 2:
		k := strings.TrimSpace(readLine("Paste public key (single line): "))
		if !looksLikeSSHKey(k) {
			return fmt.Errorf("that doesn't look like an SSH public key (expected ssh-ed25519/ssh-rsa/ecdsa-… prefix)")
		}
		keys = []string{k}
	case 3:
		fmt.Println(warn("skipping SSH key — log in via password until a key is added"))
		return nil
	}

	return installAuthorizedKeys(username, keys)
}

// installAuthorizedKeys appends any keys not already present to the user's
// authorized_keys, creating ~/.ssh with the ownership and modes sshd insists on
// before it will honour a key.
func installAuthorizedKeys(username string, keys []string) error {
	home := userHome(username)
	if home == "" {
		return fmt.Errorf("could not determine home directory for %s", username)
	}
	sshDir := filepath.Join(home, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}

	var missing []string
	for _, k := range keys {
		if !keyPresent(akPath, k) {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		fmt.Println(ok("key already present — leaving authorized_keys untouched"))
	} else {
		f, err := os.OpenFile(akPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(strings.Join(missing, "\n") + "\n"); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	if err := run("chown", "-R", username+":"+username, sshDir); err != nil {
		return err
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(akPath, 0o600); err != nil {
		return err
	}
	fmt.Println(ok("authorized_keys installed at " + akPath))
	return nil
}

// keyPresent compares the base64 body of each existing key against the new one.
// A substring check would false-positive on any key that happens to contain
// another, and miss the same key re-pasted with a different comment.
func keyPresent(path, key string) bool {
	want := sshKeyBlob(key)
	if want == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if sshKeyBlob(l) == want {
			return true
		}
	}
	return false
}

func userExists(name string) bool {
	return exec.Command("id", name).Run() == nil
}

// userHome returns the account's real home from /etc/passwd. Never assume
// /home/<name>: plenty of accounts live in /var/www, /opt or /srv, and a key
// written to the wrong path is silently ignored by sshd.
func userHome(name string) string {
	out, err := runOut("getent", "passwd", name)
	if err != nil {
		return ""
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if len(f) < 6 {
		return ""
	}
	return f[5]
}

// sudoGroupMembers lists non-root members of the sudo group.
func sudoGroupMembers() []string {
	out, err := runOut("getent", "group", "sudo")
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(out), ":")
	if len(parts) < 4 {
		return nil
	}
	var users []string
	for _, m := range strings.Split(parts[3], ",") {
		if m = strings.TrimSpace(m); m != "" && m != "root" {
			users = append(users, m)
		}
	}
	return users
}

// nonRootSudoUserExists gates the main menu: running SSH hardening without a
// sudo user is a guaranteed lockout.
func nonRootSudoUserExists() bool {
	return len(sudoGroupMembers()) > 0
}

func validUsername(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || r == '_') {
				return false
			}
			continue
		}
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

func setPassword(username, password string) error {
	c := exec.Command("chpasswd")
	c.Stdin = strings.NewReader(username + ":" + password + "\n")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func isSSHKeyType(s string) bool {
	for _, p := range []string{"ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// parseSSHKeyLine returns the algorithm and base64 body of a public key line,
// or "","" if it isn't one. Handles lines carrying leading options
// (command="…",no-pty ssh-ed25519 AAAA… user@host).
func parseSSHKeyLine(line string) (keyType, blob string) {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return "", ""
	}
	f := strings.Fields(line)
	for i, tok := range f {
		if isSSHKeyType(tok) && i+1 < len(f) && len(f[i+1]) > 40 {
			return tok, f[i+1]
		}
	}
	return "", ""
}

// sshKeyBlob returns the base64 body — the only part that identifies the key.
func sshKeyBlob(line string) string {
	_, blob := parseSSHKeyLine(line)
	return blob
}

// sshKeyType returns the algorithm name, e.g. sk-ssh-ed25519@openssh.com.
func sshKeyType(line string) string {
	t, _ := parseSSHKeyLine(line)
	return t
}

// isHardwareKey reports whether a key line is FIDO2/U2F-backed. The "sk-"
// prefix means the private half lives on a security key and cannot be copied
// off it.
func isHardwareKey(line string) bool {
	return strings.HasPrefix(sshKeyType(line), "sk-")
}

func looksLikeSSHKey(s string) bool {
	return sshKeyBlob(s) != ""
}
