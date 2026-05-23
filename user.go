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
		// visudo -c validates the whole sudoers tree; bail early if we just broke it.
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

	var key string
	switch promptInt("Choose: ", 1, 3) {
	case 1:
		data, err := os.ReadFile("/root/.ssh/authorized_keys")
		if err != nil {
			return fmt.Errorf("read /root/.ssh/authorized_keys: %w", err)
		}
		key = strings.TrimSpace(string(data))
		if key == "" {
			return fmt.Errorf("/root/.ssh/authorized_keys is empty")
		}
	case 2:
		key = strings.TrimSpace(readLine("Paste public key (single line): "))
		if !looksLikeSSHKey(key) {
			return fmt.Errorf("that doesn't look like an SSH public key (expected ssh-ed25519/ssh-rsa/ecdsa-… prefix)")
		}
	case 3:
		fmt.Println(warn("skipping SSH key — log in via password until a key is added"))
		return nil
	}

	home := "/home/" + username
	sshDir := filepath.Join(home, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}

	if existing, err := os.ReadFile(akPath); err == nil && strings.Contains(string(existing), key) {
		fmt.Println(ok("key already present — leaving authorized_keys untouched"))
	} else {
		f, err := os.OpenFile(akPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(key + "\n"); err != nil {
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

func userExists(name string) bool {
	return exec.Command("id", name).Run() == nil
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

func looksLikeSSHKey(s string) bool {
	for _, prefix := range []string{"ssh-ed25519 ", "ssh-rsa ", "ssh-dss ", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
