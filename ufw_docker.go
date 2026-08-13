package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// ufw-docker is third-party code that runs as root, so it is pinned to an
// immutable commit and checked against a known hash. A branch URL would hand
// every server this tool touches to whoever next compromises that repo.
//
// Pinned: tag 251123 (commit 78366b6). To bump, download the new file, run
// `sha256sum ufw-docker`, and update both constants together.
const (
	ufwDockerCommit = "78366b6afe6e566cd53f7e55341889c2e3c863e7"
	ufwDockerSHA256 = "c3e5f0bf6061a3a2e7d7ac06abc80665707d2f4c91e90d76f22e4168863fb472"
	ufwDockerURL    = "https://raw.githubusercontent.com/chaifeng/ufw-docker/" + ufwDockerCommit + "/ufw-docker"
	ufwDockerPath   = "/usr/local/bin/ufw-docker"
)

func stepUfwDocker(cfg Config) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("UFW is not installed — run the UFW step first")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker is not installed — run the Docker step first")
	}

	if _, err := os.Stat("/etc/ufw/after.rules"); err == nil {
		if _, err := backupFile("/etc/ufw/after.rules"); err != nil {
			return fmt.Errorf("backup after.rules: %w", err)
		}
	}

	// Download to a temp path and verify before anything becomes executable.
	tmp, err := os.CreateTemp(filepath.Dir(ufwDockerPath), "ufw-docker.*.tmp")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	if err := run("curl", "-fsSL", "-o", tmp.Name(), ufwDockerURL); err != nil {
		return fmt.Errorf("download ufw-docker: %w", err)
	}
	sum, err := fileSHA256(tmp.Name())
	if err != nil {
		return err
	}
	if sum != ufwDockerSHA256 {
		return fmt.Errorf("ufw-docker checksum mismatch — refusing to run it as root\n    expected %s\n    got      %s",
			ufwDockerSHA256, sum)
	}
	fmt.Println(ok("ufw-docker checksum verified"))

	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), ufwDockerPath); err != nil {
		return err
	}

	if err := run(ufwDockerPath, "install"); err != nil {
		return fmt.Errorf("ufw-docker install: %w", err)
	}

	if err := run("systemctl", "restart", "ufw"); err != nil {
		return fmt.Errorf("restart ufw: %w", err)
	}

	fmt.Println()
	fmt.Println(ok("ufw-docker installed — published container ports are now blocked by default"))
	fmt.Println()
	fmt.Println("Allow a published container port with one of:")
	fmt.Println("  ufw-docker allow <container-name> <port>/<proto>")
	fmt.Println("    e.g. ufw-docker allow nginx 80/tcp")
	fmt.Println("  ufw route allow proto tcp from any to any port <port>")
	fmt.Println()
	fmt.Println("List current ufw-docker rules:")
	fmt.Println("  ufw-docker status")
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
