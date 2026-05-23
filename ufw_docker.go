package main

import (
	"fmt"
	"os"
	"os/exec"
)

const ufwDockerURL = "https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker"
const ufwDockerPath = "/usr/local/bin/ufw-docker"

func stepUfwDocker(cfg Config) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("UFW is not installed — run the UFW step first")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker is not installed — run the Docker step first")
	}

	if _, err := os.Stat("/etc/ufw/after.rules"); err == nil {
		if err := backupFile("/etc/ufw/after.rules"); err != nil {
			return fmt.Errorf("backup after.rules: %w", err)
		}
	}

	if err := run("curl", "-fsSL", "-o", ufwDockerPath, ufwDockerURL); err != nil {
		return fmt.Errorf("download ufw-docker: %w", err)
	}
	if err := os.Chmod(ufwDockerPath, 0o755); err != nil {
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
