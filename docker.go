package main

import (
	"fmt"
	"os"
)

func stepDocker(cfg Config) error {
	// Remove any older bundled or third-party container packages that would
	// conflict with docker-ce from the official repo.
	conflicting := []string{"docker.io", "docker-doc", "docker-compose", "docker-compose-v2", "podman-docker", "containerd", "runc"}
	args := append([]string{"remove", "-y"}, conflicting...)
	_ = run("apt-get", args...) // best-effort; ignore if none installed

	if err := aptInstall("ca-certificates", "curl", "gnupg"); err != nil {
		return err
	}

	if err := os.MkdirAll("/etc/apt/keyrings", 0o755); err != nil {
		return err
	}

	// Fetch and dearmor the Docker GPG key. Pipe via bash to keep the install
	// step matching Docker's own published instructions.
	keyCmd := "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg"
	if err := run("bash", "-c", keyCmd); err != nil {
		return fmt.Errorf("download Docker GPG key: %w", err)
	}
	if err := os.Chmod("/etc/apt/keyrings/docker.gpg", 0o644); err != nil {
		return err
	}

	codename, err := runCapture("bash", "-c", ". /etc/os-release && printf %s \"$VERSION_CODENAME\"")
	if err != nil || codename == "" {
		return fmt.Errorf("could not detect Ubuntu codename")
	}
	arch, err := runCapture("dpkg", "--print-architecture")
	if err != nil {
		return fmt.Errorf("detect arch: %w", err)
	}

	repo := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n",
		arch, codename,
	)
	if err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(repo), 0o644); err != nil {
		return err
	}

	if err := run("apt-get", "update"); err != nil {
		return err
	}
	if err := aptInstall(
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin",
	); err != nil {
		return err
	}

	if err := run("systemctl", "enable", "--now", "docker"); err != nil {
		return err
	}

	if confirm("Add a user to the docker group? (effectively root-equivalent)", false) {
		u := readLine("Username to add to docker group: ")
		if u == "" {
			fmt.Println(warn("no username given — skipping"))
		} else if !userExists(u) {
			fmt.Println(warn("user " + u + " does not exist — skipping"))
		} else {
			if err := run("usermod", "-aG", "docker", u); err != nil {
				return fmt.Errorf("add %s to docker group: %w", u, err)
			}
			fmt.Println(ok(u + " added to docker group — they must log out and back in for it to take effect"))
		}
	}

	fmt.Println()
	fmt.Println(warn("Heads-up: Docker manages its own iptables chains and bypasses UFW by default."))
	fmt.Println(warn("Containers that publish ports will be reachable even if UFW says otherwise."))
	fmt.Println(warn("If you need UFW to gate container ports, look up 'ufw-docker' integration."))

	out, _ := runCapture("docker", "--version")
	if out != "" {
		fmt.Println(ok(out))
	}
	return nil
}
