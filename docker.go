package main

import (
	"fmt"
	"os"
	"strings"
)

// dockerKeyFingerprint is Docker's published release key. Verifying it turns
// the key fetch from "trust whatever TLS handed us" into a real check.
const dockerKeyFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

func stepDocker(cfg Config) error {
	// Older bundled or third-party container packages conflict with docker-ce.
	// Removing containerd/runc stops every running container, so on a server
	// already in use this has to be the operator's call, not ours.
	conflicting := []string{"docker.io", "docker-doc", "docker-compose", "docker-compose-v2", "podman-docker", "containerd", "runc"}
	remove := true
	if cfg.interactive() {
		fmt.Println(warn("Conflicting packages will be removed: " + strings.Join(conflicting, " ")))
		fmt.Println(warn("If containerd or runc are in use, this stops running containers."))
		remove = confirm("Remove them?", false)
	}
	if remove {
		args := append([]string{"remove", "-y"}, conflicting...)
		_ = run("apt-get", args...) // best-effort; fine if none are installed
	}

	if err := aptInstall("ca-certificates", "curl", "gnupg"); err != nil {
		return err
	}

	if err := os.MkdirAll("/etc/apt/keyrings", 0o755); err != nil {
		return err
	}

	// pipefail matters here: without it the exit status is gpg's alone and a
	// failed download can pass unnoticed.
	keyCmd := "set -o pipefail; curl -fsSL https://download.docker.com/linux/ubuntu/gpg | " +
		"gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg"
	if err := run("bash", "-c", keyCmd); err != nil {
		return fmt.Errorf("download Docker GPG key: %w", err)
	}
	if err := verifyGPGFingerprint("/etc/apt/keyrings/docker.gpg", dockerKeyFingerprint); err != nil {
		os.Remove("/etc/apt/keyrings/docker.gpg")
		return err
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
	fmt.Println(warn("Run the ufw-docker step next to close that gap."))

	out, _ := runCapture("docker", "--version")
	if out != "" {
		fmt.Println(ok(out))
	}
	return nil
}

// verifyGPGFingerprint checks a dearmored keyring holds exactly the key we
// expect, so a hijacked mirror or MITM can't seed an apt repo signing key.
func verifyGPGFingerprint(path, want string) error {
	out, err := runOut("gpg", "--no-default-keyring", "--with-colons", "--show-keys", path)
	if err != nil {
		return fmt.Errorf("inspect GPG key: %w", err)
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, ":")
		if len(f) > 9 && f[0] == "fpr" && strings.EqualFold(f[9], want) {
			fmt.Println(ok("GPG key fingerprint verified: " + want))
			return nil
		}
	}
	return fmt.Errorf("GPG key fingerprint mismatch — expected %s, refusing to trust this key", want)
}
