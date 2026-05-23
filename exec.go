package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// run streams a command's output to the terminal. It inherits stdin so apt
// prompts (where unavoidable) work; we set DEBIAN_FRONTEND=noninteractive on
// apt invocations to keep things flowing.
func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return c.Run()
}

// runCapture runs a command and returns its combined output without streaming.
// Used for short status checks where we want the result in-memory.
func runCapture(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// aptInstall installs packages with sensible flags.
func aptInstall(pkgs ...string) error {
	args := append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)
	return run("apt-get", args...)
}

// task wraps a step with a heading line and a tick/cross.
func task(title string, fn func() error) error {
	fmt.Println()
	fmt.Println(step(title))
	if err := fn(); err != nil {
		fmt.Println(errMsg(fmt.Sprintf("%s failed: %v", title, err)))
		return err
	}
	fmt.Println(ok(title + " — done"))
	return nil
}

