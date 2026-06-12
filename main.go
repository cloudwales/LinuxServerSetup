package main

import (
	"fmt"
	"os"
	"runtime"
)

// ensureSudoUser refuses to enter the main menu until a non-root sudo user
// exists. SecureSteps[0] is the user-creation step.
func ensureSudoUser(cfg Config) {
	if nonRootSudoUserExists() {
		return
	}
	fmt.Println()
	fmt.Println(warn("No non-root sudo user found on this server."))
	fmt.Println("SSH hardening disables root login — without a sudo user you'll be locked out.")
	fmt.Println()

	for !nonRootSudoUserExists() {
		if !confirm("Create one now?", true) {
			fmt.Println(warn("Continuing without a sudo user."))
			fmt.Println(warn("Do NOT run SSH hardening unless you have another way back in (e.g. DigitalOcean web console)."))
			return
		}
		if err := runStep(cfg, SecureSteps[0]); err != nil {
			fmt.Println(errMsg(fmt.Sprintf("user creation failed: %v", err)))
		}
	}
	fmt.Println()
	fmt.Println(ok("Sudo user is in place — proceeding to main menu"))
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, warn("This tool is intended to run on a Linux server. Detected: "+runtime.GOOS))
		fmt.Fprintln(os.Stderr, "Build with: GOOS=linux GOARCH=amd64 go build -o server-setup")
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, warn("This tool must be run as root (try: sudo ./server-setup)"))
		os.Exit(1)
	}

	banner()

	stage := promptServerStage()
	distro := promptDistro()

	if distro != DistroUbuntu {
		fmt.Println(warn("Only Ubuntu is supported right now."))
		os.Exit(1)
	}

	cfg := Config{Stage: stage, Distro: distro}

	ensureSudoUser(cfg)

	for {
		choice := promptMainMenu()
		switch {
		case choice == 0:
			fmt.Println("Goodbye.")
			return
		case choice == 1:
			if err := SecureServer(cfg); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("Secure server flow failed: %v", err)))
			} else {
				fmt.Println(ok("Secure server flow complete."))
			}
		case choice >= 2 && choice < 2+len(SecureSteps):
			s := SecureSteps[choice-2]
			if err := runStep(cfg, s); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("%s failed: %v", s.Title, err)))
			}
		case choice == mailChoice():
			if err := ConfigureMail(cfg); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("Mail setup failed: %v", err)))
			} else {
				fmt.Println(ok("Mail setup complete."))
			}
		case choice == nvimChoice():
			if err := ConfigureNvim(cfg); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("Nvim setup failed: %v", err)))
			} else {
				fmt.Println(ok("Nvim setup complete."))
			}
		}
	}
}
