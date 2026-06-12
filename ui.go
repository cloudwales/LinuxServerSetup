package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
)

var stdin = bufio.NewReader(os.Stdin)

func banner() {
	fmt.Println()
	fmt.Println(cBold + cCyan + "  Server Setup" + cReset)
	fmt.Println(cCyan + "  ────────────" + cReset)
	fmt.Println()
}

func ok(s string) string     { return cGreen + "✓ " + s + cReset }
func warn(s string) string   { return cYellow + "! " + s + cReset }
func errMsg(s string) string { return cRed + "✗ " + s + cReset }
func step(s string) string   { return cBlue + "▸ " + s + cReset }
func head(s string) string   { return cBold + s + cReset }

func readLine(prompt string) string {
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// readPassword reads a line from stdin without echoing it. Falls back to
// echoed input if stty isn't available (with a warning).
func readPassword(prompt string) string {
	fmt.Print(prompt)
	if err := setEcho(false); err != nil {
		fmt.Println(warn("could not disable echo, password will be visible"))
		return readLine("")
	}
	defer func() {
		setEcho(true)
		fmt.Println()
	}()
	line, err := stdin.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func setEcho(on bool) error {
	flag := "-echo"
	if on {
		flag = "echo"
	}
	c := exec.Command("stty", flag)
	c.Stdin = os.Stdin
	return c.Run()
}

// confirm asks a yes/no question. Default is the value returned when the user
// just hits enter.
func confirm(prompt string, def bool) bool {
	suffix := " [y/N]: "
	if def {
		suffix = " [Y/n]: "
	}
	for {
		ans := strings.ToLower(readLine(prompt + suffix))
		if ans == "" {
			return def
		}
		switch ans {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

func promptInt(prompt string, min, max int) int {
	for {
		raw := readLine(prompt)
		n, err := strconv.Atoi(raw)
		if err != nil || n < min || n > max {
			fmt.Println(warn(fmt.Sprintf("Enter a number between %d and %d.", min, max)))
			continue
		}
		return n
	}
}

func promptServerStage() ServerStage {
	fmt.Println(head("Is this a new server or one already in use?"))
	fmt.Println("  1) New server (apply hardened defaults non-interactively)")
	fmt.Println("  2) In-use server (prompt before each disruptive step)")
	switch promptInt("Choose: ", 1, 2) {
	case 1:
		return StageNew
	default:
		return StageInUse
	}
}

func promptDistro() Distro {
	fmt.Println()
	fmt.Println(head("Which distribution?"))
	fmt.Println("  1) Ubuntu")
	fmt.Println("  2) Other (not yet supported)")
	switch promptInt("Choose: ", 1, 2) {
	case 1:
		return DistroUbuntu
	default:
		return DistroOther
	}
}

// MailChoice is the menu index for the mail option. Computed each call so it
// stays in sync with the length of SecureSteps.
func mailChoice() int { return len(SecureSteps) + 2 }

// nvimChoice is the menu index for the Neovim dev-tools option.
func nvimChoice() int { return mailChoice() + 1 }

func promptMainMenu() int {
	fmt.Println()
	fmt.Println(head("Main menu"))
	fmt.Println("   " + cBold + "1) Install ALL (run full secure flow)" + cReset)

	prevCat := ""
	for i, s := range SecureSteps {
		if s.Category != prevCat {
			fmt.Println()
			fmt.Println("   " + cCyan + "── " + s.Category + " ──" + cReset)
			prevCat = s.Category
		}
		fmt.Printf("  %2d) %s\n", i+2, s.Title)
	}

	fmt.Println()
	fmt.Println("   " + cCyan + "── Mail ──" + cReset)
	fmt.Printf("  %2d) Configure Postfix smarthost relay\n", mailChoice())

	fmt.Println()
	fmt.Println("   " + cCyan + "── Developer tools ──" + cReset)
	fmt.Printf("  %2d) Install Neovim + LSP starter (gopls, intelephense, dockerls, bashls, jsonls)\n", nvimChoice())

	fmt.Println()
	fmt.Println("   0) Exit")
	return promptInt("Choose: ", 0, nvimChoice())
}
