package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// yubikeyDropIn sorts after 00-server-setup.conf and before any cloud-init
// drop-in, so its policy wins without clobbering the base hardening.
const yubikeyDropIn = "10-server-setup-yubikey.conf"

// skAlgorithms are the FIDO2-backed key types OpenSSH understands.
const skAlgorithms = "sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"

// ConfigureYubiKey handles the half of YubiKey SSH setup that belongs on the
// server. The key itself is generated on the machine you sit at — the private
// half never leaves the YubiKey, so there is nothing to create here. What the
// server does is accept the public key and, optionally, refuse anything weaker.
func ConfigureYubiKey(cfg Config) error {
	fmt.Println()
	fmt.Println(head("YubiKey / FIDO2 SSH keys"))
	fmt.Println()
	fmt.Println("  " + cBold + "On your laptop:" + cReset + " generate the key (it stays on the YubiKey).")
	fmt.Println("  " + cBold + "On this server:" + cReset + " store the public key, and optionally require it.")
	fmt.Println()

	if maj, min, ok := opensshVersion(); ok && (maj < 8 || (maj == 8 && min < 2)) {
		return fmt.Errorf("this server runs OpenSSH %d.%d — FIDO2 keys need 8.2 or newer", maj, min)
	}

	printClientInstructions()

	if confirm("Add a YubiKey public key for a user now?", true) {
		if err := addHardwareKey(); err != nil {
			return err
		}
	}

	fmt.Println()
	if confirm("Review/change the hardware-key policy for SSH?", false) {
		return hardwareKeyPolicy()
	}
	return nil
}

func printClientInstructions() {
	fmt.Println(head("1. On your laptop (not here)"))
	fmt.Println()
	fmt.Println("  Set a FIDO2 PIN once, if you haven't:")
	fmt.Println("    " + cBold + "ykman fido access change-pin" + cReset)
	fmt.Println()
	fmt.Println("  Generate the key — touch the YubiKey when it blinks:")
	fmt.Println("    " + cBold + "ssh-keygen -t ed25519-sk -O resident -O verify-required -C yubikey" + cReset)
	fmt.Println()
	fmt.Println("    -O resident         stores a handle on the key itself, so you can recover it")
	fmt.Println("                        on a new laptop with `ssh-keygen -K`")
	fmt.Println("    -O verify-required  asks for the PIN as well as a touch")
	fmt.Println()
	fmt.Println("  Then print the public half and paste it here:")
	fmt.Println("    " + cBold + "cat ~/.ssh/id_ed25519_sk.pub" + cReset)
	fmt.Println()
	fmt.Println(warn("If ssh-keygen says \"unknown key type\", your ssh is too old or lacks"))
	fmt.Println(warn("libfido2. On macOS: brew install openssh, then use that one."))
	fmt.Println(warn("Pre-FIDO2 YubiKeys (NEO, 4) must use -t ecdsa-sk and support neither"))
	fmt.Println(warn("-O resident nor -O verify-required."))
	fmt.Println()
}

func addHardwareKey() error {
	fmt.Println()
	fmt.Println(head("2. On this server"))

	def := ""
	if m := sudoGroupMembers(); len(m) > 0 {
		def = m[0]
		fmt.Println("Sudo users: " + strings.Join(m, ", "))
	}
	prompt := "Install the key for which user: "
	if def != "" {
		prompt = fmt.Sprintf("Install the key for which user [%s]: ", def)
	}
	username := readLine(prompt)
	if username == "" {
		username = def
	}
	if username == "" {
		return fmt.Errorf("username required")
	}
	if !userExists(username) {
		return fmt.Errorf("user %s does not exist", username)
	}

	key := strings.TrimSpace(readLine("Paste the sk public key (one line): "))
	if !looksLikeSSHKey(key) {
		return fmt.Errorf("that doesn't look like an SSH public key")
	}
	if !isHardwareKey(key) {
		fmt.Println(warn("That is a " + sshKeyType(key) + " key, not a hardware-backed one."))
		fmt.Println(warn("FIDO2 keys start with sk-ssh-ed25519@ or sk-ecdsa-sha2-."))
		if !confirm("Install it anyway?", false) {
			return fmt.Errorf("cancelled")
		}
	}

	if err := installAuthorizedKeys(username, []string{key}); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(warn("Test it from a NEW terminal before going further:"))
	fmt.Println("    ssh " + username + "@<this host>     (it should ask for a touch)")
	return nil
}

// hardwareKeyPolicy optionally restricts SSH to FIDO2-backed keys. This is the
// dangerous one: it invalidates every ordinary key on the server at once, so it
// audits what would break before touching anything.
func hardwareKeyPolicy() error {
	if policyInstalled() {
		fmt.Println()
		fmt.Println(warn("A hardware-key policy is already active."))
		fmt.Println("  1) Replace it")
		fmt.Println("  2) Remove it (go back to accepting any key type)")
		fmt.Println("  3) Leave it alone")
		switch promptInt("Choose: ", 1, 3) {
		case 2:
			return removeSSHDDropIn(yubikeyDropIn)
		case 3:
			return nil
		}
	}

	hw, soft, err := auditSudoKeys()
	if err != nil {
		return fmt.Errorf("could not audit existing keys, refusing to change policy blind: %w", err)
	}
	fmt.Println()
	fmt.Println(head("What this policy would do"))

	if len(hw) == 0 {
		fmt.Println(errMsg("No sudo user has a hardware-backed key installed."))
		fmt.Println("Enabling this now would lock everyone out. Add a key first.")
		return fmt.Errorf("no hardware key present — refusing to enforce")
	}

	fmt.Println(ok(fmt.Sprintf("%d hardware key(s) would keep working:", len(hw))))
	for _, k := range hw {
		fmt.Println("    ✓ " + k)
	}
	if len(soft) > 0 {
		fmt.Println()
		fmt.Println(warn(fmt.Sprintf("%d key(s) would STOP working immediately:", len(soft))))
		for _, k := range soft {
			fmt.Println("    ✗ " + k)
		}
		fmt.Println()
		fmt.Println(warn("That includes any deploy keys or CI access using those keys."))
	}

	fmt.Println()
	if !confirm("Restrict SSH to hardware-backed keys only?", false) {
		fmt.Println(warn("left unchanged"))
		return nil
	}

	settings := map[string]string{"PubkeyAcceptedAlgorithms": skAlgorithms}

	fmt.Println()
	fmt.Println("PIN enforcement requires every key to have been generated with")
	fmt.Println("-O verify-required. A touch-only key will stop working.")
	if confirm("Also require a PIN (not just a touch)?", false) {
		settings["PubkeyAuthOptions"] = "verify-required"
	}

	if err := applySSHDConfig(yubikeyDropIn, settings); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(ok("hardware-key policy active"))
	fmt.Println(warn("Password auth must also be off for this to mean anything —"))
	fmt.Println(warn("check with: sshd -T | grep passwordauthentication"))
	return nil
}

func policyInstalled() bool {
	dir, err := sshdIncludeDir()
	if err != nil || dir == "" {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, yubikeyDropIn))
	return err == nil
}

// auditSudoKeys splits every sudo user's authorized keys into the ones that
// would survive a hardware-only policy and the ones that would not.
//
// A read error is fatal rather than skipped: this audit is the only thing
// standing between the operator and a policy that can lock everyone out, and a
// half-read file would quietly understate what breaks.
func auditSudoKeys() (hardware, software []string, err error) {
	for _, u := range sudoGroupMembers() {
		home := userHome(u)
		if home == "" {
			return nil, nil, fmt.Errorf("cannot resolve home directory for sudo user %s", u)
		}
		path := filepath.Join(home, ".ssh", "authorized_keys")
		f, oerr := os.Open(path)
		if oerr != nil {
			if os.IsNotExist(oerr) {
				continue // no keys for this user is a fact, not a failure
			}
			return nil, nil, fmt.Errorf("read %s: %w", path, oerr)
		}

		s := bufio.NewScanner(f)
		// Options-heavy key lines can be long; the 64KB default would split
		// one and turn a single key into two unparseable halves.
		s.Buffer(make([]byte, 1024*1024), 1024*1024)
		for s.Scan() {
			line := s.Text()
			t := sshKeyType(line)
			if t == "" {
				continue
			}
			desc := fmt.Sprintf("%s: %s %s", u, t, keyComment(line))
			if isHardwareKey(line) {
				hardware = append(hardware, desc)
			} else {
				software = append(software, desc)
			}
		}
		serr := s.Err()
		f.Close()
		if serr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, serr)
		}
	}
	return hardware, software, nil
}

// keyComment returns the trailing comment on a key line, which is usually the
// only thing that tells two keys apart at a glance.
func keyComment(line string) string {
	f := strings.Fields(line)
	for i, tok := range f {
		if isSSHKeyType(tok) && i+2 < len(f) {
			return strings.Join(f[i+2:], " ")
		}
	}
	return "(no comment)"
}

// opensshVersion is parsed from `ssh -V`, which writes to stderr — hence
// runCapture rather than runOut.
func opensshVersion() (major, minor int, ok bool) {
	out, err := runCapture("ssh", "-V")
	if err != nil && out == "" {
		return 0, 0, false
	}
	m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}
