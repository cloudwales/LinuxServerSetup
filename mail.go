package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type MailConfig struct {
	Provider    string
	RelayHost   string
	RelayPort   int
	Username    string
	Password    string
	FromAddress string
	RootAlias   string
}

// mailProvider is a known relay. TokenPrompt is non-empty for providers that
// authenticate with a single API key used as both the SASL username and the
// SASL password — asking for "username and password" there just invites people
// to type their account login, which never works.
type mailProvider struct {
	Name        string
	Host        string
	Port        int
	TokenPrompt string
	Notes       []string
}

// postmark is the default relay. It is the one this tool is opinionated about:
// no DNS to configure before the first message, and system mail from a server
// nobody has warmed up still lands in an inbox.
var postmark = mailProvider{
	Name:        "Postmark",
	Host:        "smtp.postmarkapp.com",
	Port:        2525,
	TokenPrompt: "Postmark server API token (hidden): ",
	Notes: []string{
		"Token: Postmark › your server › API Tokens › Server API token.",
		"Use the SERVER token, not the account token — the account token cannot send mail.",
		"Postmark uses that one token as both the SMTP username and the SMTP password.",
		"The From address must be a confirmed Sender Signature (or on a verified domain),",
		"otherwise Postmark rejects the message with \"Invalid sender signature\".",
	},
}

// ConfigureMail installs Postfix as a satellite/smarthost relay and wires it
// up so system mail (cron, AIDE, fail2ban, etc.) reaches a real inbox.
func ConfigureMail(cfg Config) error {
	mc, proceed := promptMailConfig()
	if !proceed {
		fmt.Println(warn("mail setup cancelled"))
		return nil
	}

	steps := []struct {
		title string
		fn    func() error
	}{
		{"Preseed Postfix configuration", func() error { return preseedPostfix(mc) }},
		{"Install postfix + mailutils", func() error {
			return aptInstall("postfix", "mailutils", "libsasl2-modules", "ca-certificates")
		}},
		{"Write Postfix main.cf settings", func() error { return writePostfixMain(mc) }},
		{"Write SASL credentials", func() error { return writeSaslPasswd(mc) }},
		{"Write sender rewrite map", func() error { return writeSenderCanonical(mc) }},
		{"Set root alias", func() error { return writeAliases(mc) }},
		{"Restart Postfix", func() error { return run("systemctl", "restart", "postfix") }},
	}
	for _, s := range steps {
		if err := task(s.title, s.fn); err != nil {
			return err
		}
	}

	if confirm("Send a test email to "+mc.RootAlias+"?", true) {
		if err := sendTestMail(mc); err != nil {
			fmt.Println(errMsg(fmt.Sprintf("test mail failed: %v", err)))
			fmt.Println(warn("check /var/log/mail.log for details"))
			return nil
		}
		fmt.Println(ok("test mail queued — check the inbox and /var/log/mail.log"))
	}
	return nil
}

func promptMailConfig() (MailConfig, bool) {
	fmt.Println()
	fmt.Println(head("Outgoing mail relay (Postfix smarthost)"))
	fmt.Println("System mail — cron, AIDE, fail2ban, unattended-upgrades — is handed to a")
	fmt.Println("relay that will actually deliver it instead of rotting in /var/mail.")
	fmt.Println()
	fmt.Println("  1) Postmark (default)")
	fmt.Println("  2) Other SMTP relay (Gmail, Mailgun, SES, your own…)")

	var mc MailConfig
	var proceed bool
	if promptIntDefault("Choose [1]: ", 1, 2, 1) == 1 {
		mc, proceed = promptTokenProvider(postmark)
	} else {
		mc, proceed = promptCustomRelay()
	}
	if !proceed {
		return mc, false
	}

	if mc.Username == "" || mc.Password == "" || mc.FromAddress == "" || mc.RootAlias == "" {
		fmt.Println(warn("missing required field"))
		return mc, false
	}

	fmt.Println()
	fmt.Println(head("Confirm:"))
	fmt.Printf("  provider:     %s\n", mc.Provider)
	fmt.Printf("  relay:        [%s]:%d\n", mc.RelayHost, mc.RelayPort)
	fmt.Printf("  username:     %s\n", maskSecret(mc.Username))
	fmt.Printf("  from:         %s\n", mc.FromAddress)
	fmt.Printf("  root alias:   %s\n", mc.RootAlias)
	if !confirm("Proceed?", true) {
		return mc, false
	}
	return mc, true
}

// promptTokenProvider collects credentials for a provider whose single API
// token is both the SASL username and password.
func promptTokenProvider(p mailProvider) (MailConfig, bool) {
	mc := MailConfig{Provider: p.Name, RelayHost: p.Host, RelayPort: p.Port}

	fmt.Println()
	fmt.Println(head(p.Name + " — " + p.Host))
	for _, n := range p.Notes {
		fmt.Println("  " + n)
	}
	fmt.Println()

	token := readPassword(p.TokenPrompt)
	if token == "" {
		fmt.Println(warn("no token given — cancelled"))
		return mc, false
	}
	mc.Username, mc.Password = token, token

	mc.FromAddress = readLine("From address (a verified sender, e.g. server@example.com): ")
	mc.RootAlias = readLine("Send system mail to (real inbox e.g. you@example.com): ")
	return mc, true
}

// promptCustomRelay collects credentials for any other SMTP smarthost.
func promptCustomRelay() (MailConfig, bool) {
	fmt.Println()
	fmt.Println(head("SMTP relay settings"))
	fmt.Println("Examples: smtp.gmail.com / smtp.mailgun.org / email-smtp.eu-west-1.amazonaws.com")

	mc := MailConfig{Provider: "custom SMTP relay", RelayPort: 587}

	mc.RelayHost = readLine("Relay SMTP host: ")
	if mc.RelayHost == "" {
		return mc, false
	}
	if p := readLine("Relay port [587]: "); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			fmt.Println(warn("not a valid port — keeping 587"))
		} else {
			mc.RelayPort = n
		}
	}
	mc.Username = readLine("SASL username: ")
	mc.Password = readPassword("SASL password (hidden): ")
	mc.FromAddress = readLine("From address (e.g. server@example.com): ")
	mc.RootAlias = readLine("Send root mail to (real inbox e.g. you@example.com): ")
	return mc, true
}

// maskSecret shows just enough of a token to tell two of them apart without
// printing the whole thing to a terminal that may be logged or scrolled back.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

func preseedPostfix(mc MailConfig) error {
	hostname, _ := runCapture("hostname", "-f")
	if hostname == "" {
		hostname, _ = runCapture("hostname")
	}
	preseed := fmt.Sprintf(
		"postfix postfix/main_mailer_type select Satellite system\n"+
			"postfix postfix/mailname string %s\n"+
			"postfix postfix/relayhost string [%s]:%d\n",
		hostname, mc.RelayHost, mc.RelayPort,
	)
	c := exec.Command("debconf-set-selections")
	c.Stdin = strings.NewReader(preseed)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func writePostfixMain(mc MailConfig) error {
	settings := []string{
		fmt.Sprintf("relayhost = [%s]:%d", mc.RelayHost, mc.RelayPort),
		"smtp_sasl_auth_enable = yes",
		"smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd",
		"smtp_sasl_security_options = noanonymous",
		"smtp_sasl_tls_security_options = noanonymous",
		"smtp_tls_security_level = encrypt",
		"smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt",
		"smtp_use_tls = yes",
		"inet_interfaces = loopback-only",
		"sender_canonical_classes = envelope_sender, header_sender",
		"sender_canonical_maps = regexp:/etc/postfix/sender_canonical",
		"smtp_header_checks = regexp:/etc/postfix/header_checks",
	}
	for _, s := range settings {
		if err := run("postconf", "-e", s); err != nil {
			return err
		}
	}
	// Rewrite the From: header too — many providers reject mail whose From
	// header doesn't match the SASL user's verified domain.
	hc := fmt.Sprintf("/^From:.*/ REPLACE From: %s\n", mc.FromAddress)
	return os.WriteFile("/etc/postfix/header_checks", []byte(hc), 0o644)
}

func writeSaslPasswd(mc MailConfig) error {
	line := fmt.Sprintf("[%s]:%d %s:%s\n", mc.RelayHost, mc.RelayPort, mc.Username, mc.Password)
	if err := os.WriteFile("/etc/postfix/sasl_passwd", []byte(line), 0o600); err != nil {
		return err
	}
	if err := run("postmap", "/etc/postfix/sasl_passwd"); err != nil {
		return err
	}
	// .db file is created by postmap — lock it down too.
	if err := os.Chmod("/etc/postfix/sasl_passwd.db", 0o600); err != nil {
		return err
	}
	return nil
}

func writeSenderCanonical(mc MailConfig) error {
	body := fmt.Sprintf("/.+/    %s\n", mc.FromAddress)
	return os.WriteFile("/etc/postfix/sender_canonical", []byte(body), 0o644)
}

// writeAliases ensures /etc/aliases has a root: <real-inbox> entry, replacing
// any existing root: line, then runs newaliases.
func writeAliases(mc MailConfig) error {
	const path = "/etc/aliases"
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "root:") || strings.HasPrefix(trim, "#root:") {
			continue
		}
		out = append(out, line)
	}
	// Drop trailing empty entry from the final newline split.
	if len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	out = append(out, fmt.Sprintf("root: %s", mc.RootAlias))
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return run("newaliases")
}

// mailRelayHost returns the smarthost Postfix will relay through, or "" when
// Postfix is absent or delivering everything itself.
func mailRelayHost() string {
	out, err := runOut("postconf", "-h", "relayhost")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// rootAliasTarget returns the address root's mail is forwarded to, or "" if
// /etc/aliases has no root entry.
func rootAliasTarget() string {
	data, err := os.ReadFile("/etc/aliases")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "root:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(trim, "root:"))
	}
	return ""
}

// sendTestMail proves the whole chain works, addressed to root so the
// /etc/aliases entry is exercised too rather than bypassed.
func sendTestMail(mc MailConfig) error {
	return sendTestMailTo("root", mc.FromAddress, "server-setup test mail")
}

// sendTestMailTo queues a message through the local MTA. from may be empty,
// in which case Postfix uses the local default and whatever sender rewriting
// is already configured.
func sendTestMailTo(to, from, subject string) error {
	hostname, _ := runCapture("hostname", "-f")
	var b strings.Builder
	fmt.Fprintf(&b, "To: %s\nSubject: %s\n", to, subject)
	if from != "" {
		fmt.Fprintf(&b, "From: %s\n", from)
	}
	fmt.Fprintf(&b, "\nThis is a test message from server-setup on %s.\n"+
		"If you are reading this, outgoing mail from this server works.\n", hostname)

	c := exec.Command("sendmail", "-t")
	c.Stdin = strings.NewReader(b.String())
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
