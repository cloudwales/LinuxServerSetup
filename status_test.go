package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetShellVars(t *testing.T) {
	cases := []struct {
		name string
		in   string
		vars map[string]string
		want string
	}{
		{
			name: "existing assignment is replaced in place",
			in:   "COMMAND=check\nMAILTO=root\nCOPYNEWDB=no\n",
			vars: map[string]string{"MAILTO": "ops@example.com"},
			want: "COMMAND=check\nMAILTO=ops@example.com\nCOPYNEWDB=no\n",
		},
		{
			name: "missing assignment is appended",
			in:   "COMMAND=check\n",
			vars: map[string]string{"MAILTO": "ops@example.com"},
			want: "COMMAND=check\nMAILTO=ops@example.com\n",
		},
		{
			name: "commented defaults are left alone and the real key still lands",
			in:   "#MAILTO=root\nCOMMAND=check\n",
			vars: map[string]string{"MAILTO": "ops@example.com"},
			want: "#MAILTO=root\nCOMMAND=check\nMAILTO=ops@example.com\n",
		},
		{
			name: "quoted values survive intact",
			in:   "MAILSUBJ=\"old subject\"\n",
			vars: map[string]string{"MAILSUBJ": `"AIDE report for $FQDN"`},
			want: "MAILSUBJ=\"AIDE report for $FQDN\"\n",
		},
		{
			name: "multiple keys are applied in one pass",
			in:   "MAILTO=root\nQUIETREPORTS=yes\n",
			vars: map[string]string{"MAILTO": "ops@example.com", "QUIETREPORTS": "no", "CRON_DAILY_RUN": "yes"},
			want: "MAILTO=ops@example.com\nQUIETREPORTS=no\nCRON_DAILY_RUN=yes\n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "aide")
			if err := os.WriteFile(path, []byte(c.in), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := setShellVars(path, c.vars); err != nil {
				t.Fatalf("setShellVars: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

func TestShellVar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aide")
	body := "# MAILTO=commented\nMAILTO=ops@example.com\nMAILSUBJ=\"AIDE report\"\nCOMMAND=check\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := shellVar(path, "MAILTO"); got != "ops@example.com" {
		t.Errorf("MAILTO = %q, want ops@example.com", got)
	}
	if got := shellVar(path, "MAILSUBJ"); got != "AIDE report" {
		t.Errorf("MAILSUBJ = %q, want unquoted value", got)
	}
	if got := shellVar(path, "NOPE"); got != "" {
		t.Errorf("missing key = %q, want empty", got)
	}
	if got := shellVar(filepath.Join(t.TempDir(), "absent"), "MAILTO"); got != "" {
		t.Errorf("missing file = %q, want empty", got)
	}
}

func TestUFWAllowed(t *testing.T) {
	status := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`
	// The v6 duplicate carries a suffix, so it is a distinct "To" value and
	// listing it twice would be noise — but 22/tcp itself must appear once.
	got := ufwAllowed(status)
	if got != "22/tcp, 443/tcp" {
		t.Errorf("ufwAllowed = %q, want %q", got, "22/tcp, 443/tcp")
	}
}

func TestRelayProvider(t *testing.T) {
	cases := map[string]string{
		"[smtp.postmarkapp.com]:587":               "Postmark",
		"[email-smtp.eu-west-1.amazonaws.com]:587": "Amazon SES",
		"[smtp.example.com]:2525":                  "custom relay",
	}
	for relay, want := range cases {
		if got := relayProvider(relay); got != want {
			t.Errorf("relayProvider(%q) = %q, want %q", relay, got, want)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	cases := map[string]string{
		"":                                     "****",
		"abcd":                                 "****",
		"11111111-2222-3333-4444-555555555555": "****5555",
	}
	for in, want := range cases {
		if got := maskSecret(in); got != want {
			t.Errorf("maskSecret(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLastCut(t *testing.T) {
	// IPv6 socket addresses are all colons; only the final one is the port.
	if host, port, ok := lastCut("[::]:22", ":"); !ok || host != "[::]" || port != "22" {
		t.Errorf("lastCut IPv6 = %q %q %v", host, port, ok)
	}
	if host, port, ok := lastCut("0.0.0.0:443", ":"); !ok || host != "0.0.0.0" || port != "443" {
		t.Errorf("lastCut IPv4 = %q %q %v", host, port, ok)
	}
	if _, _, ok := lastCut("nocolon", ":"); ok {
		t.Error("lastCut with no separator should report not-found")
	}
}

func TestParsePublishedPorts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []publishedPort
	}{
		{
			name: "ipv4 and ipv6 publishes are both read",
			in:   "0.0.0.0:80->80/tcp, [::]:80->80/tcp",
			want: []publishedPort{
				{HostIP: "0.0.0.0", HostPort: 80, ContainerPort: 80, Proto: "tcp"},
				{HostIP: "::", HostPort: 80, ContainerPort: 80, Proto: "tcp"},
			},
		},
		{
			name: "exposed-but-unpublished entries are skipped",
			in:   "443/tcp, 0.0.0.0:8080->80/tcp",
			want: []publishedPort{
				{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Proto: "tcp"},
			},
		},
		{
			name: "loopback publish keeps its host address so it can be flagged",
			in:   "127.0.0.1:80->80/tcp",
			want: []publishedPort{
				{HostIP: "127.0.0.1", HostPort: 80, ContainerPort: 80, Proto: "tcp"},
			},
		},
		{
			name: "quic udp publish is read as udp",
			in:   "0.0.0.0:443->443/udp",
			want: []publishedPort{
				{HostIP: "0.0.0.0", HostPort: 443, ContainerPort: 443, Proto: "udp"},
			},
		},
		{
			name: "empty port column yields nothing",
			in:   "",
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePublishedPorts(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("got %d ports %+v, want %d", len(got), got, len(c.want))
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("port %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestPublishedPortLoopbackOnly(t *testing.T) {
	// A loopback publish looks correct everywhere except where it matters.
	if !(publishedPort{HostIP: "127.0.0.1"}).loopbackOnly() {
		t.Error("127.0.0.1 should be loopback-only")
	}
	if !(publishedPort{HostIP: "::1"}).loopbackOnly() {
		t.Error("::1 should be loopback-only")
	}
	if (publishedPort{HostIP: "0.0.0.0"}).loopbackOnly() {
		t.Error("0.0.0.0 is not loopback-only")
	}
}

func TestUFWAllowsPort(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80                         ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
443/tcp (v6)               ALLOW       Anywhere (v6)
`
	cases := []struct {
		port  int
		proto string
		want  bool
	}{
		{22, "tcp", true},
		// Added without a protocol, so it covers both — matching only
		// "80/tcp" would wrongly report the port as blocked.
		{80, "tcp", true},
		{80, "udp", true},
		{443, "tcp", true},
		{443, "udp", false},
		{8080, "tcp", false},
	}
	for _, c := range cases {
		if got := ufwAllowsPort(status, c.port, c.proto); got != c.want {
			t.Errorf("ufwAllowsPort(%d/%s) = %v, want %v", c.port, c.proto, got, c.want)
		}
	}
}
