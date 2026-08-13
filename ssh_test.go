package main

import "testing"

var testKeys = []string{"PasswordAuthentication", "PermitRootLogin", "AllowTcpForwarding"}

func TestNeutraliseSSHDKeys(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{
			name:    "plain directive is commented out",
			in:      "PasswordAuthentication yes\nPort 22\n",
			want:    "# disabled by server-setup: PasswordAuthentication yes\nPort 22\n",
			changed: true,
		},
		{
			name:    "already commented directive is left alone",
			in:      "#PasswordAuthentication yes\nPort 22\n",
			want:    "#PasswordAuthentication yes\nPort 22\n",
			changed: false,
		},
		{
			name:    "duplicates are all commented out",
			in:      "PasswordAuthentication yes\nPort 22\nPasswordAuthentication yes\n",
			want:    "# disabled by server-setup: PasswordAuthentication yes\nPort 22\n# disabled by server-setup: PasswordAuthentication yes\n",
			changed: true,
		},
		{
			// Match-scoped settings apply to specific connections only and a
			// global drop-in cannot override them, so we must not touch them.
			name:    "directives inside a Match block survive",
			in:      "PermitRootLogin yes\nMatch User git\n    PasswordAuthentication yes\n",
			want:    "# disabled by server-setup: PermitRootLogin yes\nMatch User git\n    PasswordAuthentication yes\n",
			changed: true,
		},
		{
			name:    "equals form and odd casing are caught",
			in:      "passwordauthentication=yes\n  ALLOWTCPFORWARDING yes\n",
			want:    "# disabled by server-setup: passwordauthentication=yes\n# disabled by server-setup:   ALLOWTCPFORWARDING yes\n",
			changed: true,
		},
		{
			name:    "unrelated config is untouched",
			in:      "Port 2222\nX11Forwarding yes\n",
			want:    "Port 2222\nX11Forwarding yes\n",
			changed: false,
		},
		{
			// PasswordAuthenticationFoo is a different word; a prefix match
			// would wrongly comment it out.
			name:    "longer keys are not matched by prefix",
			in:      "PermitRootLoginXyz yes\n",
			want:    "PermitRootLoginXyz yes\n",
			changed: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, changed := neutraliseSSHDKeys(c.in, testKeys)
			if got != c.want {
				t.Errorf("content:\n got %q\nwant %q", got, c.want)
			}
			if changed != c.changed {
				t.Errorf("changed = %v, want %v", changed, c.changed)
			}
		})
	}
}

func TestSSHKeyBlob(t *testing.T) {
	const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleXY"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain key", "ssh-ed25519 " + blob + " me@host", blob},
		{"no comment", "ssh-ed25519 " + blob, blob},
		{"leading options", `command="/bin/true",no-pty ssh-ed25519 ` + blob + " me@host", blob},
		{"commented line", "# ssh-ed25519 " + blob, ""},
		{"blank", "", ""},
		{"prose mentioning a key type", "ssh-rsa key goes here", ""},
		{"truncated blob", "ssh-ed25519 AAAAC3Nza", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sshKeyBlob(c.in); got != c.want {
				t.Errorf("sshKeyBlob(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseSSHKeyLine(t *testing.T) {
	const (
		blob   = "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleXY"
		skBlob = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tExampleExampleExampleXY"
	)
	cases := []struct {
		name     string
		in       string
		wantType string
		hardware bool
	}{
		{"ordinary ed25519", "ssh-ed25519 " + blob + " me@mac", "ssh-ed25519", false},
		{"yubikey ed25519", "sk-ssh-ed25519@openssh.com " + skBlob + " yubikey", "sk-ssh-ed25519@openssh.com", true},
		{"yubikey ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com " + skBlob + " yk", "sk-ecdsa-sha2-nistp256@openssh.com", true},
		{"plain ecdsa is not hardware", "ecdsa-sha2-nistp256 " + blob + " me", "ecdsa-sha2-nistp256", false},
		{"sk key behind options", `no-pty sk-ssh-ed25519@openssh.com ` + skBlob, "sk-ssh-ed25519@openssh.com", true},
		{"comment line", "# sk-ssh-ed25519@openssh.com " + skBlob, "", false},
		{"blank", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sshKeyType(c.in); got != c.wantType {
				t.Errorf("sshKeyType = %q, want %q", got, c.wantType)
			}
			if got := isHardwareKey(c.in); got != c.hardware {
				t.Errorf("isHardwareKey = %v, want %v", got, c.hardware)
			}
		})
	}
}

func TestKeyComment(t *testing.T) {
	const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleXY"
	cases := map[string]string{
		"ssh-ed25519 " + blob + " me@mac":            "me@mac",
		"ssh-ed25519 " + blob + " two word comment":  "two word comment",
		"ssh-ed25519 " + blob:                        "(no comment)",
		"no-pty ssh-ed25519 " + blob + " restricted": "restricted",
	}
	for in, want := range cases {
		if got := keyComment(in); got != want {
			t.Errorf("keyComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidUsername(t *testing.T) {
	good := []string{"deploy", "web_1", "a-b", "_svc"}
	bad := []string{"", "1abc", "-abc", "Deploy", "has space", "u;rm -rf /", string(make([]byte, 33))}
	for _, u := range good {
		if !validUsername(u) {
			t.Errorf("validUsername(%q) = false, want true", u)
		}
	}
	for _, u := range bad {
		if validUsername(u) {
			t.Errorf("validUsername(%q) = true, want false", u)
		}
	}
}
