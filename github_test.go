package main

import "testing"

func TestNormaliseRepoURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "cloudwales/LinuxServerSetup", want: "https://github.com/cloudwales/LinuxServerSetup"},
		{in: "  cloudwales/repo  ", want: "https://github.com/cloudwales/repo"},
		{in: "https://github.com/cloudwales/repo.git", want: "https://github.com/cloudwales/repo.git"},
		{in: "git@github.com:cloudwales/repo.git", want: "https://github.com/cloudwales/repo.git"},
		// http is upgraded: the token must not cross the wire in the clear.
		{in: "http://github.com/cloudwales/repo", want: "https://github.com/cloudwales/repo"},
		// A token pasted into the URL is stripped — git would otherwise write
		// it to .git/config in plain text.
		{in: "https://user:ghp_secret@github.com/cloudwales/repo", want: "https://github.com/cloudwales/repo"},
		{in: "", wantErr: true},
		{in: "justarepo", wantErr: true},
		{in: "too/many/slashes", wantErr: true},
		{in: "/leading", wantErr: true},
	}
	for _, c := range cases {
		got, err := normaliseRepoURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normaliseRepoURL(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normaliseRepoURL(%q) returned error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normaliseRepoURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCredentialsWithoutHost(t *testing.T) {
	const (
		gh  = "https://me:ghp_tok@github.com"
		gl  = "https://me:tok@gitlab.com"
		odd = "not-a-url-someone-else-wrote"
	)
	cases := []struct {
		name        string
		in          string
		wantKeep    []string
		wantRemoved int
	}{
		{"only github", gh + "\n", nil, 1},
		{"other hosts survive", gh + "\n" + gl + "\n", []string{gl}, 1},
		{"nothing to remove", gl + "\n", []string{gl}, 0},
		{"blank lines ignored", "\n" + gh + "\n\n", nil, 1},
		{"empty file", "", nil, 0},
		// Don't discard lines we can't parse — they aren't ours to delete.
		{"unparseable line kept", odd + "\n" + gh, []string{odd}, 1},
		{"duplicate github entries all go", gh + "\n" + gh + "\n", nil, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keep, removed := credentialsWithoutHost(c.in, "github.com")
			if removed != c.wantRemoved {
				t.Errorf("removed = %d, want %d", removed, c.wantRemoved)
			}
			if len(keep) != len(c.wantKeep) {
				t.Fatalf("keep = %q, want %q", keep, c.wantKeep)
			}
			for i := range keep {
				if keep[i] != c.wantKeep[i] {
					t.Errorf("keep[%d] = %q, want %q", i, keep[i], c.wantKeep[i])
				}
			}
		})
	}
}

func TestRepoName(t *testing.T) {
	cases := map[string]string{
		"https://github.com/cloudwales/repo.git": "repo",
		"https://github.com/cloudwales/repo":     "repo",
		"https://github.com/cloudwales/repo/":    "repo",
		"https://github.com/":                    "repo",
	}
	for in, want := range cases {
		if got := repoName(in); got != want {
			t.Errorf("repoName(%q) = %q, want %q", in, got, want)
		}
	}
}
