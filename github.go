package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const githubHost = "github.com"

type ghUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    int64  `json:"id"`
}

// ConfigureGitHub stores a personal access token in git's credential store so
// clones and pushes stop asking, then optionally clones a repo.
//
// The token lands in ~/.git-credentials in plain text — that is how git's
// "store" helper works, and there is no keyring on a headless server to do
// better. The mitigation is scope: a fine-grained, short-lived token that can
// only reach the repos this server actually needs.
func ConfigureGitHub(cfg Config) error {
	fmt.Println()
	fmt.Println(head("GitHub access"))

	if err := aptInstall("git", "ca-certificates"); err != nil {
		return err
	}

	username, home, err := promptTargetUser()
	if err != nil {
		return err
	}

	// Only offer the replace/remove choice when there is something to act on;
	// on a fresh server this prompt would just be noise.
	if storedGitHubLogin(home) != "" {
		fmt.Println()
		fmt.Println(warn("A github.com token is already stored for " + username +
			" (" + storedGitHubLogin(home) + ")"))
		fmt.Println("  1) Replace it with a new token")
		fmt.Println("  2) Remove it (log out)")
		fmt.Println("  3) Keep it and just clone a repository")
		switch promptInt("Choose: ", 1, 3) {
		case 2:
			return removeGitHubCredentials(username, home)
		case 3:
			return cloneRepo(username, home)
		}
	}

	fmt.Println()
	fmt.Println("  Create a token at: https://github.com/settings/personal-access-tokens")
	fmt.Println("  Fine-grained, limited to the repos this server needs, with:")
	fmt.Println("    • Contents: Read           (clone and pull)")
	fmt.Println("    • Contents: Read and write (only if this server must push)")
	fmt.Println("  Set an expiry date.")
	fmt.Println()
	fmt.Println(warn("The token is saved in plain text at ~/.git-credentials (mode 0600)."))
	fmt.Println(warn("Anyone who can read that file, or become root, has the token."))
	fmt.Println()

	token := readPassword("Personal access token (hidden): ")
	if token == "" {
		return fmt.Errorf("no token entered")
	}

	login := ""
	user, err := verifyGitHubToken(token)
	switch {
	case err == nil:
		login = user.Login
		fmt.Println(ok("token valid — authenticated as " + login))
	case strings.Contains(err.Error(), "could not reach"):
		// Offline or proxied: the token may be perfectly good, so let them go on.
		fmt.Println(warn(err.Error()))
		if !confirm("Save the token without verifying it?", false) {
			return fmt.Errorf("cancelled")
		}
		login = readLine("GitHub username: ")
		if login == "" {
			return fmt.Errorf("username required when the token can't be verified")
		}
	default:
		return err
	}

	if err := saveGitCredentials(username, home, login, token); err != nil {
		return err
	}
	fmt.Println(ok("credentials saved for " + githubHost + " as " + username))

	if err := maybeSetGitIdentity(username, home, user, login); err != nil {
		return err
	}

	if confirm("Clone a repository now?", true) {
		if err := cloneRepo(username, home); err != nil {
			return err
		}
	}
	return nil
}

// promptTargetUser picks the account the credentials belong to. Defaults to the
// first sudo user, since that is who will actually be working on the box.
func promptTargetUser() (string, string, error) {
	def := ""
	if m := sudoGroupMembers(); len(m) > 0 {
		def = m[0]
		fmt.Println("Sudo users on this server: " + strings.Join(m, ", "))
	}

	prompt := "Install credentials for which user: "
	if def != "" {
		prompt = fmt.Sprintf("Install credentials for which user [%s]: ", def)
	}
	username := readLine(prompt)
	if username == "" {
		username = def
	}
	if username == "" {
		return "", "", fmt.Errorf("username required")
	}
	if !userExists(username) {
		return "", "", fmt.Errorf("user %s does not exist", username)
	}
	if username == "root" {
		fmt.Println(warn("storing the token under /root — it will only work for root's own clones"))
	}
	home := userHome(username)
	if home == "" {
		return "", "", fmt.Errorf("could not determine home directory for %s", username)
	}
	return username, home, nil
}

// verifyGitHubToken checks the token before we persist it, and returns who it
// belongs to. Uses net/http rather than shelling out to curl so the token never
// appears in a command line, where any user could read it from ps.
func verifyGitHubToken(token string) (ghUser, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return ghUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "server-setup")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return ghUser{}, fmt.Errorf("could not reach api.github.com: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return ghUser{}, fmt.Errorf("GitHub rejected the token (401) — expired, revoked, or mistyped")
	case http.StatusForbidden:
		return ghUser{}, fmt.Errorf("GitHub refused the token (403) — check its permissions")
	default:
		return ghUser{}, fmt.Errorf("GitHub returned %s", resp.Status)
	}

	var u ghUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return ghUser{}, fmt.Errorf("could not read GitHub's reply: %w", err)
	}
	if u.Login == "" {
		return ghUser{}, fmt.Errorf("GitHub did not return an account for this token")
	}
	return u, nil
}

// saveGitCredentials writes the entry git's "store" helper expects and points
// the user's gitconfig at it.
func saveGitCredentials(username, home, login, token string) error {
	credPath := filepath.Join(home, ".git-credentials")

	// net/url does the percent-encoding, so a token containing reserved
	// characters can't corrupt the entry.
	entry := (&url.URL{
		Scheme: "https",
		User:   url.UserPassword(login, token),
		Host:   githubHost,
	}).String()

	// Replace any existing github.com line; leave other hosts alone.
	data, _ := os.ReadFile(credPath)
	lines, _ := credentialsWithoutHost(string(data), githubHost)
	lines = append(lines, entry)

	if err := os.WriteFile(credPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	// WriteFile only applies the mode when creating, so tighten an existing file.
	if err := os.Chmod(credPath, 0o600); err != nil {
		return err
	}

	gitconfig := filepath.Join(home, ".gitconfig")
	// --replace-all: a gitconfig that already lists helpers would otherwise
	// make plain `git config` fail on the multi-valued key.
	if err := run("git", "config", "--file", gitconfig, "--replace-all", "credential.helper", "store"); err != nil {
		return err
	}

	for _, p := range []string{credPath, gitconfig} {
		if err := run("chown", username+":"+username, p); err != nil {
			return err
		}
	}
	return nil
}

// credentialsWithoutHost splits a .git-credentials body into the entries that
// are not for host, and reports how many were dropped. Lines that don't parse
// are kept: they belong to someone else's setup, not ours to discard.
func credentialsWithoutHost(content, host string) (keep []string, removed int) {
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if u, err := url.Parse(l); err == nil && u.Host == host {
			removed++
			continue
		}
		keep = append(keep, l)
	}
	return keep, removed
}

// storedGitHubLogin returns the username of the stored github.com credential,
// or "" if there isn't one.
func storedGitHubLogin(home string) string {
	data, err := os.ReadFile(filepath.Join(home, ".git-credentials"))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		u, err := url.Parse(strings.TrimSpace(l))
		if err == nil && u.Host == githubHost && u.User != nil {
			return u.User.Username()
		}
	}
	return ""
}

// removeGitHubCredentials deletes the locally stored token. It cannot revoke
// anything — the token stays valid on GitHub until it is revoked there, which
// is the part that actually matters if it leaked.
func removeGitHubCredentials(username, home string) error {
	credPath := filepath.Join(home, ".git-credentials")

	data, err := os.ReadFile(credPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(ok("nothing stored for " + username + " — already logged out"))
			return nil
		}
		return err
	}

	keep, removed := credentialsWithoutHost(string(data), githubHost)
	if removed == 0 {
		fmt.Println(ok("no " + githubHost + " entry stored for " + username))
		return nil
	}

	if len(keep) == 0 {
		// Nothing left to look up, so drop the file and the helper with it.
		if err := os.Remove(credPath); err != nil {
			return err
		}
		gitconfig := filepath.Join(home, ".gitconfig")
		if _, err := os.Stat(gitconfig); err == nil {
			// Exits non-zero when the key is already absent — not a failure.
			_ = run("git", "config", "--file", gitconfig, "--unset-all", "credential.helper")
		}
		fmt.Println(ok("removed " + credPath + " and unset credential.helper"))
	} else {
		if err := os.WriteFile(credPath, []byte(strings.Join(keep, "\n")+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(credPath, 0o600); err != nil {
			return err
		}
		if err := run("chown", username+":"+username, credPath); err != nil {
			return err
		}
		fmt.Printf("%s\n", ok(fmt.Sprintf("removed the %s entry — %d credential(s) for other hosts kept",
			githubHost, len(keep))))
	}

	fmt.Println()
	fmt.Println(warn("This only deleted the local copy. The token still works on GitHub."))
	fmt.Println("  If it may have leaked, revoke it now:")
	fmt.Println("    https://github.com/settings/tokens")
	fmt.Println("  Existing clones keep their remote URL and will prompt for credentials.")
	return nil
}

// maybeSetGitIdentity saves the operator the "please tell me who you are" error
// on their first commit. Defaults to GitHub's noreply address so a private
// email doesn't end up in public history.
func maybeSetGitIdentity(username, home string, u ghUser, login string) error {
	name := u.Name
	if name == "" {
		name = login
	}
	email := u.Email
	if email == "" && u.ID != 0 {
		email = fmt.Sprintf("%d+%s@users.noreply.github.com", u.ID, login)
	}
	if email == "" {
		return nil
	}

	fmt.Println()
	fmt.Printf("  git identity: %s <%s>\n", name, email)
	if !confirm("Set this as the commit identity for "+username+"?", true) {
		return nil
	}

	gitconfig := filepath.Join(home, ".gitconfig")
	if err := run("git", "config", "--file", gitconfig, "user.name", name); err != nil {
		return err
	}
	if err := run("git", "config", "--file", gitconfig, "user.email", email); err != nil {
		return err
	}
	return run("chown", username+":"+username, gitconfig)
}

func cloneRepo(username, home string) error {
	raw := readLine("Repository (owner/repo, or a full URL): ")
	repoURL, err := normaliseRepoURL(raw)
	if err != nil {
		return err
	}

	def := filepath.Join(home, repoName(repoURL))
	dest := readLine(fmt.Sprintf("Clone to [%s]: ", def))
	if dest == "" {
		dest = def
	}
	if !filepath.IsAbs(dest) {
		dest = filepath.Join(home, dest)
	}

	// Refuse a destination that already has something in it, before we take
	// ownership of it below — chowning someone's existing /var/www to the
	// wrong account is a worse outcome than a failed clone.
	if entries, err := os.ReadDir(dest); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already exists and is not empty", dest)
	}

	// Create and hand over the destination first: the parent may be root-owned
	// (/srv, /opt), and cloning as the user would fail on a directory they
	// cannot create.
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	if err := run("chown", username+":"+username, dest); err != nil {
		return err
	}

	// Clone as the user so the files are theirs and git finds their stored
	// credential. git refuses a non-empty destination, which is the check we want.
	if err := run("sudo", "-H", "-u", username, "git", "clone", repoURL, dest); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	fmt.Println(ok("cloned " + repoURL + " → " + dest))
	return nil
}

// normaliseRepoURL accepts owner/repo, an https URL or an SSH URL, and always
// returns https — the stored token only applies to https, so an SSH remote
// would silently ask for a key instead.
func normaliseRepoURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", fmt.Errorf("repository required")

	case strings.HasPrefix(s, "git@"+githubHost+":"):
		return "https://" + githubHost + "/" + strings.TrimPrefix(s, "git@"+githubHost+":"), nil

	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "http://"):
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("could not parse that URL: %w", err)
		}
		u.Scheme = "https"
		// Drop any credentials pasted into the URL — those would be written
		// to .git/config in plain text, where the credential helper's 0600
		// protection doesn't apply.
		u.User = nil
		return u.String(), nil

	default:
		if strings.Count(s, "/") != 1 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
			return "", fmt.Errorf("expected owner/repo or a full URL, got %q", s)
		}
		return "https://" + githubHost + "/" + s, nil
	}
}

func repoName(repoURL string) string {
	name := repoURL
	if u, err := url.Parse(repoURL); err == nil {
		name = u.Path
	}
	name = strings.TrimSuffix(strings.Trim(name, "/"), ".git")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "repo"
	}
	return name
}
