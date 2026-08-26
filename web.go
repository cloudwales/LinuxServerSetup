package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// webPorts is what a TLS-terminating reverse proxy actually needs inbound.
//
// 443/udp is not padding: Caddy turns HTTP/3 on by default and advertises it
// in an Alt-Svc header, so a browser that has cached that hint will try QUIC
// first and stall until it gives up and falls back to TCP. Opening only
// 443/tcp produces a site that works but feels intermittently slow.
var webPorts = []struct {
	Port  int
	Proto string
	Why   string
}{
	{80, "tcp", "HTTP — the ACME HTTP-01 challenge and the redirect to HTTPS"},
	{443, "tcp", "HTTPS"},
	{443, "udp", "HTTP/3 (QUIC), which Caddy advertises by default"},
}

// ConfigureWebPorts opens the ports a web server needs and, crucially, works
// out which of the two firewalls in play is the one blocking them.
//
// A hardened server has two independent things that can drop traffic to :443,
// and the fix for one does nothing for the other:
//
//   - UFW's INPUT chain, for a web server running on the host;
//   - the DOCKER-USER FORWARD chain that ufw-docker installs, for a web server
//     in a container. `ufw allow 443/tcp` does not touch this one, which is
//     why "I opened the port and it still doesn't work" is the usual symptom.
func ConfigureWebPorts(cfg Config) error {
	fmt.Println()
	fmt.Println(head("Web server ports (80/443)"))
	fmt.Println("UFW is default-deny inbound and the hardening flow only opens SSH, so a")
	fmt.Println("freshly hardened server blocks Caddy, nginx, and every ACME challenge with it.")
	fmt.Println()

	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("UFW is not installed — run the UFW step first")
	}

	if cfg.interactive() {
		fmt.Println("Will allow:")
		for _, p := range webPorts {
			fmt.Printf("  %d/%s — %s\n", p.Port, p.Proto, p.Why)
		}
		if !confirm("Open these to the internet?", true) {
			fmt.Println(warn("cancelled"))
			return nil
		}
	}

	if err := task("Allow 80/443 through UFW", openWebPorts); err != nil {
		return err
	}

	if !ufwActive() {
		fmt.Println(warn("UFW is not active — these rules do nothing until it is enabled."))
		fmt.Println(warn("Run the UFW step from the main menu; it allows the SSH ports first."))
	}

	if err := allowDockerWebPorts(); err != nil {
		fmt.Println(errMsg(fmt.Sprintf("container port rules failed: %v", err)))
		fmt.Println(warn("the host firewall rules above were still applied"))
	}

	reportWebReachability()
	return nil
}

func openWebPorts() error {
	for _, p := range webPorts {
		rule := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		if err := run("ufw", "allow", rule, "comment", "server-setup: web"); err != nil {
			return fmt.Errorf("ufw allow %s: %w", rule, err)
		}
	}
	return nil
}

// allowDockerWebPorts punches the container-side hole that `ufw allow` cannot.
// It is a no-op when nothing is containerised, which is the common case.
func allowDockerWebPorts() error {
	if !haveCmd("docker") {
		return nil
	}

	containers, err := webContainers()
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return nil
	}

	fmt.Println()
	fmt.Println(head("Containers publishing 80/443"))

	if !fileExists(ufwDockerPath) {
		for _, c := range containers {
			fmt.Printf("  %s → %s\n", c.Name, c.summary())
		}
		fmt.Println(warn("ufw-docker is not installed, so Docker bypasses UFW entirely —"))
		fmt.Println(warn("these container ports are already reachable, and so is every other"))
		fmt.Println(warn("port any container publishes. Install the ufw-docker step to fix that,"))
		fmt.Println(warn("then re-run this option to allow 80/443 back through deliberately."))
		return nil
	}

	for _, c := range containers {
		for _, p := range c.Ports {
			if p.loopbackOnly() {
				fmt.Println(warn(fmt.Sprintf("%s publishes %d/%s on %s only — it is not reachable from outside this host, "+
					"and no firewall rule will change that. Republish it on 0.0.0.0 if it should be public.",
					c.Name, p.HostPort, p.Proto, p.HostIP)))
				continue
			}
			rule := fmt.Sprintf("%d/%s", p.ContainerPort, p.Proto)
			if err := run(ufwDockerPath, "allow", c.Name, rule); err != nil {
				fmt.Println(errMsg(fmt.Sprintf("ufw-docker allow %s %s: %v", c.Name, rule, err)))
				continue
			}
			fmt.Println(ok(fmt.Sprintf("ufw-docker allow %s %s", c.Name, rule)))
		}
	}
	return nil
}

// reportWebReachability says what is now true, rather than asserting success.
// Everything above is a firewall change; whether the site actually answers
// depends on something being bound to the port in the first place.
func reportWebReachability() {
	fmt.Println()
	fmt.Println(head("Where things stand"))

	ls := listeners()
	for _, p := range webPorts {
		var who []string
		for _, l := range ls {
			if l.Port == p.Port && l.Proto == p.Proto && !l.loopback() {
				who = append(who, l.describe())
			}
		}
		if len(who) == 0 {
			fmt.Println(warn(fmt.Sprintf("nothing is listening on %d/%s", p.Port, p.Proto)))
			continue
		}
		fmt.Println(ok(fmt.Sprintf("%d/%s — %s", p.Port, p.Proto, strings.Join(who, ", "))))
	}

	if s := caddyServiceState(); s != "" {
		fmt.Println(step("caddy.service is " + s))
	}

	fmt.Println()
	fmt.Println(head("If it is still unreachable, in the order worth checking"))
	fmt.Println("  1. Your provider's firewall. DigitalOcean cloud firewalls, AWS security")
	fmt.Println("     groups and Hetzner firewalls sit in front of UFW and deny by default —")
	fmt.Println("     UFW cannot see them and nothing on this box will tell you they are there.")
	fmt.Println("  2. DNS. Caddy's certificate needs the A/AAAA record pointing here already;")
	fmt.Println("     the HTTP-01 challenge is an inbound request to this server on :80.")
	fmt.Println("  3. What Caddy is bound to: " + cBold + "sudo ss -tulnp | grep -E ':(80|443)'" + cReset)
	fmt.Println("  4. Why it gave up: " + cBold + "sudo journalctl -u caddy -n 50 --no-pager" + cReset)
	fmt.Println("  5. From off the box: " + cBold + "curl -sSv http://your-domain/ 2>&1 | head" + cReset)
}

// ── container ports ─────────────────────────────────────────────────────────

type publishedPort struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Proto         string
}

// loopbackOnly reports a publish that binds the host's loopback address. It is
// worth calling out separately: the container looks correctly published, the
// firewall looks correctly open, and the port is still unreachable.
func (p publishedPort) loopbackOnly() bool {
	return p.HostIP == "127.0.0.1" || p.HostIP == "::1" || strings.HasPrefix(p.HostIP, "127.")
}

type webContainer struct {
	Name  string
	Ports []publishedPort
}

func (c webContainer) summary() string {
	var s []string
	for _, p := range c.Ports {
		s = append(s, fmt.Sprintf("%s:%d→%d/%s", p.HostIP, p.HostPort, p.ContainerPort, p.Proto))
	}
	return strings.Join(s, ", ")
}

// webContainers lists running containers publishing host port 80 or 443.
func webContainers() ([]webContainer, error) {
	out, err := runOut("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}

	var found []webContainer
	for _, line := range nonEmptyLines(out) {
		name, ports, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		var web []publishedPort
		seen := map[string]bool{}
		for _, p := range parsePublishedPorts(ports) {
			if p.HostPort != 80 && p.HostPort != 443 {
				continue
			}
			// Docker lists IPv4 and IPv6 publishes separately; one ufw-docker
			// rule covers both, so collapse them.
			key := fmt.Sprintf("%d/%s", p.ContainerPort, p.Proto)
			if seen[key] {
				continue
			}
			seen[key] = true
			web = append(web, p)
		}
		if len(web) > 0 {
			found = append(found, webContainer{Name: name, Ports: web})
		}
	}
	return found, nil
}

// parsePublishedPorts reads the port column of `docker ps`, e.g.
// "0.0.0.0:80->80/tcp, [::]:80->80/tcp, 443/tcp". Entries without "->" are
// merely exposed, not published, and are skipped.
func parsePublishedPorts(s string) []publishedPort {
	var out []publishedPort
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		host, container, ok := strings.Cut(entry, "->")
		if !ok {
			continue
		}

		ip, hostPort, ok := lastCut(strings.TrimSpace(host), ":")
		if !ok {
			continue
		}
		hp, err := strconv.Atoi(hostPort)
		if err != nil {
			continue
		}

		containerPort, proto, ok := strings.Cut(strings.TrimSpace(container), "/")
		if !ok {
			continue
		}
		cp, err := strconv.Atoi(containerPort)
		if err != nil {
			continue
		}

		out = append(out, publishedPort{
			HostIP:        strings.Trim(ip, "[]"),
			HostPort:      hp,
			ContainerPort: cp,
			Proto:         proto,
		})
	}
	return out
}

// ── listening sockets ───────────────────────────────────────────────────────

type socketListener struct {
	Proto   string
	Addr    string
	Port    int
	Process string
}

func (l socketListener) loopback() bool {
	return l.Addr == "127.0.0.1" || l.Addr == "::1" || strings.HasPrefix(l.Addr, "127.")
}

func (l socketListener) describe() string {
	who := l.Process
	if who == "" {
		who = "unknown process"
	}
	return fmt.Sprintf("%s on %s", who, l.Addr)
}

var ssProcess = regexp.MustCompile(`\(\("([^"]+)"`)

// listeners parses `ss` into something the report can reason about. Process
// names need root; without them the rest of the line is still useful.
func listeners() []socketListener {
	out, err := runOut("ss", "-tulnpH")
	if err != nil {
		return nil
	}

	var found []socketListener
	for _, line := range nonEmptyLines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		addr, port, ok := lastCut(f[4], ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			continue
		}

		l := socketListener{Proto: f[0], Addr: strings.Trim(addr, "[]"), Port: n}
		if m := ssProcess.FindStringSubmatch(line); m != nil {
			l.Process = m[1]
		}
		found = append(found, l)
	}
	return found
}

func ufwActive() bool {
	out, _ := runCapture("ufw", "status")
	return strings.Contains(out, "Status: active")
}

// caddyServiceState returns systemd's word for caddy.service, or "" when
// Caddy is not installed as a host service (a container, most likely).
func caddyServiceState() string {
	if !svcExists("caddy") {
		return ""
	}
	return systemctlIs("is-active", "caddy")
}
