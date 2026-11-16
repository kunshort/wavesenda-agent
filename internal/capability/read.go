package capability

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Reads are summarised here rather than shipped whole. A log tail is the
// clearest case: sending fifty thousand lines upstream would cost tokens to
// read, bandwidth to move, and would bury the three lines that matter.

func serverFacts(ctx context.Context, _ Args) (string, error) {
	var parts []string

	if release, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(release), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				parts = append(parts, "OS: "+strings.Trim(line[12:], `"`))
			}
		}
	}
	if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
		seconds := strings.SplitN(string(uptime), " ", 2)[0]
		parts = append(parts, "Up: "+seconds+"s")
	}
	if out, err := run(ctx, 5*time.Second, "uname", "-r"); err == nil {
		parts = append(parts, "Kernel: "+out)
	}
	if mem := meminfo(); mem != "" {
		parts = append(parts, mem)
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("could not read anything about this machine")
	}
	return strings.Join(parts, "\n"), nil
}

func serviceList(ctx context.Context, _ Args) (string, error) {
	out, err := run(ctx, 10*time.Second,
		"systemctl", "list-units", "--type=service", "--no-pager", "--no-legend", "--state=running")
	if err != nil {
		return "", err
	}

	var names []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, strings.TrimSuffix(fields[0], ".service"))
		}
		if len(names) >= 40 {
			break
		}
	}
	if len(names) == 0 {
		return "Nothing is running that systemd knows about.", nil
	}
	return fmt.Sprintf("%d services running:\n%s", len(names), strings.Join(names, ", ")), nil
}

// containersList answers the question most often asked of a machine that runs
// everything in Docker, and which `service.list` cannot: systemd sees one unit
// called `docker` and nothing of what is inside it. Asked without this, the
// agent answered with a list of system daemons and then asked the operator to
// run `docker ps` themselves — which is the one thing an agent on the box
// exists to save them doing.
//
// Read-only by construction: `ps` with a format string, no container ids
// accepted, nothing to inject. A machine with no Docker says so rather than
// failing, because "Docker is not installed here" is an answer and an error is
// not.
func containersList(ctx context.Context, _ Args) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "Docker is not installed on this machine.", nil
	}

	args := []string{
		"ps", "--all", "--no-trunc",
		"--format", "{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}",
	}

	out, err := run(ctx, 15*time.Second, "docker", args...)
	if err != nil && refusedTheSocket(out) {
		// The agent runs as its own unprivileged user and the Docker socket is
		// root-owned. The usual advice — put the user in the `docker` group —
		// hands it the ability to start a privileged container, which is root
		// on the host by another name. The whole point of this agent is that
		// what it may elevate is a handful of named commands in a file anyone
		// can read, so `docker ps` becomes one more of them and nothing else
		// about Docker does.
		out, err = run(ctx, 15*time.Second, "sudo", append([]string{"-n", "docker"}, args...)...)
	}
	if err != nil {
		switch {
		case dockerIsDown(out):
			// An answer, not a failure: "Docker itself is not running" is
			// exactly what somebody asking after their containers needs.
			return "Docker is installed but its daemon is not running.", nil
		case refusedTheSocket(out):
			// Said as the one step that fixes it. An operator reading
			// "permission denied" about containers they can see running
			// learns nothing about where the permission is missing.
			return "", fmt.Errorf("this agent may not talk to Docker here — " +
				"re-run the installer to grant it `docker ps`, or add " +
				"`wavesenda ALL=(root) NOPASSWD: /usr/bin/docker ps *` to " +
				"/etc/sudoers.d/wavesenda")
		default:
			return "", fmt.Errorf("could not ask Docker: %w", err)
		}
	}

	var running, other []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		name, state, status := parts[0], parts[1], parts[2]
		// Health is the half of the answer a bare name hides: a container can
		// be up and failing its own healthcheck, which is exactly the state
		// somebody is asking about when a deploy has just gone wrong.
		entry := fmt.Sprintf("%s — %s", name, status)
		if state == "running" {
			running = append(running, entry)
		} else {
			other = append(other, entry)
		}
		if len(running)+len(other) >= 60 {
			break
		}
	}

	if len(running) == 0 && len(other) == 0 {
		return "Docker is running and there are no containers at all.", nil
	}

	text := fmt.Sprintf("%d running:\n%s", len(running), strings.Join(running, "\n"))
	if len(running) == 0 {
		text = "Nothing is running."
	}
	if len(other) > 0 {
		text += fmt.Sprintf("\n\n%d not running:\n%s", len(other), strings.Join(other, "\n"))
	}
	return text, nil
}

// refusedTheSocket reports whether Docker turned us away rather than failing
// at the thing we asked for.
//
// Matched on the text because the exit status does not distinguish it: the
// client exits 1 both for "I cannot reach the socket" and for "there is no
// such container", and only the first is fixed by a line in a sudoers file.
func refusedTheSocket(out string) bool {
	lowered := strings.ToLower(out)
	return strings.Contains(lowered, "permission denied") ||
		strings.Contains(lowered, "docker.sock") ||
		strings.Contains(lowered, "is the docker daemon running")
}

// dockerIsDown reports whether Docker is installed and simply not running.
func dockerIsDown(out string) bool {
	lowered := strings.ToLower(out)
	return strings.Contains(lowered, "is the docker daemon running") ||
		strings.Contains(lowered, "cannot connect to the docker daemon")
}

func serviceStatus(ctx context.Context, args Args) (string, error) {
	unit, err := args.Unit()
	if err != nil {
		return "", err
	}

	state, _ := run(ctx, 5*time.Second, "systemctl", "is-active", unit)
	since, _ := run(ctx, 5*time.Second,
		"systemctl", "show", unit, "--property=ActiveEnterTimestamp", "--value")

	answer := fmt.Sprintf("%s is %s", unit, orUnknown(state))
	if since != "" {
		answer += " since " + since
	}
	if state != "active" {
		// The reason it stopped is the whole question when it is not running.
		if why, err := run(ctx, 5*time.Second, "systemctl", "show", unit, "--property=Result", "--value"); err == nil && why != "" {
			answer += fmt.Sprintf(" (%s)", why)
		}
	}
	return answer, nil
}

func logsTail(ctx context.Context, args Args) (string, error) {
	unit, err := args.Unit()
	if err != nil {
		return "", err
	}
	lines := args.Lines(50, 200)

	out, err := run(ctx, 15*time.Second,
		"journalctl", "-u", unit, "-n", fmt.Sprint(lines), "--no-pager", "--output=short")
	if err != nil {
		return out, err
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Sprintf("%s has logged nothing recently.", unit), nil
	}
	return out, nil
}

func diskUsage(ctx context.Context, _ Args) (string, error) {
	out, err := run(ctx, 10*time.Second, "df", "-h", "--output=target,size,used,pcent", "-x", "tmpfs", "-x", "devtmpfs")
	if err != nil {
		// Busybox and macOS df do not take --output. Worth a plain retry
		// before telling somebody their disk cannot be read.
		out, err = run(ctx, 10*time.Second, "df", "-h")
		if err != nil {
			return "", err
		}
	}
	return out, nil
}

func memoryUsage(ctx context.Context, _ Args) (string, error) {
	if mem := meminfo(); mem != "" {
		return mem, nil
	}
	return run(ctx, 5*time.Second, "free", "-h")
}

func portsListening(ctx context.Context, _ Args) (string, error) {
	out, err := run(ctx, 10*time.Second, "ss", "-ltnH")
	if err != nil {
		return "", err
	}

	var rows []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		address := fields[3]
		// Saying whether it faces the internet is the part a non-technical
		// owner actually needs; the socket table alone means nothing to them.
		reach := "localhost only"
		if !strings.HasPrefix(address, "127.") && !strings.HasPrefix(address, "[::1]") {
			reach = "open to the internet"
		}
		rows = append(rows, fmt.Sprintf("%s — %s", address, reach))
		if len(rows) >= 30 {
			break
		}
	}
	if len(rows) == 0 {
		return "Nothing is listening.", nil
	}
	return strings.Join(rows, "\n"), nil
}

func certExpiry(_ context.Context, _ Args) (string, error) {
	var rows []string

	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		name := filepath.Base(filepath.Dir(path))
		switch {
		case days < 0:
			rows = append(rows, fmt.Sprintf("%s expired %d days ago", name, -days))
		case days < 14:
			rows = append(rows, fmt.Sprintf("%s expires in %d days — renew it", name, days))
		default:
			rows = append(rows, fmt.Sprintf("%s is good for %d more days", name, days))
		}
	}

	if len(rows) == 0 {
		return "No certificates found in the usual place.", nil
	}
	return strings.Join(rows, "\n"), nil
}

// httpCheck fetches a URL and reports what happened.
//
// Only plain http and https, and the redirect chain is not followed — a check
// that silently follows a redirect to somewhere else is a check that can be
// pointed at somewhere else.
func httpCheck(ctx context.Context, args Args) (string, error) {
	raw, _ := args["url"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 300 {
		return "", fmt.Errorf("that is not a URL")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", fmt.Errorf("that is not a URL")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", fmt.Errorf("that is not a URL")
	}
	request.Header.Set("User-Agent", "wavesenda-agent")

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not reach it: %w", err)
	}
	defer response.Body.Close()

	return fmt.Sprintf("%s answered %d in %dms",
		raw, response.StatusCode, time.Since(started).Milliseconds()), nil
}

func meminfo() string {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return ""
	}
	wanted := map[string]string{"MemTotal:": "", "MemAvailable:": "", "SwapTotal:": ""}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if _, ok := wanted[fields[0]]; ok {
				wanted[fields[0]] = fields[1] + " kB"
			}
		}
	}
	if wanted["MemTotal:"] == "" {
		return ""
	}
	return fmt.Sprintf("Memory: %s total, %s available (swap %s)",
		wanted["MemTotal:"], orUnknown(wanted["MemAvailable:"]), orUnknown(wanted["SwapTotal:"]))
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
