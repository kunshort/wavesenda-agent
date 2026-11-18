package capability

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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

// How long Docker gets to answer. Generous on purpose: a box with thirty
// containers and a busy daemon is exactly the box somebody asks about, and a
// read that gives up at fifteen seconds reports a failure where there was
// only a queue.
const dockerTimeout = 30 * time.Second

// Whether the socket has already turned this process away.
//
// A one-way latch, and it exists for the cost of finding out: on a machine
// where only sudo works, asking the socket first burns a whole timeout before
// the attempt that was always going to be the one that worked — twice over,
// since the agent says "one moment" before it starts. After the first refusal
// the question goes straight to sudo.
var socketRefusedUs atomic.Bool

// askDocker runs one read-only Docker command, through sudo if it has to.
//
// The agent runs as its own unprivileged user and the socket is root-owned.
// The usual advice — put that user in the `docker` group — would let it start
// a privileged container, which is root on the host by another name. The whole
// point of this agent is that what it may elevate is a handful of named
// commands in a file anyone can read, so each of these is one more of them and
// nothing else about Docker is.
func askDocker(ctx context.Context, docker string, args []string) (string, error) {
	if !socketRefusedUs.Load() {
		out, err := run(ctx, dockerTimeout, docker, args...)
		if err == nil {
			return out, nil
		}
		// Any failure, not only a refusal. A socket this user may not touch
		// does not always say so quickly — it can hang until the deadline
		// instead, which looked like Docker being slow and meant the attempt
		// that works was never made at all.
		socketRefusedUs.Store(true)
	}

	out, err := run(ctx, dockerTimeout, "sudo", append([]string{"-n", docker}, args...)...)
	if err == nil {
		return out, nil
	}

	// A slow answer is still an answer. Docker on a loaded box writes its rows
	// as it finds them, so a deadline reached mid-list leaves real data in
	// hand — and reporting "took too long" while holding a list of containers
	// is the least useful thing this could do with it.
	if rows(out) > 0 {
		return out, errPartial
	}

	switch {
	case dockerIsDown(out):
		// Not an error: "Docker itself is not running" is exactly what
		// somebody asking after their containers needs to hear.
		return "", errDockerDown
	case refusedTheSocket(out):
		// Said as the one step that fixes it. An operator reading "permission
		// denied" about containers they can see running learns nothing about
		// where the permission is missing.
		return "", fmt.Errorf("this agent may not talk to Docker here — " +
			"re-run the installer, which grants it the Docker reads and " +
			"nothing else about Docker in /etc/sudoers.d/wavesenda")
	default:
		// With what was actually said, not only the exit status. A bare "sudo
		// failed: exit status 1" names neither the reason nor the fix, and
		// sudo's own line — a path the rule does not cover, a password being
		// asked for — is both.
		return "", fmt.Errorf("could not ask Docker: %w%s", err, said(out))
	}
}

// errDockerDown is a state rather than a failure, so each caller can turn it
// into the sentence that fits what was asked.
var errDockerDown = errors.New("the Docker daemon is not running")

// errPartial means the output is real but may be short of the full list.
var errPartial = errors.New("Docker was still answering")

// rows counts the lines that parsed as a record rather than as noise.
func rows(out string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, "|") {
			n++
		}
	}
	return n
}

// dockerArgs is the shape every call here takes: a fixed verb and a fixed
// format string, so the exact invocation can be named in a sudoers file
// instead of the rule ending in a wildcard.
//
// Fields are separated by a pipe rather than a tab because sudoers needs
// whitespace escaped and cannot carry a literal tab at all. A pipe is special
// to neither sudoers nor fnmatch, and appears in no container name, status,
// image or measurement.
var (
	listArgs = []string{
		"ps", "--all", "--no-trunc",
		"--format", "{{.Names}}|{{.State}}|{{.Status}}|{{.Image}}",
	}
	statsArgs = []string{
		"stats", "--no-stream",
		"--format", "{{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}",
	}
)

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
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "Docker is not installed on this machine.", nil
	}

	out, err := askDocker(ctx, docker, listArgs)
	if errors.Is(err, errDockerDown) {
		return "Docker is installed but its daemon is not running.", nil
	}
	if errors.Is(err, errPartial) {
		return summariseContainers(out) +
			"\n\n(Docker was still answering when I ran out of time, so there " +
			"may be more.)", nil
	}
	if err != nil {
		return "", err
	}
	return summariseContainers(out), nil
}

// containersStats answers "which one is eating the machine".
//
// The list above cannot: it knows what is running and whether it is healthy,
// and nothing at all about what any of it costs. Asked for the heaviest
// container, an agent with only the list did the one thing worse than
// refusing — it printed every container and then promised statistics it had
// no way to fetch.
//
// `memory.usage` is not this either. It reports the machine's largest
// processes, and on a box where everything is containerised those are a dozen
// anonymous runtimes whose names say nothing about which service they are.
func containersStats(ctx context.Context, _ Args) (string, error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "Docker is not installed on this machine.", nil
	}

	out, err := askDocker(ctx, docker, statsArgs)
	if errors.Is(err, errDockerDown) {
		return "Docker is installed but its daemon is not running, so there is nothing to measure.", nil
	}
	if errors.Is(err, errPartial) {
		return summariseStats(out) +
			"\n\n(Docker was still measuring when I ran out of time, so a " +
			"heavier one may be missing.)", nil
	}
	if err != nil {
		return "", err
	}
	return summariseStats(out), nil
}

// summariseContainers turns `docker ps` output into something worth reading in
// a chat message.
//
// Separate from the call so that the parsing can be tested without Docker: the
// field separator is the one part of this that a sudoers file also has an
// opinion about, and a change to it that nothing catches turns every container
// into one unreadable line.
func summariseContainers(out string) string {
	var running, other []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
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
		return "Docker is running and there are no containers at all."
	}

	text := fmt.Sprintf("%d running:\n%s", len(running), strings.Join(running, "\n"))
	if len(running) == 0 {
		text = "Nothing is running."
	}
	if len(other) > 0 {
		text += fmt.Sprintf("\n\n%d not running:\n%s", len(other), strings.Join(other, "\n"))
	}
	return text
}

// summariseStats puts the heaviest container first.
//
// Sorted here rather than left to the model, because the question is almost
// always a superlative — which one is the worst — and an unordered list of
// thirty measurements is an invitation to answer it wrongly. Only the top of
// the list is sent: nobody asks after the twenty-fifth hungriest container.
func summariseStats(out string) string {
	type row struct {
		name  string
		mem   string
		share float64
		cpu   string
	}

	var rows []row
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) < 4 || parts[0] == "" {
			continue
		}
		share, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(parts[2]), "%"), 64)
		if err != nil {
			// A container that reports no percentage still belongs in the
			// list; it simply sorts last rather than being dropped.
			share = -1
		}
		rows = append(rows, row{parts[0], parts[1], share, parts[3]})
	}

	if len(rows) == 0 {
		return "Docker is running and there is nothing to measure."
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].share > rows[j].share })
	if len(rows) > 15 {
		rows = rows[:15]
	}

	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("%s — %s memory, %s CPU", r.name, r.mem, r.cpu))
	}
	return "By memory, heaviest first:\n" + strings.Join(lines, "\n")
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

// said renders a command's own output for an error message, or nothing.
//
// Trimmed hard: this ends up in a WhatsApp message, and the first line of a
// refusal is the whole of what it is telling us.
func said(out string) string {
	first := strings.TrimSpace(out)
	if first == "" {
		return ""
	}
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if len(first) > 200 {
		first = first[:200]
	}
	return " — " + first
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
