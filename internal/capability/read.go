package capability

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
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
