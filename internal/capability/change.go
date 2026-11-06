package capability

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Changes go through sudo with the exact command named in the sudoers file
// the installer writes. The daemon's own user can do none of this directly,
// so a bug here fails with a permission error rather than with a surprise.

func serviceRestart(ctx context.Context, args Args) (string, error) {
	unit, err := args.Unit()
	if err != nil {
		return "", err
	}

	// Refuse to restart ourselves. An agent that can stop its own service can
	// stop anybody fixing the thing it just broke.
	if strings.HasPrefix(unit, "wavesenda-agent") {
		return "", fmt.Errorf("I will not restart myself")
	}

	before, _ := run(ctx, 5*time.Second, "systemctl", "is-active", unit)

	if _, err := run(ctx, 30*time.Second, "sudo", "-n", "systemctl", "restart", unit); err != nil {
		return "", err
	}

	// Checked rather than assumed. `systemctl restart` exits zero on a unit
	// that starts and immediately dies, which is exactly the case somebody
	// needs to hear about.
	time.Sleep(2 * time.Second)
	after, _ := run(ctx, 5*time.Second, "systemctl", "is-active", unit)
	if after != "active" {
		return "", fmt.Errorf("%s was %s, restarted, and is now %s", unit, orUnknown(before), orUnknown(after))
	}
	return fmt.Sprintf("%s is running (it was %s)", unit, orUnknown(before)), nil
}

func diskReclaim(ctx context.Context, _ Args) (string, error) {
	freedBefore := diskFreeKB()

	var done []string
	if _, err := run(ctx, 60*time.Second, "sudo", "-n", "journalctl", "--vacuum-size=200M"); err == nil {
		done = append(done, "old logs")
	}
	if _, err := run(ctx, 60*time.Second, "sudo", "-n", "apt-get", "clean"); err == nil {
		done = append(done, "package cache")
	}

	if len(done) == 0 {
		return "", fmt.Errorf("nothing could be cleared")
	}

	gained := diskFreeKB() - freedBefore
	answer := "Cleared " + strings.Join(done, " and ")
	if gained > 0 {
		answer += fmt.Sprintf(", freeing about %d MB", gained/1024)
	}
	return answer, nil
}

func certRenew(ctx context.Context, args Args) (string, error) {
	domain, err := args.Domain()
	if err != nil {
		return "", err
	}
	out, err := run(ctx, 180*time.Second,
		"sudo", "-n", "certbot", "renew", "--cert-name", domain, "--non-interactive")
	if err != nil {
		return out, err
	}
	return fmt.Sprintf("Renewed the certificate for %s.", domain), nil
}

func diskFreeKB() int64 {
	out, err := run(context.Background(), 5*time.Second, "df", "-k", "--output=avail", "/")
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0
	}
	var value int64
	fmt.Sscanf(strings.TrimSpace(lines[len(lines)-1]), "%d", &value)
	return value
}
