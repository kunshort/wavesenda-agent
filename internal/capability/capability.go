// Package capability is the list of things this daemon will do, and the only
// list there is.
//
// It is deliberately a map of names to Go functions. There is no path from a
// job descriptor to a shell: arguments are parsed into typed values, validated
// against this machine's own reality, and passed to exec as separate argv
// entries. A job asking for a capability that is not in this map is refused
// without being parsed at all.
//
// That is what makes the architecture hold. The far side decides what to ask
// for; this side decides what is possible. An attacker who owns the far side
// inherits the first and not the second.
package capability

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Tier string

const (
	TierRead       Tier = "read"
	TierReversible Tier = "reversible"
)

// Runner does one job. It never receives the raw job, only the arguments it
// declared, already checked.
type Runner func(ctx context.Context, args Args) (string, error)

type Capability struct {
	Name string
	Tier Tier
	Run  Runner
}

// Args is the decoded argument map. The helpers on it are the only sanctioned
// way to read a value — each one validates before returning.
type Args map[string]any

var (
	unitPattern   = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)
	domainPattern = regexp.MustCompile(`^[a-z0-9.-]+$`)
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// Unit returns a systemd unit name, or an error.
//
// Pattern first, then length. A name that passes both still goes to exec as a
// single argv entry, so even a pattern mistake could not become a second
// command — the belt exists because the braces are what people forget.
func (a Args) Unit() (string, error) {
	raw, _ := a["unit"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 || !unitPattern.MatchString(raw) {
		return "", fmt.Errorf("that is not a service name")
	}
	if !strings.Contains(raw, ".") {
		raw += ".service"
	}
	return raw, nil
}

func (a Args) Domain() (string, error) {
	raw, _ := a["domain"].(string)
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || len(raw) > 253 || !domainPattern.MatchString(raw) {
		return "", fmt.Errorf("that is not a domain")
	}
	return raw, nil
}

func (a Args) Ref() (string, error) {
	raw, _ := a["ref"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 100 || !refPattern.MatchString(raw) {
		return "", fmt.Errorf("that is not a branch or commit")
	}
	return raw, nil
}

// Lines is bounded on both ends. An unbounded tail is how a daemon is made to
// read a gigabyte off disk by a job that looked harmless.
func (a Args) Lines(fallback, max int) int {
	raw, ok := a["lines"].(float64) // JSON numbers decode as float64
	if !ok {
		return fallback
	}
	n := int(raw)
	if n < 1 {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}

// run executes a command with its arguments kept apart.
//
// Never `sh -c`. The single most important line in this package is the one
// below that passes argv as a slice: a unit name containing a semicolon is a
// unit name that does not exist, not a second command.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("%s took too long", name)
	}
	if err != nil {
		return text, fmt.Errorf("%s failed: %w", name, err)
	}
	return text, nil
}

// Registry is every capability this build can perform.
func Registry() map[string]Capability {
	all := []Capability{
		{"server.facts", TierRead, serverFacts},
		{"service.list", TierRead, serviceList},
		{"service.status", TierRead, serviceStatus},
		{"logs.tail", TierRead, logsTail},
		{"disk.usage", TierRead, diskUsage},
		{"memory.usage", TierRead, memoryUsage},
		{"ports.listening", TierRead, portsListening},
		{"cert.expiry", TierRead, certExpiry},
		{"http.check", TierRead, httpCheck},

		{"service.restart", TierReversible, serviceRestart},
		{"disk.reclaim", TierReversible, diskReclaim},
		{"cert.renew", TierReversible, certRenew},
	}

	out := make(map[string]Capability, len(all))
	for _, c := range all {
		out[c.Name] = c
	}
	return out
}

// Known reports whether a name is in this build at all. Used before anything
// else, so an unknown capability is refused without its arguments being read.
func Known(name string) bool {
	_, ok := Registry()[name]
	return ok
}
