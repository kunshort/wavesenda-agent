// Command wavesenda-agent runs on a customer's own server.
//
// It holds one secret, dials out, and does only what is compiled into it. The
// list of permitted actions lives here rather than on our side, which is the
// property the whole product rests on: a breach of WaveSenda lets an attacker
// ask this machine for things, and this machine still answers only within the
// list its owner installed.
//
//	wavesenda-agent            # run (systemd does this)
//	wavesenda-agent --check    # prove it can reach us, then exit
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kunshort/wavesenda-agent/internal/capability"
	"github.com/kunshort/wavesenda-agent/internal/client"
	"github.com/kunshort/wavesenda-agent/internal/policy"
	"github.com/kunshort/wavesenda-agent/internal/redact"
)

// Version is stamped at build time: -ldflags "-X main.Version=1.2.3".
var Version = "dev"

const (
	configPath = "/etc/wavesenda/agent.json"
	policyPath = "/etc/wavesenda/policy.json"

	// Output beyond this is truncated before it leaves the machine. Generous
	// for a log tail, small enough that nothing here can fill a context window.
	maxOutput = 8000

	// A job that has not finished by now is abandoned and reported as such.
	// Better a stated failure than a daemon stuck on one job for ever.
	jobTimeout = 5 * time.Minute
)

type config struct {
	API   string `json:"api"`
	Token string `json:"token"`
	Name  string `json:"name"`
}

func main() {
	check := flag.Bool("check", false, "verify the connection and exit")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("cannot start: %v", err)
	}

	local, err := policy.Load(policyPath)
	if err != nil {
		log.Fatalf("cannot read %s: %v", policyPath, err)
	}
	if len(local.Allow) > 0 || local.ReadOnly {
		log.Printf("local policy in force: read_only=%v allow=%d", local.ReadOnly, len(local.Allow))
	}

	api := client.New(cfg.API, cfg.Token)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := api.Register(ctx, Version, discover(ctx)); err != nil {
		if *check {
			fmt.Fprintf(os.Stderr, "could not reach WaveSenda: %v\n", err)
			os.Exit(1)
		}
		log.Printf("could not register yet: %v", err)
	} else if *check {
		fmt.Println("Connected. This server is ready.")
		return
	}

	log.Printf("wavesenda-agent %s started", Version)
	loop(ctx, api, local)
}

func loadConfig() (config, error) {
	var cfg config

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, fmt.Errorf("no configuration at %s", configPath)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("%s is not valid JSON", configPath)
	}
	if cfg.Token == "" || cfg.API == "" {
		return cfg, fmt.Errorf("%s is missing the api address or the token", configPath)
	}
	return cfg, nil
}

// loop polls for work and reports in. Both on the same goroutine: a machine
// that is busy running a job has nothing useful to say in a heartbeat anyway,
// and one loop is one thing to reason about.
func loop(ctx context.Context, api *client.Client, local policy.Policy) {
	grants := map[string]bool{}
	lastBeat := time.Time{}

	for {
		select {
		case <-ctx.Done():
			log.Print("stopping")
			return
		default:
		}

		if time.Since(lastBeat) > 60*time.Second {
			if fresh, err := api.Heartbeat(ctx, watch(ctx)); err == nil {
				grants = asSet(fresh)
			} else if isGone(err) {
				log.Printf("%v — stopping", err)
				return
			}
			lastBeat = time.Now()
		}

		jobs, err := api.Jobs(ctx)
		if err != nil {
			if isGone(err) {
				log.Printf("%v — stopping", err)
				return
			}
			sleep(ctx, 10*time.Second)
			continue
		}

		if len(jobs) == 0 {
			sleep(ctx, 5*time.Second)
			continue
		}

		for _, job := range jobs {
			perform(ctx, api, job, grants, local)
		}
	}
}

// perform runs one job, or refuses it.
//
// The order of the three refusals matters. Known-to-this-build comes first, so
// an unrecognised capability is rejected before its arguments are even looked
// at. Local policy comes next, because it is the one rule the network cannot
// change. The grant list comes last, because it is the only one that arrives
// over the wire.
func perform(ctx context.Context, api *client.Client, job client.Job, grants map[string]bool, local policy.Policy) {
	started := time.Now()

	report := func(ok bool, output string) {
		cleaned := redact.Truncate(redact.Clean(output), maxOutput)
		if err := api.Result(ctx, job.ID, ok, cleaned, time.Since(started).Milliseconds()); err != nil {
			log.Printf("could not report job %s: %v", job.ID, err)
		}
	}

	spec, refusal := decide(job.Capability, grants, local)
	if refusal != "" {
		log.Printf("refused %s: %s", job.Capability, refusal)
		report(false, refusal)
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()

	output, err := spec.Run(jobCtx, capability.Args(job.Arguments))
	if err != nil {
		log.Printf("%s failed: %v", spec.Name, err)
		report(false, err.Error())
		return
	}
	log.Printf("%s ok in %dms", spec.Name, time.Since(started).Milliseconds())
	report(true, output)
}

// decide answers whether a capability may run here, and why not.
//
// The order is the point, and it runs outermost-first. Known-to-this-build
// comes first, so an unrecognised name is rejected before its arguments are
// read. Local policy is second, because it is the one rule that arrives from
// the machine's own disk rather than over the network. The granted list is
// last, because it is the only one an attacker who owned our side could
// influence — and by then the other two have already had their say.
func decide(name string, grants map[string]bool, local policy.Policy) (capability.Capability, string) {
	spec, known := capability.Registry()[name]
	if !known {
		return spec, "This server's agent does not know how to do that. It may need updating."
	}
	if !local.Permits(spec.Name, spec.Tier != capability.TierRead) {
		return spec, "This server's own policy does not allow that."
	}
	if len(grants) > 0 && !grants[spec.Name] {
		return spec, "This server has not been set up to allow that."
	}
	return spec, ""
}

// watch evaluates the thresholds locally.
//
// Deliberately here and not upstream. A server that decides for itself whether
// its disk is too full costs nothing when everything is fine, where asking a
// language model the same question every minute would cost a great deal.
func watch(ctx context.Context) []client.Alert {
	var alerts []client.Alert

	if out, err := capability.Registry()["disk.usage"].Run(ctx, capability.Args{}); err == nil {
		for _, line := range strings.Split(out, "\n") {
			for _, field := range strings.Fields(line) {
				if !strings.HasSuffix(field, "%") {
					continue
				}
				var percent int
				if _, scanErr := fmt.Sscanf(field, "%d%%", &percent); scanErr == nil && percent >= 90 {
					alerts = append(alerts, client.Alert{
						Kind:      "disk_critical",
						Summary:   fmt.Sprintf("the disk is %d%% full", percent),
						Suggested: "clear old logs and package caches",
					})
				}
			}
		}
	}

	if out, err := capability.Registry()["cert.expiry"].Run(ctx, capability.Args{}); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "renew it") || strings.Contains(line, "expired") {
				alerts = append(alerts, client.Alert{
					Kind:      "cert_expired",
					Summary:   line,
					Suggested: "renew it",
				})
			}
		}
	}

	if len(alerts) > 3 {
		// A machine in a bad way can trip everything at once. Three is enough
		// to act on; the rest would be a wall of text on a phone.
		alerts = alerts[:3]
	}
	return alerts
}

func discover(ctx context.Context) map[string]string {
	facts := map[string]string{"agent_version": Version}

	for name, cap := range map[string]string{
		"facts":    "server.facts",
		"services": "service.list",
		"disk":     "disk.usage",
		"ports":    "ports.listening",
	} {
		if spec, ok := capability.Registry()[cap]; ok {
			if out, err := spec.Run(ctx, capability.Args{}); err == nil {
				facts[name] = redact.Truncate(redact.Clean(out), 500)
			}
		}
	}
	return facts
}

func asSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func isGone(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no longer registered")
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
