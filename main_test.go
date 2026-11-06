package main

import (
	"testing"

	"github.com/kunshort/wavesenda-agent/internal/capability"
	"github.com/kunshort/wavesenda-agent/internal/policy"
)

// What this daemon refuses matters more than what it runs, so the refusals
// are what is tested. Each case is a thing that would have to be true for a
// compromise of the far side to reach this machine.

func TestACapabilityThisBuildDoesNotHaveIsRefused(t *testing.T) {
	// The whole point of the local list. Our API could ask for anything;
	// this build answers only for what was compiled into it.
	for _, name := range []string{"shell.run", "db.drop", "firewall.set", "made.up"} {
		if _, refusal := decide(name, nil, policy.Policy{}); refusal == "" {
			t.Errorf("%s was allowed", name)
		}
	}
}

func TestLocalPolicyCannotBeWidenedByAGrant(t *testing.T) {
	// The machine's owner narrowed it to reads. A grant list naming a change
	// — however it got there — does not reopen it.
	local := policy.Policy{Allow: []string{"service.status"}}
	grants := map[string]bool{"service.status": true, "service.restart": true}

	if _, refusal := decide("service.status", grants, local); refusal != "" {
		t.Errorf("refused something on the local allow list: %s", refusal)
	}
	if _, refusal := decide("service.restart", grants, local); refusal == "" {
		t.Error("a grant widened the local policy")
	}
}

func TestReadOnlyStopsChangesAndNotQuestions(t *testing.T) {
	local := policy.Policy{ReadOnly: true}
	grants := map[string]bool{"service.status": true, "service.restart": true}

	if _, refusal := decide("service.status", grants, local); refusal != "" {
		t.Errorf("read-only blocked a read: %s", refusal)
	}
	if _, refusal := decide("service.restart", grants, local); refusal == "" {
		t.Error("read-only allowed a change")
	}
}

func TestAnUngrantedCapabilityIsRefused(t *testing.T) {
	grants := map[string]bool{"disk.usage": true}
	if _, refusal := decide("service.restart", grants, policy.Policy{}); refusal == "" {
		t.Error("ran something that was not granted")
	}
}

func TestAnEmptyGrantListMeansWeHaveNotHeardYet(t *testing.T) {
	// Before the first heartbeat there is no list. Falling back to the local
	// policy is right: a daemon that refused everything until it had spoken to
	// us would be useless exactly when the network is the problem.
	if _, refusal := decide("disk.usage", nil, policy.Policy{}); refusal != "" {
		t.Errorf("refused before the first heartbeat: %s", refusal)
	}
}

func TestTheDecisionIsMadeBeforeArgumentsAreRead(t *testing.T) {
	// `decide` takes a name and never the arguments, which is what guarantees
	// an unknown capability cannot reach any parsing code at all.
	spec, refusal := decide("service.status", map[string]bool{"service.status": true}, policy.Policy{})
	if refusal != "" || spec.Run == nil {
		t.Fatalf("expected a runnable capability, got %q", refusal)
	}
	if spec.Tier != capability.TierRead {
		t.Errorf("service.status is tier %q", spec.Tier)
	}
}
