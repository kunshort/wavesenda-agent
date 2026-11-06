// Package policy is the ceiling this machine's owner sets, which nothing on
// the network can raise.
//
// The server tells the daemon what it has been granted. That is a narrowing
// instruction, never a widening one: if /etc/wavesenda/policy.json names an
// allow list, a capability missing from it stays refused however the API asks.
// This is the property that makes a breach of our own infrastructure
// survivable — an attacker who can send jobs still cannot send jobs this
// machine was never configured to accept.
package policy

import (
	"encoding/json"
	"os"
)

// Policy is read once at startup. Changing it is a local act: edit the file,
// restart the service. There is deliberately no way to change it remotely.
type Policy struct {
	// Empty means "whatever the server grants". A non-empty list is a ceiling.
	Allow []string `json:"allow"`
	// Refuses every state change regardless of grants. For somebody who wants
	// the agent to answer questions and never touch anything.
	ReadOnly bool `json:"read_only"`
}

// Load reads the policy file. A missing file is not an error — it means the
// owner has not narrowed anything.
func Load(path string) (Policy, error) {
	var p Policy
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	return p, nil
}

// Permits reports whether this machine's own configuration allows a
// capability at all.
func (p Policy) Permits(name string, isChange bool) bool {
	if isChange && p.ReadOnly {
		return false
	}
	if len(p.Allow) == 0 {
		return true
	}
	for _, allowed := range p.Allow {
		if allowed == name {
			return true
		}
	}
	return false
}
