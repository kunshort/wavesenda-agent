package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoFileMeansNothingIsNarrowed(t *testing.T) {
	p, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing policy is not an error: %v", err)
	}
	if !p.Permits("service.restart", true) {
		t.Error("refused a change with no policy file present")
	}
}

func TestAnAllowListIsACeiling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"allow": ["service.status"]}`), 0o600)

	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Permits("service.status", false) {
		t.Error("refused something on the allow list")
	}
	// The grant list upstream cannot widen this.
	if p.Permits("service.restart", true) {
		t.Error("allowed something the machine's owner left off the list")
	}
}

func TestReadOnlyRefusesEveryChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"read_only": true}`), 0o600)

	p, _ := Load(path)
	if !p.Permits("service.status", false) {
		t.Error("read-only blocked a read")
	}
	if p.Permits("service.restart", true) {
		t.Error("read-only allowed a change")
	}
}
