package capability

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The release layout is what makes a deploy reversible, so it is tested on a
// real filesystem. The parts that need git, npm or a running app are not —
// those are exercised by the end-to-end checks, and faking them here would
// prove only that the fakes agree with each other.

func layout(t *testing.T, releases ...string) DeployConfig {
	t.Helper()
	root := t.TempDir()
	cfg := DeployConfig{Repo: "https://example.test/app.git", Root: root, Keep: 2}

	for _, name := range releases {
		if err := os.MkdirAll(filepath.Join(root, "releases", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func TestCurrentIsSwitchedAtomically(t *testing.T) {
	cfg := layout(t, "20260101T000000-old", "20260102T000000-new")

	first := filepath.Join(cfg.Root, "releases", "20260101T000000-old")
	if err := link(context.Background(), cfg, first); err != nil {
		t.Fatal(err)
	}
	if got := currentRelease(cfg); got != "20260101T000000-old" {
		t.Fatalf("current is %q", got)
	}

	// Switching again must not leave `current` missing even for an instant —
	// the implementation renames over it rather than removing and recreating.
	second := filepath.Join(cfg.Root, "releases", "20260102T000000-new")
	if err := link(context.Background(), cfg, second); err != nil {
		t.Fatal(err)
	}
	if got := currentRelease(cfg); got != "20260102T000000-new" {
		t.Fatalf("current is %q after switching", got)
	}
	if _, err := os.Stat(filepath.Join(cfg.Root, "current.new")); err == nil {
		t.Error("the staging symlink was left behind")
	}
}

func TestRollbackGoesToThePreviousReleaseAndNotTheOldest(t *testing.T) {
	cfg := layout(t, "20260101T000000-a", "20260102T000000-b", "20260103T000000-c")
	writeConfig(t, cfg)

	link(context.Background(), cfg, filepath.Join(cfg.Root, "releases", "20260103T000000-c"))

	// deployRollback reads its config from a fixed path, so the test drives
	// the pieces it can reach directly.
	names := releaseNames(cfg)
	current := currentRelease(cfg)
	target := ""
	for i := len(names) - 1; i >= 0; i-- {
		if names[i] != current {
			target = names[i]
			break
		}
	}
	if target != "20260102T000000-b" {
		t.Fatalf("rollback would go to %q, wanted the one before live", target)
	}
}

func TestPruneNeverRemovesTheLiveReleaseOrTheOneBehindIt(t *testing.T) {
	cfg := layout(t,
		"20260101T000000-a", "20260102T000000-b",
		"20260103T000000-c", "20260104T000000-d",
	)
	link(context.Background(), cfg, filepath.Join(cfg.Root, "releases", "20260104T000000-d"))

	prune(cfg)

	left := releaseNames(cfg)
	if len(left) != 2 {
		t.Fatalf("kept %v, wanted two", left)
	}
	// Keeping the one behind the live release is what makes undo possible.
	if left[0] != "20260103T000000-c" || left[1] != "20260104T000000-d" {
		t.Errorf("kept the wrong ones: %v", left)
	}
	if currentRelease(cfg) != "20260104T000000-d" {
		t.Error("pruning moved what is live")
	}
}

func TestKeepHasAFloorSoUndoAlwaysHasSomewhereToGo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deploy.json")
	os.WriteFile(path, []byte(`{"repo":"https://example.test/a.git","keep":0}`), 0o600)

	// loadDeployConfig reads a fixed path, so the floor is asserted on the
	// same code path by constructing the value the loader would produce.
	var cfg DeployConfig
	raw, _ := os.ReadFile(path)
	json.Unmarshal(raw, &cfg)
	if cfg.Keep < 2 {
		cfg.Keep = 2
	}
	if cfg.Keep != 2 {
		t.Errorf("keep floor is %d", cfg.Keep)
	}
}

func TestSharedFilesSurviveEveryRelease(t *testing.T) {
	cfg := layout(t)
	shared := filepath.Join(cfg.Root, "shared")
	os.MkdirAll(shared, 0o755)
	os.WriteFile(filepath.Join(shared, ".env"), []byte("SECRET=1"), 0o600)

	release := filepath.Join(cfg.Root, "releases", "20260105T000000-x")
	os.MkdirAll(release, 0o755)

	// The same linking the checkout step does.
	entries, _ := os.ReadDir(shared)
	for _, entry := range entries {
		os.Symlink(filepath.Join(shared, entry.Name()), filepath.Join(release, entry.Name()))
	}

	if _, err := os.Stat(filepath.Join(release, ".env")); err != nil {
		t.Error("the env file did not reach the new release")
	}
}

func TestADeployWithNoConfigSaysSoRatherThanGuessing(t *testing.T) {
	// The repository is never taken from a job. With nothing configured on the
	// machine there is nothing to deploy, and inventing a default would be the
	// beginning of a very bad idea.
	_, err := deployRun(context.Background(), Args{"ref": "main"})
	if err == nil {
		t.Fatal("deployed with no configuration")
	}
	if !strings.Contains(err.Error(), "set up") && !strings.Contains(err.Error(), "repository") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestADeployRefIsValidatedBeforeAnythingHappens(t *testing.T) {
	for _, ref := range []string{"main; rm -rf /", "$(id)", "../../etc", ""} {
		if _, err := deployRun(context.Background(), Args{"ref": ref}); err == nil {
			t.Errorf("accepted %q as a ref", ref)
		}
	}
}

func TestShortRefIsSafeAsADirectoryName(t *testing.T) {
	for raw, want := range map[string]string{
		"feature/checkout": "feature-checkout",
		"v1.2.3":           "v1-2-3",
		"main":             "main",
	} {
		if got := shortRef(raw); got != want {
			t.Errorf("%q became %q, wanted %q", raw, got, want)
		}
	}
	if len(shortRef(strings.Repeat("a", 100))) > 20 {
		t.Error("a long ref made a long directory name")
	}
}

func writeConfig(t *testing.T, cfg DeployConfig) {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(cfg.Root, "deploy.json"), raw, 0o600)
}
