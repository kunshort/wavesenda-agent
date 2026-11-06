package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Deploying is the reason somebody buys this, and the action most likely to
// take a working site down. So it is release-based and self-reversing: build
// beside the live version, switch, check, and put the old one back by itself
// if the check fails. Fifteen years of Capistrano behind that shape.
//
// Two things are deliberately not configurable from the network.
//
// The repository lives in /etc/wavesenda/deploy.json, written on this machine
// at install time. If our API could name the repository, a breach of our API
// would be remote code execution on every customer's server — it would simply
// point a deploy at a repository whose build script it controlled. A job can
// name a ref and nothing else.
//
// The build is detected, never supplied. There is no field anywhere that takes
// a build command, because a build command is a shell string and this program
// does not have a shell. What it has is a recipe per project type, compiled in
// and readable below.

const deployConfigPath = "/etc/wavesenda/deploy.json"

// DeployConfig is written locally. Changing it is a local act.
type DeployConfig struct {
	// Where the code comes from. Only ever read from disk.
	Repo string `json:"repo"`
	// Where releases are kept. Defaults to /srv/wavesenda/app.
	Root string `json:"root"`
	// The service to restart once the new release is current.
	Unit string `json:"unit"`
	// Fetched after the switch. A deploy that cannot be checked is not
	// finished, it is just hopeful.
	HealthURL string `json:"health_url"`
	// How many old releases to keep. Keeping at least one is what makes undo
	// possible, so the floor is enforced rather than trusted.
	Keep int `json:"keep"`
}

func loadDeployConfig() (DeployConfig, error) {
	var cfg DeployConfig
	raw, err := os.ReadFile(deployConfigPath)
	if err != nil {
		return cfg, fmt.Errorf("no application is set up on this server yet")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("the deploy configuration on this server is not valid")
	}
	if cfg.Repo == "" {
		return cfg, fmt.Errorf("no repository is configured on this server")
	}
	if cfg.Root == "" {
		cfg.Root = "/srv/wavesenda/app"
	}
	if cfg.Keep < 2 {
		cfg.Keep = 2
	}
	return cfg, nil
}

func deployRun(ctx context.Context, args Args) (string, error) {
	ref, err := args.Ref()
	if err != nil {
		return "", err
	}
	cfg, err := loadDeployConfig()
	if err != nil {
		return "", err
	}

	previous := currentRelease(cfg)

	if err := fetch(ctx, cfg, ref); err != nil {
		return "", err
	}

	name := fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405"), shortRef(ref))
	release := filepath.Join(cfg.Root, "releases", name)

	if err := checkout(ctx, cfg, ref, release); err != nil {
		return "", err
	}

	recipe, built, err := build(ctx, release)
	if err != nil {
		// Nothing has been switched yet, so the live version never moved.
		_ = os.RemoveAll(release)
		return "", fmt.Errorf("the build failed, so nothing changed: %w", err)
	}

	if err := link(ctx, cfg, release); err != nil {
		return "", err
	}
	if cfg.Unit != "" {
		if _, err := run(ctx, 60*time.Second, "sudo", "-n", "systemctl", "restart", cfg.Unit); err != nil {
			return "", rollbackTo(ctx, cfg, previous, fmt.Errorf("the app would not start: %w", err))
		}
	}

	if cfg.HealthURL != "" {
		if err := healthy(ctx, cfg.HealthURL); err != nil {
			return "", rollbackTo(ctx, cfg, previous, err)
		}
	}

	prune(cfg)

	answer := fmt.Sprintf("Deployed %s (%s build).", ref, recipe)
	if built != "" {
		answer += " " + built
	}
	if cfg.HealthURL != "" {
		answer += " The health check passed."
	}
	if previous != "" {
		answer += " The previous version is still here."
	}
	return answer, nil
}

func deployRollback(ctx context.Context, _ Args) (string, error) {
	cfg, err := loadDeployConfig()
	if err != nil {
		return "", err
	}

	releases := releaseNames(cfg)
	if len(releases) < 2 {
		return "", fmt.Errorf("there is no previous version to go back to")
	}
	current := currentRelease(cfg)

	// The newest release that is not the live one.
	target := ""
	for i := len(releases) - 1; i >= 0; i-- {
		if releases[i] != current {
			target = releases[i]
			break
		}
	}
	if target == "" {
		return "", fmt.Errorf("there is no previous version to go back to")
	}

	if err := link(ctx, cfg, filepath.Join(cfg.Root, "releases", target)); err != nil {
		return "", err
	}
	if cfg.Unit != "" {
		if _, err := run(ctx, 60*time.Second, "sudo", "-n", "systemctl", "restart", cfg.Unit); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("Back on %s.", target), nil
}

func deployHistory(_ context.Context, _ Args) (string, error) {
	cfg, err := loadDeployConfig()
	if err != nil {
		return "", err
	}

	names := releaseNames(cfg)
	if len(names) == 0 {
		return "Nothing has been deployed yet.", nil
	}
	current := currentRelease(cfg)

	var rows []string
	for i := len(names) - 1; i >= 0 && len(rows) < 10; i-- {
		marker := ""
		if names[i] == current {
			marker = "  ← live"
		}
		rows = append(rows, names[i]+marker)
	}
	return strings.Join(rows, "\n"), nil
}

// ── The steps ───────────────────────────────────────────────────────────────

func fetch(ctx context.Context, cfg DeployConfig, ref string) error {
	repo := filepath.Join(cfg.Root, "repo")

	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		if err := os.MkdirAll(filepath.Dir(repo), 0o755); err != nil {
			return err
		}
		// The URL comes from disk, never from the job.
		if _, err := run(ctx, 300*time.Second, "git", "clone", "--no-checkout", cfg.Repo, repo); err != nil {
			return fmt.Errorf("could not reach the repository: %w", err)
		}
	}

	if _, err := run(ctx, 300*time.Second, "git", "-C", repo, "fetch", "--all", "--tags", "--prune"); err != nil {
		return fmt.Errorf("could not fetch: %w", err)
	}
	// Proves the ref exists before a release directory is made for it.
	if _, err := run(ctx, 30*time.Second, "git", "-C", repo, "rev-parse", "--verify", ref+"^{commit}"); err != nil {
		return fmt.Errorf("there is no branch or commit called %s", ref)
	}
	return nil
}

func checkout(ctx context.Context, cfg DeployConfig, ref, release string) error {
	if err := os.MkdirAll(release, 0o755); err != nil {
		return err
	}
	repo := filepath.Join(cfg.Root, "repo")
	if _, err := run(ctx, 120*time.Second,
		"git", "--work-tree="+release, "--git-dir="+filepath.Join(repo, ".git"),
		"checkout", "--force", ref, "--", "."); err != nil {
		_ = os.RemoveAll(release)
		return fmt.Errorf("could not put %s on disk: %w", ref, err)
	}

	// Anything the app needs that is not in git — an env file, uploads — lives
	// in shared/ and is linked in, so it survives every release.
	shared := filepath.Join(cfg.Root, "shared")
	if entries, err := os.ReadDir(shared); err == nil {
		for _, entry := range entries {
			_ = os.Symlink(filepath.Join(shared, entry.Name()), filepath.Join(release, entry.Name()))
		}
	}
	return nil
}

// build detects the project type and runs the recipe for it.
//
// Detection order matters: a Node project with a Dockerfile is a Docker
// project, because the Dockerfile is the author saying how they want it built.
func build(ctx context.Context, release string) (string, string, error) {
	switch {
	case exists(release, "Dockerfile"), exists(release, "docker-compose.yml"), exists(release, "compose.yaml"):
		out, err := run(ctx, 900*time.Second, "docker", "compose", "--project-directory", release, "up", "-d", "--build")
		return "Docker", lastLine(out), err

	case exists(release, "package.json"):
		if _, err := run(ctx, 900*time.Second, "npm", "--prefix", release, "ci", "--omit=dev"); err != nil {
			// A project with no lockfile cannot use `ci`, and telling somebody
			// to go and write one is not help.
			if _, err := run(ctx, 900*time.Second, "npm", "--prefix", release, "install", "--omit=dev"); err != nil {
				return "Node", "", err
			}
		}
		if hasNpmScript(release, "build") {
			if out, err := run(ctx, 900*time.Second, "npm", "--prefix", release, "run", "build"); err != nil {
				return "Node", lastLine(out), err
			}
		}
		return "Node", "", nil

	case exists(release, "requirements.txt"):
		venv := filepath.Join(release, ".venv")
		if _, err := run(ctx, 120*time.Second, "python3", "-m", "venv", venv); err != nil {
			return "Python", "", err
		}
		out, err := run(ctx, 900*time.Second,
			filepath.Join(venv, "bin", "pip"), "install", "--no-input", "-r",
			filepath.Join(release, "requirements.txt"))
		return "Python", lastLine(out), err

	case exists(release, "go.mod"):
		out, err := run(ctx, 900*time.Second, "go", "build", "-C", release, "-o", filepath.Join(release, "app"), ".")
		return "Go", lastLine(out), err
	}

	// A static site needs no build, and saying so is better than failing.
	if exists(release, "index.html") {
		return "static", "", nil
	}
	return "", "", fmt.Errorf("I could not tell how to build this project")
}

func link(ctx context.Context, cfg DeployConfig, release string) error {
	current := filepath.Join(cfg.Root, "current")
	staging := current + ".new"
	_ = os.Remove(staging)

	if err := os.Symlink(release, staging); err != nil {
		return err
	}
	// Renaming a symlink over another is atomic, so there is no instant where
	// `current` points at nothing and the app is serving a missing directory.
	if err := os.Rename(staging, current); err != nil {
		_ = os.Remove(staging)
		return err
	}
	_ = ctx
	return nil
}

func healthy(ctx context.Context, url string) error {
	var last error
	// A freshly restarted app is allowed a few seconds to come up before its
	// silence is read as failure.
	for attempt := 0; attempt < 6; attempt++ {
		time.Sleep(3 * time.Second)
		out, err := httpCheck(ctx, Args{"url": url})
		if err == nil && (strings.Contains(out, "answered 2") || strings.Contains(out, "answered 3")) {
			return nil
		}
		if err != nil {
			last = err
		} else {
			last = fmt.Errorf("the health check said: %s", out)
		}
	}
	return fmt.Errorf("the new version did not pass its health check (%v)", last)
}

func rollbackTo(ctx context.Context, cfg DeployConfig, previous string, cause error) error {
	if previous == "" {
		return fmt.Errorf("%w — and there was no previous version to go back to", cause)
	}
	if err := link(ctx, cfg, filepath.Join(cfg.Root, "releases", previous)); err != nil {
		return fmt.Errorf("%w — and putting the old version back also failed: %v", cause, err)
	}
	if cfg.Unit != "" {
		_, _ = run(ctx, 60*time.Second, "sudo", "-n", "systemctl", "restart", cfg.Unit)
	}
	return fmt.Errorf("%w — I put the previous version back", cause)
}

func prune(cfg DeployConfig) {
	names := releaseNames(cfg)
	if len(names) <= cfg.Keep {
		return
	}
	current := currentRelease(cfg)
	for _, name := range names[:len(names)-cfg.Keep] {
		if name != current {
			_ = os.RemoveAll(filepath.Join(cfg.Root, "releases", name))
		}
	}
}

// ── Reading the layout ──────────────────────────────────────────────────────

func releaseNames(cfg DeployConfig) []string {
	entries, err := os.ReadDir(filepath.Join(cfg.Root, "releases"))
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	// Names start with a sortable timestamp, so this is chronological.
	sort.Strings(names)
	return names
}

func currentRelease(cfg DeployConfig) string {
	target, err := os.Readlink(filepath.Join(cfg.Root, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func hasNpmScript(release, name string) bool {
	raw, err := os.ReadFile(filepath.Join(release, "package.json"))
	if err != nil {
		return false
	}
	var parsed struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return false
	}
	_, ok := parsed.Scripts[name]
	return ok
}

func shortRef(ref string) string {
	safe := strings.NewReplacer("/", "-", ".", "-").Replace(ref)
	if len(safe) > 20 {
		safe = safe[:20]
	}
	return safe
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
