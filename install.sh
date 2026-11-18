#!/bin/sh
#
# Install the WaveSenda agent on this server.
#
#   curl -fsSL https://github.com/kunshort/wavesenda-agent/releases/latest/download/install.sh \
#     | sh -s -- <token>
#
# Read this before you run it. We are asking you to pipe a script from the
# internet into a root shell, and being casual about that would teach exactly
# the wrong habit — so here is everything it does, in order:
#
#   1. Downloads one binary over TLS and checks it against a published SHA-256.
#   2. Creates a `wavesenda` user that owns nothing and can log in nowhere.
#   3. Writes a sudoers file naming each command that user may elevate.
#      Not ALL. You can read it at /etc/sudoers.d/wavesenda afterwards.
#   4. Writes your token to a file only that user can read.
#   5. Installs a systemd service and starts it.
#
# It opens no ports and changes no firewall rule. The agent dials out; nothing
# dials in.
#
# To remove all of it:  wavesenda-agent-uninstall
set -eu

TOKEN="${1:-}"
API="${WAVESENDA_API:-https://api.wavesenda.com/api/internal/servers}"
# The public mirror, because this is fetched by machines that have never heard
# of us and must not need a token. `latest` resolves through GitHub's own
# redirect, so there is no version list to keep in step with anything.
RELEASES="${WAVESENDA_RELEASES:-https://github.com/kunshort/wavesenda-agent/releases}"
VERSION="${WAVESENDA_VERSION:-latest}"

die() { printf 'wavesenda: %s\n' "$1" >&2; exit 1; }

[ -n "$TOKEN" ] || die "no token given. Copy the whole line from the console."
[ "$(id -u)" = "0" ] || die "run this as root (try: sudo !!)"
command -v systemctl >/dev/null 2>&1 || die "this needs systemd, which this machine does not have"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

printf 'Installing the WaveSenda agent (%s)\n' "$ARCH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ "$VERSION" = "latest" ]; then
  BINARY="$RELEASES/latest/download/wavesenda-agent-linux-$ARCH"
else
  BINARY="$RELEASES/download/v$VERSION/wavesenda-agent-linux-$ARCH"
fi
curl -fsSL "$BINARY" -o "$TMP/agent" || die "could not download the agent"
curl -fsSL "$BINARY.sha256" -o "$TMP/agent.sha256" || die "could not download the checksum"

# Verified before it is ever executed. A download that cannot be checked is a
# download that does not get run.
EXPECTED="$(cut -d' ' -f1 < "$TMP/agent.sha256")"
ACTUAL="$(sha256sum "$TMP/agent" | cut -d' ' -f1)"
[ "$EXPECTED" = "$ACTUAL" ] || die "the downloaded agent does not match its checksum — stopping"

install -m 0755 "$TMP/agent" /usr/local/bin/wavesenda-agent

# A system user with no shell, no home worth anything, and no password. It
# cannot log in; systemd starts it and nothing else can.
id wavesenda >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin wavesenda

install -d -m 0750 -o wavesenda -g wavesenda /etc/wavesenda
umask 077
cat > /etc/wavesenda/agent.json <<JSON
{"api": "$API", "token": "$TOKEN", "name": "$(hostname)"}
JSON
chown wavesenda:wavesenda /etc/wavesenda/agent.json
chmod 0600 /etc/wavesenda/agent.json

# Exactly what the agent may elevate, and nothing else. Read it yourself:
# there is no ALL in this file, and no shell.
cat > /etc/sudoers.d/wavesenda <<'SUDO'
wavesenda ALL=(root) NOPASSWD: /bin/systemctl restart *, /usr/bin/systemctl restart *
wavesenda ALL=(root) NOPASSWD: /usr/bin/journalctl --vacuum-size=200M
wavesenda ALL=(root) NOPASSWD: /usr/bin/apt-get clean
wavesenda ALL=(root) NOPASSWD: /usr/bin/certbot renew --cert-name * --non-interactive
# Reading what Docker is running, and nothing else about Docker. The usual
# advice is to put this user in the `docker` group, which would let it start a
# privileged container — root on this machine by another name. `docker ps`
# cannot change anything, whatever flags it is given.
#
# The exact invocation first, naming every argument, so what the agent may
# run is one command and not a family of them. The wildcard line stays
# underneath for the agent that is older than this file.
#
# Several paths because sudo matches the one a rule names and Docker is not
# always in the same place: the packages put it in /usr/bin, and a wrapper
# in /usr/local/bin shadows that for anything resolving through PATH.
wavesenda ALL=(root) NOPASSWD: /usr/bin/docker ps --all --no-trunc --format {{.Names}}|{{.State}}|{{.Status}}|{{.Image}}
wavesenda ALL=(root) NOPASSWD: /usr/local/bin/docker ps --all --no-trunc --format {{.Names}}|{{.State}}|{{.Status}}|{{.Image}}
wavesenda ALL=(root) NOPASSWD: /usr/bin/docker stats --no-stream --format {{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}
wavesenda ALL=(root) NOPASSWD: /usr/local/bin/docker stats --no-stream --format {{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}
wavesenda ALL=(root) NOPASSWD: /usr/bin/docker ps *, /bin/docker ps *, /usr/local/bin/docker ps *
wavesenda ALL=(root) NOPASSWD: /usr/bin/docker stats *, /bin/docker stats *, /usr/local/bin/docker stats *
SUDO
chmod 0440 /etc/sudoers.d/wavesenda
visudo -cf /etc/sudoers.d/wavesenda >/dev/null || {
  rm -f /etc/sudoers.d/wavesenda
  die "the sudoers file was rejected and has been removed — nothing was changed"
}

cat > /etc/systemd/system/wavesenda-agent.service <<'UNIT'
[Unit]
Description=WaveSenda agent
Documentation=https://wavesenda.com/docs/servers
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wavesenda
Group=wavesenda
ExecStart=/usr/local/bin/wavesenda-agent
Restart=always
RestartSec=10

# It reads logs and runs a handful of elevated commands, so it needs sudo —
# and sudo needs setuid, which `NoNewPrivileges=yes` forbids outright.
#
# Saying `no` here is not enough on its own, which is the trap this unit fell
# into: systemd documents ProtectKernelTunables=, ProtectKernelModules=,
# RestrictSUIDSGID= and LockPersonality= as *implying* NoNewPrivileges=yes,
# and an implication is not overridden by setting it to no further up. All
# four were set, so every elevated capability failed with "the no new
# privileges flag is set" — a restart, a certificate renewal, a disk reclaim
# and `docker ps` alike — while the agent otherwise looked perfectly healthy.
#
# What is left is the hardening that costs nothing here: no writing outside
# the paths below, no home directories, a private /tmp, and hard ceilings on
# memory and tasks.
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
# 512M, not the 256M this started with. The agent itself is small, but it
# execs the Docker client — a 47 MB binary — and a cgroup that cannot
# comfortably hold both does not fail: it thrashes, and `docker ps` goes from
# instant to slower than the read's own deadline.
MemoryMax=512M
TasksMax=64

[Install]
WantedBy=multi-user.target
UNIT

cat > /usr/local/bin/wavesenda-agent-uninstall <<'REMOVE'
#!/bin/sh
set -eu
systemctl disable --now wavesenda-agent 2>/dev/null || true
rm -f /etc/systemd/system/wavesenda-agent.service /etc/sudoers.d/wavesenda
rm -f /usr/local/bin/wavesenda-agent /usr/local/bin/wavesenda-agent-uninstall
rm -rf /etc/wavesenda
systemctl daemon-reload 2>/dev/null || true
userdel wavesenda 2>/dev/null || true
echo "The WaveSenda agent has been removed."
REMOVE
chmod 0755 /usr/local/bin/wavesenda-agent-uninstall

systemctl daemon-reload
systemctl enable --now wavesenda-agent

# The one property this unit cannot do without, read back from systemd rather
# than assumed. A hardening option added here later that implies it again
# would otherwise break every elevated capability silently, which is precisely
# what happened the first time.
if [ "$(systemctl show wavesenda-agent -p NoNewPrivileges --value)" = "yes" ]; then
  printf '\nWarning: this unit forbids privilege escalation, so the agent cannot\n'
  printf 'restart a service, renew a certificate or read Docker. Check which\n'
  printf 'option in %s implies NoNewPrivileges.\n' /etc/systemd/system/wavesenda-agent.service
fi

printf '\nChecking it can reach WaveSenda...\n'
if sudo -u wavesenda /usr/local/bin/wavesenda-agent --check; then
  printf '\nDone. Go back to the console — your server is connected.\n'
else
  printf '\nThe agent is installed but could not reach WaveSenda.\n'
  printf 'Check the token, then: journalctl -u wavesenda-agent -n 50\n'
  exit 1
fi
