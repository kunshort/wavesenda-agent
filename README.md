# wavesenda-agent

The program that runs on a customer's own server.

```sh
curl -fsSL https://get.wavesenda.com/agent | sh -s -- <token>
```

## What it is

A single static binary with no dependencies beyond the Go standard library. It
holds one token, dials out to WaveSenda, and performs only what is compiled
into [`internal/capability`](internal/capability/capability.go).

It opens no ports. Nothing connects to it; it connects out. That is why it
works behind NAT, needs no firewall change, and is not reachable from the
internet even in principle.

## Why the list lives here

The far side decides what to *ask for*. This side decides what is *possible*.

An attacker who compromises WaveSenda inherits the first and not the second. A
job naming a capability that is not in this build is refused before its
arguments are read; a job naming one that `/etc/wavesenda/policy.json` excludes
is refused however the grant list was set. Neither refusal can be lifted
remotely — changing them means editing a file on the machine and restarting the
service.

Three refusals, outermost first:

1. **Not in this build** — unknown capability, rejected before parsing.
2. **Not permitted locally** — the owner's `policy.json` is a ceiling.
3. **Not granted** — the list that arrives over the wire, checked last.

## No shell, anywhere

There is no `sh -c` in this program. Commands run through `exec.CommandContext`
with argv as a slice, so a unit name containing a semicolon is a unit name that
does not exist rather than a second command. Arguments are parsed by the
helpers on `capability.Args`, each of which validates before returning.

The test suite asserts the refusals rather than the successes — `nginx; rm -rf
/`, `$(reboot)`, path escapes and over-long values all have cases.

## What it may elevate

The installer writes `/etc/sudoers.d/wavesenda` naming three commands. There is
no `ALL` in it and no shell. Read it after installing:

```sh
cat /etc/sudoers.d/wavesenda
```

## Narrowing it further

```jsonc
// /etc/wavesenda/policy.json
{
  "read_only": true,                       // refuse every change
  "allow": ["service.status", "logs.tail"] // or name a ceiling
}
```

Then `systemctl restart wavesenda-agent`. Nothing on the network can widen it.

## Building

```sh
go test ./...
go build -ldflags "-X main.Version=$(git describe --tags)" -o wavesenda-agent .
```

Releases are built for `linux/amd64` and `linux/arm64`, published with a
SHA-256 the installer verifies before the binary is ever executed.

## Removing it

```sh
wavesenda-agent-uninstall
```

Takes the service, the user, the sudoers file, the config and the binary.
