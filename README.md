# WaveSenda agent

> **This is a generated mirror.** It is force-pushed from the WaveSenda
> monorepo on every release, so anything committed here is overwritten. Issues
> and pull requests belong upstream — this repository exists so that a program
> people install on their own servers can be read before it is run, not because
> the code is developed in it.

The program that runs on your server and lets you operate it from WhatsApp:
ask whether a service is up, read its logs, deploy a new version, put the old
one back.

```sh
curl -fsSL https://github.com/kunshort/wavesenda-agent/releases/latest/download/install.sh \
  | sh -s -- <your-token>
```

You get the token from **Servers → Connect a server** in the WaveSenda console.

Read the installer before you run it. It is in every release beside the
binaries, it is about a hundred lines, and the top of it lists everything it
does. We are asking you to pipe a script from the internet into a root shell,
and being casual about that would teach exactly the wrong habit.

## What it does to your machine

1. Downloads one binary and checks it against a published SHA-256.
2. Creates a `wavesenda` system user that owns nothing and can log in nowhere.
3. Writes `/etc/sudoers.d/wavesenda` naming the three commands that user may
   elevate. Not `ALL`. Read it afterwards.
4. Writes your token to a file only that user can read.
5. Installs a systemd service and starts it.

It opens no ports and changes no firewall rule.

## It dials out. Nothing dials in.

There is no listener anywhere in this program. The agent connects *out* to
WaveSenda over TLS and asks whether there is anything to do. That is why it
works behind NAT, needs no inbound rule, and is not reachable from the
internet even in principle.

It also means WaveSenda never holds a credential that opens a shell on your
server. If we were to store an SSH key for every customer, one breach of our
database would be root on every one of those machines at once.

## The list of things it will do is in here, not on our side

Everything the agent can perform is compiled into
[`internal/capability`](internal/capability/capability.go). A job naming
anything else is refused before its arguments are read.

That is the property the whole design rests on: WaveSenda decides what to
*ask for*, and your machine decides what is *possible*. An attacker who
compromised WaveSenda would inherit the first and not the second.

Three refusals, outermost first:

1. **Not in this build** — unknown capability, rejected without parsing.
2. **Not permitted locally** — your `policy.json` is a ceiling.
3. **Not granted** — the list that arrives over the wire, checked last,
   because it is the only one that comes from outside your machine.

## No shell, anywhere

There is no `sh -c` in this program. Commands run through
`exec.CommandContext` with the arguments kept apart from the command, so a
service name containing a semicolon is a service name that does not exist
rather than a second command.

The tests assert the refusals rather than the successes — `nginx; rm -rf /`,
`$(reboot)`, path escapes and over-long values all have cases.

## Narrowing it further

Nothing on the network can widen what you set here.

```jsonc
// /etc/wavesenda/policy.json
{
  "read_only": true,                        // refuse every change
  "allow": ["service.status", "logs.tail"]  // or name a ceiling
}
```

Then `systemctl restart wavesenda-agent`.

## Secrets do not leave the machine

Output is scanned for credential-shaped text here, before it is sent —
connection strings, API keys, private key blocks, bearer tokens. A secret that
never crosses the network cannot be read out of a chat thread, a model's
context window, or a backup.

## Verifying a download

```sh
curl -fsSLO https://github.com/kunshort/wavesenda-agent/releases/latest/download/wavesenda-agent-linux-amd64
curl -fsSL  https://github.com/kunshort/wavesenda-agent/releases/latest/download/wavesenda-agent-linux-amd64.sha256
sha256sum -c wavesenda-agent-linux-amd64.sha256
```

The installer does this for you and refuses to execute a binary that does not
match.

## Building it yourself

```sh
go test ./...
go build -o wavesenda-agent .
```

Go 1.22+. No dependencies outside the standard library, by design: the list of
things to audit before running this on your own server should be short.

## Removing it

```sh
wavesenda-agent-uninstall
```

Takes the service, the user, the sudoers file, the configuration and the
binary.

## Reporting something

See [SECURITY.md](SECURITY.md). Anything else belongs in the WaveSenda
console or at support@wavesenda.com — this repository is a mirror and is not
watched.
