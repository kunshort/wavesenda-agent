# Reporting a security problem

This program runs as a privileged service on other people's servers. If you
have found something wrong with it, we would much rather hear from you than
not.

**security@wavesenda.com.** Please do not open a public issue — and note that
issues on this repository are not watched at all, because it is a mirror.

Include whatever you have: the version (`wavesenda-agent --check` prints it, or
read it from the release you installed), what you did, and what happened. A
rough description of a real problem is worth more than a polished report of a
theoretical one.

We will acknowledge within two working days and tell you what we think,
including if we think it is not a problem and why.

## What we consider serious

- Anything that runs a command the capability list does not contain.
- Anything that escapes the argument validation — a service name, domain or
  git ref that reaches a shell.
- Anything that widens what the daemon will do without a change on the machine
  itself: the local `policy.json` is meant to be a ceiling that nothing on the
  network can raise.
- A credential reaching our servers through output that the redactor should
  have caught.
- Anything that lets one customer's instructions reach another's machine.

## What is already known and intended

- **The agent can restart services, deploy, renew certificates and clear
  caches** when granted. That is the product. The sudoers file written by the
  installer lists exactly what it may elevate.
- **An operator who holds the bound WhatsApp account can make changes.** That
  is why state-changing actions also require a code sent to a separate email
  address, and why destructive operations are not available over chat at all.
- **The installer is piped into a root shell.** It is published with a
  checksum it verifies before executing anything, and it is readable in every
  release. If you would rather not, download the binary, check the SHA-256
  yourself, and run the steps by hand.

## Scope

This repository only. Problems with the WaveSenda API, console or WhatsApp
integration go to the same address, and are just as welcome.
