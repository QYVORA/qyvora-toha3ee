# toha3ee documentation

toha3ee is an **authorised-engagement network security framework** written in
Go. It demonstrates classic layer-2/3/7 network attacks — ARP/DHCP/DNS/IPv6
poisoning, inline HTTP/HTTPS interception, wireless and switch-layer
exploitation — driven from an interactive REPL, a guided wizard, `.toha3ee`
scripts or one-shot command sequences.

> **Read this first.** toha3ee actively redirects, poisons, decrypts and
> intercepts network traffic. Use it **only on networks you own or are
> explicitly authorised to test.** See [Security & responsible use](security.md)
> before running anything.

## Documentation map

| Guide | What it covers |
|-------|----------------|
| [Getting started](getting-started.md) | Install, build, prerequisites, first session |
| [User guide](user-guide.md) | The console, commands, wizard, caplets, common workflows |
| [Scripting reference](scripting.md) | The full `.toha3ee` language |
| [Configuration](configuration.md) | `toha3ee.json`, per-module settings, environment variables |
| [Architecture](architecture.md) | Module contract, lifecycle, layers, stealth engine |
| [Module reference](module-reference.md) | Every module, its risk, targets and settings |
| [Reporting](reporting.md) | The `report.generate` output format and interpretation |
| [Security & responsible use](security.md) | Risk model, blast radius, legal and ethical use |
| [Contributing](contributing.md) | Developer setup, how to add a module, conventions |
| [FAQ](faq.md) | Common questions and troubleshooting |

## Project files

- [`README.md`](../README.md) — quick overview and installation
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — contributor onboarding
- [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) — community standards
- [`SECURITY.md`](../SECURITY.md) — vulnerability disclosure policy
- [`CHANGELOG.md`](../CHANGELOG.md) — release history
- [`LICENSE`](../LICENSE) — MIT license

## Quick start

```sh
# Install (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh

# Or from a checkout
make install

# Interactive console
sudo toha3ee --iface eth0

# One-shot: scan then show hosts
sudo toha3ee --eval "net.scan; net.show" --iface eth0

# Dry-run a full engagement script (no packets)
toha3ee --no-sudo build scripts/full-pipeline.toha3ee
```

See [Getting started](getting-started.md) for details.

## Command reference

```
toha3ee [flags] [command]

Commands:
  interactive    start the interactive console (default)
  wizard         guided attack setup
  eval           run a one-shot command sequence and exit
  run            execute a script or caplet non-interactively
  script         execute a .toha3ee script file
  build          validate a .toha3ee script and print a dry-run plan
  modules        list all registered modules
  version        print the version

Flags:
      --iface string    network interface to attack from
      --config string   config file path (default toha3ee.json)
      --eval string     run a one-shot command sequence and exit
  -v, --verbose         verbose logging
      --no-color        disable colored output
      --no-sudo         do not auto-escalate to root via sudo
```
