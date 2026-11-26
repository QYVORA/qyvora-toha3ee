# toha3ee

![Build](https://img.shields.io/github/actions/workflow/status/qyvora/qyvora-toha3ee/ci.yml?branch=main&label=CI)
![Go Version](https://img.shields.io/github/go-mod/go-version/qyvora/qyvora-toha3ee)
![License](https://img.shields.io/github/license/qyvora/qyvora-toha3ee)
![Release](https://img.shields.io/github/v/release/qyvora/qyvora-toha3ee?sort=semver)
[![Documentation](https://img.shields.io/badge/docs-docs%2F-blue)](/docs)

A local & network security assessment framework written in Go. It is a
research and authorised-penetration-testing tool that covers the network
assessment pipeline — host and service discovery, enumeration, credential
auditing, vulnerability identification and authorised exploitation. Its ten
module categories span recon, enumeration, OSINT, MITM (ARP/DHCP/DNS/IPv6
poisoning and inline HTTP/HTTPS interception), wireless, switch-layer,
web, auth, espionage and post-exploitation — all driven by one-shot commands,
caplet scripts, or the guided wizard.

MITM is one capability within this broader domain: TOHA3EE is not limited to
man-in-the-middle scenarios.

> **WARNING**: toha3ee actively redirects, poisons, decrypts and intercepts
> network traffic. Use it **only on networks you own or are explicitly
> authorised to test**. Running these modules against third parties is illegal
> in most jurisdictions. Read [`docs/Security.md`](docs/Security.md) first.

## Readiness

**BETA.** TOHA3EE is a broad local/network security framework: the wizard and caplets remain, while the interactive console/TUI is retired; MITM is one capability, not the whole framework. Implementation exists for exploration/testing but has not received final production-readiness approval. Its owner classification is `BETA` in the [Product Registry](../../../../knowledge/qyvora-docs/07-products/PRODUCT-REGISTRY.md); release tags do not promote it to `AVAILABLE`.

## Documentation

- **User** — [Getting started](docs/Getting-Started.md) · [User guide](docs/User-Guide.md) · [Scripting](docs/Scripting.md) · [Configuration](docs/Configuration.md) · [FAQ](docs/FAQ.md)
- **Reference** — [Module reference](docs/Module-Reference.md) (all 70 modules) · [Reporting](docs/Reporting.md)
- **Developer** — [Architecture](docs/Architecture.md) · [Contributing](docs/Contributing.md) · [Changelog](CHANGELOG.md)
- **Governance** — [Security](SECURITY.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [License](LICENSE)

## Install

One-liner installers fetch the prebuilt binary for your platform from the
latest release, verify its SHA-256 checksum and add it to your PATH. If no
prebuilt binary exists yet they build from source instead.

Linux / macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.ps1 | iex
```

Or from a checkout:

```sh
make install   # installs ~/.local/bin/toha3ee and adds it to PATH
```

Install options (Unix): `--prefix <dir>` (default: `/usr/local/bin` as root,
else `~/.local/bin`), `--no-path` to skip editing your shell rc, `--from-source`
to build instead of downloading, and `TOHA3EE_VERSION=<tag>` to pin a release.
Run with `sudo sh ...` to install system-wide. The Windows installer puts the
binary in `%LOCALAPPDATA%\Programs\toha3ee\bin` and updates your user PATH;
Windows-on-ARM64 runs the x64 build.

On Linux the installer also registers the app with the desktop environment: it
installs the logo to the hicolor icon theme and drops a `.desktop` entry
next to the install prefix (e.g. `/usr/local/share` or `~/.local/share`), so
`toha3ee` shows up in GNOME's search with its icon. On Windows it copies the
`.ico` and creates a Start Menu shortcut. The release tarball/zip carry the
icon so the installer can register it from the same verified artifact.

Uninstall: delete the binary and the PATH line the installer added to your
shell rc (or `%LOCALAPPDATA%\Programs\toha3ee` on Windows).

## Updating

Once installed, update with:

```sh
toha3ee updates        # `toha3ee update` works as an alias
```

Checks the installed version against the latest official QYVORA GitHub
release, verifies the download's SHA-256 against the published checksum,
and swaps the binary in atomically. Downgrades are refused and any failure
leaves your current binary untouched — no Go toolchain or Git required.
See [docs/Update.md](docs/Update.md) for details.

## Build

Requires Go 1.26+ and libpcap.

```sh
# Debian/Ubuntu
sudo apt install libpcap-dev

# then
go build ./cmd/toha3ee
```

Linux builds need libpcap headers (the installer's from-source fallback checks
for them and prints the right apt/dnf command if they are missing). macOS ships
libpcap with Xcode Command Line Tools.

## Quick start

The interactive session is retired and unavailable in this release; a bare
`toha3ee` invocation prints usage instead of opening a TUI. Use `--eval`,
`script`, `run`, or the wizard for assessments.

```sh
# Guided wizard
sudo ./toha3ee wizard --iface eth0

# One-shot: scan the subnet, then show what was found
sudo ./toha3ee --eval "net.scan; net.show" --iface eth0

# One-shot: procedural deep recon (synscan -> fingerprint -> service enum)
sudo ./toha3ee --eval "net.recon; net.profile" --iface eth0

# Non-interactive caplet script
sudo ./toha3ee run --iface eth0 caplets/basic.cap

# Dry-run a .toha3ee script (validates it, prints the plan, sends no packets)
./toha3ee build scripts/full-pipeline.toha3ee

# Execute a .toha3ee script non-interactively
sudo ./toha3ee script --iface eth0 scripts/full-pipeline.toha3ee
```

Most attack modules require root (raw sockets, packet capture and IP
forwarding). Run as root or with `CAP_NET_ADMIN`/`CAP_NET_RAW` where possible.
Add `--no-color` to disable colored output, `-v` for verbose logging.

The verbs that touch the network stack (`wizard`, `eval`, `run`, `script`)
run with admin privileges **by default**: on Linux/macOS the tool
re-executes itself under `sudo` and prompts for the admin (root) password.
Local-only verbs never escalate and need no password — `version`, `modules`,
`capabilities`, `completion`, `help`, `updates`, `build` and `report` run
unprivileged as the invoking user. Pass `--no-sudo` (or set
`TOHA3EE_NO_SUDO=1`) to suppress escalation for the network verbs too.

## Architecture

Everything is a **module**. Modules self-register in their package `init()` and
are surfaced automatically by the registry; adding an attack means adding a
package under `internal/attacks/` that implements the `attacks.Module`
contract (see `internal/attacks/attacks.go`):

- `Meta()` — ID, category, risk, targets, description, limitations
- `Preflight(ctx)` — check preconditions before running
- `Run(ctx, opts)` — the attack loop (must respect `ctx.Done`)
- `Verify(ctx)` — report what happened
- `Cleanup(ctx)` — undo everything, restore the network

A central `safety` lifecycle (`internal/safety`) tracks registered cleanups
and heartbeats so every attack is torn down even on panic or SIGINT, and a
shared `store` keeps the host inventory, captured credentials, sessions and
the event log that feeds the report generator.

### Layers

| Path | Purpose |
|------|---------|
| `cmd/toha3ee` | CLI: wizard, `--eval`, caplet runner, `script`/`build` (console retired) |
| `internal/ui` | one-shot rendering: banner, palette, sections, tables, status glyphs |
| `internal/script` | the `.toha3ee` scripting language: lexer, parser, engine |
| `internal/attacks/` | all attack modules by category |
| `internal/netx/` | protocol primitives (ARP, DHCP, DNS, NDP, 802.11, SMB/NTLM, proxy, …) |
| `internal/hijack` | HTTP/HTTPS MITM proxy and credential/session interception |
| `internal/phish` | captive-portal phishing and login-page clones |
| `internal/store` | shared data store and event bus |
| `internal/safety` | cleanup/heartbeat lifecycle |
| `internal/config` | JSON config loading |
| `internal/oui` | MAC vendor database |
| `pkg/certutil` | framework CA and per-host TLS certificates |

## Modules

Run `toha3ee modules` for the full, current catalogue. Highlights:

| Category | Modules |
|----------|---------|
| **mitm** | `arp.spoof`, `dns.spoof`, `dns.rebind`, `dhcp.rogue`, `dhcp.starve`, `dhcp6.spoof`, `icmp.redirect`, `ipv6.ra`, `ipv6.ndp`, `llmnr.poison`, `wpad.poison` |
| **espionage** | `http.harvest`, `http.proxy`, `https.proxy`, `ssl.strip`, `phish.inject` |
| **auth** | `default.creds`, `ntlm.relay`, `smb.signing`, `smb.kerberoast`, `auth.spray`, `auth.brute`, `auth.userenum`, `auth.asrep` |
| **recon** | `net.scan`, `net.ping`, `net.traceroute`, `net.osdetect`, `service.synscan`, `service.tcpconnect`, `service.udpscan`, `service.finxmas`, `service.ack`, `service.protoscan`, `service.idle`, `service.fingerprint`, `service.tls`, `web.dir`, `cve.suggest` |
| **osint** | `osint.dns`, `osint.whois`, `osint.ct`, `osint.asn`, `osint.shodan`, `osint.bucket`, `osint.wayback`, `osint.github`, `osint.hibp`, `osint.metadata`, `osint.dork`, `osint.harvest` |
| **enum** | `smtp.enum`, `snmp.enum`, `ldap.enum`, `nfs.enum`, `smb.enum`, `net.ip6sweep` |
| **web** | `web.misconfig` |
| **switch** | `switch.flood`, `switch.portsteal`, `switch.vlanhop`, `switch.cdp`, `switch.stp` |
| **wireless** | `wlan.scan`, `wlan.deauth`, `wlan.handshake`, `wlan.eviltwin`, `wlan.pmkid`, `wlan.beaconflood`, `wlan.karma` |
| **post** | `report.generate`, `session.replay`, `pcap.export` |

## Interactive session — unavailable in this release

The interactive session is retired and not built: `cmd/toha3ee/tui.go` carries
`//go:build ignore`, and a bare `toha3ee` invocation prints usage. The shared
QYVORA terminal application is disabled pending the redirect of qyvora-tui to
the future AI orchestration layer. Use `toha3ee eval`, `toha3ee script`,
`toha3ee run`, or `toha3ee wizard` instead.

## Scripting

`.toha3ee` files drive the full recon → exploit → report pipeline with a
Python-like language that reads like English. Execute one with `toha3ee script
<file>`, or run any `.toha3ee` file with `toha3ee run <file>`. `toha3ee build
<file>` validates the file and prints a dry-run plan without touching the
network. `scripts/full-pipeline.toha3ee` is a working end-to-end example.

```toha3ee
# comment (or //)
set net.scan.targets -> "192.168.8.0/24"     # configure a module
on net.scan                                   # start a module (run/start)
wait for net.scan                             # block until it finishes
_hosts -> [$(net.hosts)]                      # capture a list (or =, >>)
echo -> "found $(_hosts.size) hosts"          # print (say/print)

if $(hosts.count) > 1                         # conditions
    on arp.spoof targets "192.168.8.0/24"
    sleep -> 30
    off arp.spoof
end

for each _h in $(_hosts)                      # loops
    repeat 3 times
        exec -> net.show                      # run any module command once
        break
    end
end

get net.scan.timeout -> _t                    # read a config value
report -> "assessment.md"                     # write the assessment report
```

Language notes:

- **Statements** — `set`, `get`, `on`/`start`/`run`, `off`/`stop`, `wait for
  <module> [max <secs>]`, `sleep <secs>`, `echo`/`say`/`print`, `show
  <module>`, `report <file>`, `exec <command>`, `if/else/end`, `for each _x
  in <list>`, `repeat N times`, `while <cond>`, `break`, `continue`, and a
  bare `stop` halts the script.
- **Assignments** — `_name -> value`, `_name = value` or `_name >> value`;
  `[...]` builds a list from a property, `$(_name.size)` and `$(_list.size)`
  are the lengths.
- **Interpolation** — `$(...)` resolves live session state: `$(hosts.count)`,
  `$(net.hosts)`, `$(creds.count)`, `$(sessions.count)`, `$(running.list)`,
  `$(iface.ip)`, `$(iface.cidr)`, `$(iface.mac)`, `$(iface.gateway)`,
  `$(config.<module.key>)`; underscore-prefixed paths read script variables.
- **Conditions** — `== != < > <= >=`, `&&`, `||`, `!`, numbers compare
  numerically. `while` loops are capped so a bad condition can never hang the
  script.
- **Modules** — every statement drives the exact same module lifecycle and
  preflight/risk gates as a one-shot invocation, so a script cannot bypass the
  safety checks.

## Configuration

Configuration defaults to `toha3ee.json` (`--config` to override). Per-module
settings are read by each module from its own namespace, e.g.
`report.generate.out`, `switch.portsteal.victim_mac`, `http.harvest.pcap`.

## Stealth

Stealth is always on, in every phase, down to the individual packet. Every
packet-sending module ships a randomized, jittered profile by default; there
is nothing to enable, and disabling it (`set <module>.stealth false`) is
explicitly unsupported by the design intent.

- **Ordering** — probe targets are shuffled (`stealth_shuffle`) so sweeps do
  not walk the subnet in the predictable ascending order scanners are
  fingerprinted by.
- **Pacing** — probes are sent in bursts with per-probe jitter
  (`stealth_jitter`, `stealth_burst`, `stealth_pause`) so traffic is neither
  a flat uniform stream nor a single synchronized flood.
- **ARP** — who-has requests use randomized Ethernet padding
  (`stealth_pad`) instead of the zero-padded frames most scanners emit, and
  the active `net.scan` sweep is collected by a single capture loop while the
  passive listener keeps ingesting traffic.
- **SYN scan** — every probe varies its source port (`stealth_ports`), IP
  TTL and identification (`stealth_ttl`, `stealth_id`), TCP sequence number
  and window, and occasionally clears the DF bit, so the probe stream does
  not resolve to a single tool signature.
- **Fingerprinting** — HTTP probing rotates realistic browser user agents and
  banner grabs are jittered, so service identification does not advertise the
  framework.

Tunables are read per module, e.g. `set net.scan.stealth_jitter 5ms`,
`set service.synscan.stealth_burst 128`. Sequence commands with `--eval` or a
script; one command finishes before the next starts.

## Tests

```sh
go test ./...
```

The suite covers the frame crafters (DHCP, NDP, 802.11, STP/CDP/LLDP), the
store and report renderer, and a registry contract test that pins the full
module catalogue.

CI (`.github/workflows/ci.yml`) runs `gofmt`, `go vet`, `go build` and
`go test -race` on Linux plus tests on Windows and macOS for every push/PR;
[CodeQL](.github/workflows/codeql.yml) runs static security analysis.
Dependency updates are handled by Dependabot.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/Contributing.md](docs/Contributing.md)
and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues via
[SECURITY.md](SECURITY.md) — not as public issues.

## About QYVORA

**QYVORA is an African cybersecurity company — built in Tamale, Ghana, serving the
whole continent.** Its mission is to build Africa's strongest cybersecurity
ecosystem and develop the talent to run it.

Toha3ee is part of a fourteen-framework open-source offensive security toolkit. The
frameworks are unrestricted free software, published for defenders and researchers
across Africa and beyond.

- Company and services: https://qyvora.org
- All frameworks: https://github.com/QYVORA

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## CI pre-push checks

Run these from the repository root before pushing (they mirror `.github/workflows/ci.yml`):

```sh
sudo apt-get update && sudo apt-get install -y --no-install-recommends libpcap-dev gcc
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ./...
```

This framework links libpcap via cgo; the `CGO_ENABLED=0` cross-builds used by the other frameworks do not apply here.

CI needs the repository secret `QYVORA_CI_TOKEN` (fine-grained PAT or GitHub App token with read access to the private QYVORA Go module repositories). Without it the private-module preflight step fails with an explicit message.
