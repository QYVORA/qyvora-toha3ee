# toha3ee

![Build](https://img.shields.io/github/actions/workflow/status/qyvora/qyvora-toha3ee/ci.yml?branch=main&label=CI)
![Go Version](https://img.shields.io/github/go-mod/go-version/qyvora/qyvora-toha3ee)
![License](https://img.shields.io/github/license/qyvora/qyvora-toha3ee)
![Release](https://img.shields.io/github/v/release/qyvora/qyvora-toha3ee?sort=semver)
[![Documentation](https://img.shields.io/badge/docs-docs%2F-blue)](/docs)

A network exploitation & MITM framework written in Go. It is a research and
authorised-penetration-testing tool that demonstrates classic layer-2/3/7
attacks: ARP/DHCP/DNS/IPv6 poisoning, inline HTTP/HTTPS interception, wireless
attacks and switch-layer exploitation — all driven from an interactive REPL,
a guided wizard, or one-shot command sequences.

> **WARNING**: toha3ee actively redirects, poisons, decrypts and intercepts
> network traffic. Use it **only on networks you own or are explicitly
> authorised to test**. Running these modules against third parties is illegal
> in most jurisdictions. Read [`docs/security.md`](docs/security.md) first.

## Documentation

- **User** — [Getting started](docs/getting-started.md) · [User guide](docs/user-guide.md) · [Scripting](docs/scripting.md) · [Configuration](docs/configuration.md) · [FAQ](docs/faq.md)
- **Reference** — [Module reference](docs/module-reference.md) (all 73 modules) · [Reporting](docs/reporting.md)
- **Developer** — [Architecture](docs/architecture.md) · [Contributing](docs/contributing.md) · [Changelog](CHANGELOG.md)
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

```sh
# Interactive console (bare command drops straight in)
sudo ./toha3ee --iface eth0

# Interactive console (explicit subcommand)
sudo ./toha3ee interactive --iface eth0

# Guided wizard
sudo ./toha3ee wizard --iface eth0

# One-shot: scan the subnet, then show what was found
sudo ./toha3ee --eval "net.scan; net.show" --iface eth0

# Non-interactive caplet script
sudo ./toha3ee run --iface eth0 caplets/basic.cap

# Dry-run a .toha3ee script (validates it, prints the plan, sends no packets)
./toha3ee --no-sudo build scripts/full-pipeline.toha3ee

# Execute a .toha3ee script non-interactively
sudo ./toha3ee script --iface eth0 scripts/full-pipeline.toha3ee
```

Most attack modules require root (raw sockets, packet capture and IP
forwarding). Run as root or with `CAP_NET_ADMIN`/`CAP_NET_RAW` where possible.
Add `--no-color` to disable colored output, `-v` for verbose logging.

The tool runs with admin privileges **by default**: on Linux/macOS it
re-executes itself under `sudo` and prompts for the admin (root) password on
every invocation. Pass `--no-sudo` (or set `TOHA3EE_NO_SUDO=1`) to run
unprivileged, e.g. for a quick `toha3ee --no-sudo version`.

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
| `cmd/toha3ee` | CLI: console, wizard, `--eval`, caplet runner, `script`/`build` |
| `internal/ui` | console rendering: banner, palette, sections, tables, status glyphs, HUD |
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

## Console

Bare `toha3ee` (or `toha3ee interactive`) opens a bettercap/metasploit-style
console: the `@@@` banner, a **red-accented `toha3ee > ` prompt** with
tab-completion, and a persistent one-line **status HUD** above the prompt that
shows the interface, running modules and live host/port/credential/event
counts. Output is grouped and aligned in a green/amber/white palette — red is
used deliberately, for the prompt accent, hard errors (`[x]`), the HUD edge
mark and critical-risk modules (high risk is amber). Every command's output is
sectioned (`─── modules ───`), tables are column-aligned (colors are ignored
when computing alignment), and module messages are colorized centrally, so
every module gets consistent status glyphs with no per-module work. Output
falls back to plain text automatically when piped, and the prompt stays
visible and live while any module runs, like bettercap.

```
$ sudo ./toha3ee --iface eth0
@@@@@@@@
    @@@@@@@@@@@@@
    @@@@@@@@     @@@@@@@
  @@@@@@@@           @@@@@@@@
  @@@@@@@@                 @@@@@@@@
 @@@@@@@         @               @@@@@@@
 @@@@@@@@        @@@@@@@@@              @@@@@@@
 @@@@@@@@         @@@   @                     @@@@@@@
  @@@@@@@            @@       @@@@@@@@@@              @@@@@@@
  @@@@@@    @@        @     @@@@@@@@@@@@@@@@@@             @@@@@@
  @@@        @@@   @@@@@@@  @@@@@@@@@@@@@@@@@@@@@@            @@@
  @@@         @@@@@   @    @@@@@@@@@@@@@@@@@@@@@@@            @@@
  @@@          @@@@@@  @   @@@@@@@@@@@@@@@@@@ @@@             @@@
  @@@          @@@@@@   @ @@@@@@@@@@@@@@@@@   @@@             @@@
  @@@           @@@@@@    @@@@@@@@@@@@@@@@@@@@@@              @@@
  @@@              @@@@@  @@@@@@@@@@@@@@@    @@@              @@@
  @@@               @@@@@  @@@@@@@@@@@@@@   @@@               @@@
  @@@                 @@@    @@@@@@@@@@@@@ @@@@               @@@
  @@@               @@  @@@@  @@@@@   @@@@@@@@@               @@@
  @@@            @@@@@@@@@@@@@  @@@@@@    @@@                 @@@
  @@@        @@@@@@@@@@@@@@@@@@@  @@@@@@@   @@@               @@@
  @@@       @@@@@@@@@@@@@@@@@@@@@@@     @@@ @@@@@@            @@@
  @@@      @@@@@@@@@@@@@@@@@@@@@@   @@@   @@@@@@@@@@          @@@
  @@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@          @@@
  @@@     @@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@ @@@@@@@@@         @@@
  @@@    @@@@@@@@@@@@@@@    @@@@@@@@@@@@@  @@@@@@@@@@@        @@@
  @@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@    @@@@@
   @@@@@@@    @@@@@@@@@@@@@@@@@@@@@@@@  @@@@  @@@@@@@   @@@@@@@@
     @@@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@   @@@@@@@
      @@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@
       @@@@@@@    @@@@@@@@@@@@@@@@@@@    @@@@@@@
         @@@@@@@    @@@@@@@@@@@@@    @@@@@@@
           @@@@@@@    @@@@@@@    @@@@@@
               @@@@@@        @@@@@@@
                 @@@@@@@@ @@@@@@@
                     @@@@@@@@
                        @@@

network exploitation & MITM framework

  [>] iface wlan0 (10.135.199.31, 8c:c8:4b:30:bf:91)
  [>] v 0.1.0
type 'help' for commands, 'modules' for the catalogue, 'quit' to exit

[*] session ready. type 'help' for commands.
toha3ee> help
```

Status glyphs follow bettercap's convention:

| Glyph | Meaning |
|-------|---------|
| `[*]` | info / running (white) |
| `[+]` | success (green) |
| `[!]` | warning (amber) |
| `[>]` | system (bold white) |
| `[-]` | neutral (dim) |
| `[x]` | hard error (red) |
| `[OK]` | verified / passed (green) |

The red block `▮` at the left edge of the HUD marks the status strip; the HUD
is reprinted after every command so counts stay current without extra typing.

Example session:

```
toha3ee> modules recon        # module catalogue filtered by category
toha3ee> on net.scan          # run a module (preflight checks shown first)
toha3ee> net.show             # discovered hosts
toha3ee> net.profile          # profile + ranked attack vectors
toha3ee> help                 # grouped command reference
toha3ee> quit
```

`set <module.key> <value>` stores per-module settings (module IDs are dotted,
so the split happens on the last dot: `set arp.spoof.targets 10.0.0.5`);
`config` dumps everything set so far. Sessions keep captured data across
module runs; `report.generate` renders a Markdown assessment from the
in-memory store.

## Scripting

`.toha3ee` files drive the full recon → exploit → report pipeline with a
Python-like language that reads like English. Execute one with `toha3ee script
<file>`, from the REPL with `script <file>`, or run any `.toha3ee` file with
`run <file>`. `toha3ee build <file>` (or REPL `build <file>`) validates the
file and prints a dry-run plan without touching the network. `scripts/full-
pipeline.toha3ee` is a working end-to-end example.

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
        exec -> net.show                      # run any REPL command once
        break
    end
end

get net.scan.timeout -> _t                    # read a config value
report -> "assessment.md"                     # write the session report
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
  preflight/risk gates as the REPL, so a script cannot do anything the console
  cannot.

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
`set service.synscan.stealth_burst 128`. The REPL prompt stays visible and
live while any module runs, like bettercap.

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

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/contributing.md](docs/contributing.md)
and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues via
[SECURITY.md](SECURITY.md) — not as public issues.
