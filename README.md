# toha3ee

A network exploitation & MITM framework written in Go. It is a research and
authorised-penetration-testing tool that demonstrates classic layer-2/3/7
attacks: ARP/DHCP/DNS/IPv6 poisoning, inline HTTP/HTTPS interception, wireless
attacks and switch-layer exploitation — all driven from an interactive REPL,
a guided wizard, or one-shot command sequences.

> **WARNING**: toha3ee actively redirects, poisons, decrypts and intercepts
> network traffic. Use it **only on networks you own or are explicitly
> authorised to test**. Running these modules against third parties is illegal
> in most jurisdictions.

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
| `cmd/toha3ee` | CLI: console, wizard, `--eval`, caplet runner |
| `internal/ui` | console rendering: banner, palette, sections, tables, status glyphs |
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
| **auth** | `default.creds`, `ntlm.relay`, `smb.signing`, `smb.kerberoast` |
| **recon** | `net.scan`, `service.synscan`, `service.fingerprint`, `cve.suggest` |
| **switch** | `switch.flood`, `switch.portsteal`, `switch.vlanhop`, `switch.cdp`, `switch.stp` |
| **wireless** | `wlan.scan`, `wlan.deauth`, `wlan.handshake`, `wlan.eviltwin`, `wlan.pmkid`, `wlan.beaconflood`, `wlan.karma` |
| **post** | `report.generate`, `session.replay`, `pcap.export` |

## Console

Bare `toha3ee` (or `toha3ee interactive`) opens a bettercap/metasploit-style
console: the `@@@` banner, a `toha3ee> ` prompt with tab-completion, and
grouped, aligned output in a green/amber/white palette (red is reserved for
hard errors). Every command's output is sectioned (`─── modules ───`), tables
are column-aligned (colors are ignored when computing alignment), and module
messages are colorized centrally, so every module gets consistent status
glyphs with no per-module work. Output falls back to plain text automatically
when piped.

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
| `[OK]` | verified / passed (green) |

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

## Configuration

Configuration defaults to `toha3ee.json` (`--config` to override). Per-module
settings are read by each module from its own namespace, e.g.
`report.generate.out`, `switch.portsteal.victim_mac`, `http.harvest.pcap`.

## Tests

```sh
go test ./...
```

The suite covers the frame crafters (DHCP, NDP, 802.11, STP/CDP/LLDP), the
store and report renderer, and a registry contract test that pins the full
module catalogue.
