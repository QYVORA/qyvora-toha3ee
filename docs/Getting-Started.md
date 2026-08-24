# Getting started

This guide covers installing, building and running toha3ee for the first time,
plus your first authorised engagement session.

## Prerequisites

| Platform | Requirement |
|----------|-------------|
| **Linux** | libpcap headers (`sudo apt install libpcap-dev`), raw-socket privileges |
| **macOS** | Xcode Command Line Tools (ships libpcap) |
| **Windows** | no libpcap needed (uses gopacket's native pcap bindings) |

Root privileges are required for the raw sockets, packet capture and IP
forwarding most modules depend on. toha3ee escalates to `sudo` automatically
and prompts for the admin password; pass `--no-sudo` (or `TOHA3EE_NO_SUDO=1`)
to run unprivileged for things like `version` or `modules`.

## Install

### One-liner (Linux / macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh
```

Add `sudo` to install system-wide, or `| sh -s -- --prefix ~/.local/bin` for a
custom prefix. The installer:

1. downloads the prebuilt binary for your platform from the latest release,
2. verifies its SHA-256 checksum,
3. installs it and adds the install directory to your PATH,
4. registers the app icon + `.desktop` entry (Linux) / Start Menu shortcut
   (Windows).

Install options:

| Flag / env | Meaning |
|------------|---------|
| `TOHA3EE_VERSION=<tag>` | pin a specific release instead of latest |
| `--prefix <dir>` | install directory |
| `--no-path` | skip editing your shell rc |
| `--from-source` | build from the checkout instead of downloading |

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\toha3ee\bin` and updates your user PATH.

### From source

```sh
git clone https://github.com/QYVORA/qyvora-toha3ee.git
cd toha3ee

# Debian/Ubuntu prerequisite
sudo apt install libpcap-dev

make install          # ~/.local/bin (or /usr/local/bin as root)
# or just
go build ./cmd/toha3ee
```

> **Linux note:** gopacket's capture engine needs libpcap at runtime. If the
> build can't find the headers, install `libpcap-dev` (apt/dnf) and retry.

### Uninstall

Delete the binary and the PATH line the installer added to your shell rc. On
Windows remove `%LOCALAPPDATA%\Programs\toha3ee`.

### Updating / reinstalling

See [Updating toha3ee](Update.md) for upgrade, reinstall and rollback
instructions. After a source install the man pages are available too:

```sh
man toha3ee        # console, commands, modules and options
man scripting      # the .toha3ee scripting language
man 7 security     # responsible use and safety controls
```

## Verify the install

```sh
toha3ee --no-sudo version
toha3ee --no-sudo modules        # full module catalogue
```

## First session

### 1. Discover hosts

```sh
sudo toha3ee --iface eth0
```

Drop into the console, then run a subnet sweep:

```
toha3eeλ> on net.scan
```

`net.scan` ARP-sweeps your subnet and populates the host inventory. The status
HUD above the prompt keeps counting live hosts, ports, credentials and events
while it runs.

### 2. Inspect what was found

```
toha3eeλ> net.show         # discovered hosts (IP, MAC, vendor, OS guess)
toha3eeλ> net.profile      # ranked attack vectors for the target set
```

### 3. Profile services

```
toha3eeλ> on service.synscan       # half-open SYN scan of common ports
toha3eeλ> on service.fingerprint   # banner grabs + HTTP fingerprinting
toha3eeλ> on service.tls           # TLS handshake probe (HTTPS services)
```

### 4. Generate a report

```
toha3eeλ> exec -> report.generate
```

This writes `toha3ee-report.md` in the current directory — hosts, credentials,
sessions and the event log from everything the session captured.

## Running without a live interface

For validation, dry runs and CI you can use a `.toha3ee` script without sending
a single packet:

```sh
toha3ee --no-sudo build scripts/full-pipeline.toha3ee
```

`build` validates the script and prints the plan. Execute it for real with:

```sh
sudo toha3ee script scripts/full-pipeline.toha3ee
```

## Lab setup recommendation

- Use a dedicated **Kali Linux VM** or container.
- Test against a disposable **isolated lab subnet** (a second VM, a container
  network, or a router you own). Do not run against the internet-facing
  interface of a shared network.
- Keep a snapshot of every VM so you can roll back a botched DHCP/WLAN test.
- Monitor with your own tools (Wireshark/tcpdump on the attacker box) so you
  can confirm exactly what toha3ee emits.

## Next steps

- [User guide](User-Guide.md) — the console and command reference
- [Security & responsible use](Security.md) — read this before your first
  real engagement
