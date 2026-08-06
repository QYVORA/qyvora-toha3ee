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

## Build

Requires Go 1.26+ and libpcap.

```sh
# Debian/Ubuntu
sudo apt install libpcap-dev

# then
go build ./cmd/toha3ee
```

## Quick start

```sh
# Interactive REPL
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
| `cmd/toha3ee` | CLI: REPL, wizard, `--eval`, caplet runner |
| `internal/attacks/` | all attack modules by category |
| `internal/netx/` | protocol primitives (ARP, DHCP, DNS, NDP, 802.11, SMB/NTLM, proxy, …) |
| `internal/hijack` | HTTP/HTTPS MITM proxy and credential/session interception |
| `internal/phish` | captive-portal phishing and login-page clones |
| `internal/store` | shared data store and event bus |
| `internal/safety` | cleanup/heartbeat lifecycle |
| `internal/config` | YAML/JSON config loading |
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

## REPL

```
> modules                  # list everything
> net.scan                 # run a module
> net.show
> run caplets/basic.cap    # run a caplet script
> help
> exit
```

Sessions keep captured data across module runs; `report.generate` renders a
Markdown assessment from the in-memory store.

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
