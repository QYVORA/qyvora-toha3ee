# User guide

This guide covers the interactive console, the guided wizard, caplets, and the
everyday workflows for running an authorised engagement with toha3ee.

## Modes of operation

| Mode | Command | Use when |
|------|---------|----------|
| **Interactive console** | `sudo toha3ee --iface eth0` | exploring, ad-hoc attacks, live monitoring |
| **Wizard** | `sudo toha3ee wizard` | you want a guided, risk-gated walkthrough |
| **One-shot eval** | `sudo toha3ee --eval "net.scan; net.show"` | a fixed sequence in scripts/CI |
| **Caplet** | `sudo toha3ee run caplets/mitm-arp.caplet` | a reusable attack recipe |
| **Script** | `sudo toha3ee script scripts/full-pipeline.toha3ee` | a full programmatic engagement |
| **Dry run** | `toha3ee --no-sudo build scripts/x.toha3ee` | validate a script, print the plan, no packets |

## The interactive console

Bare `toha3ee` (or `toha3ee interactive`) opens a bettercap/metasploit-style
console. Above the prompt sits a persistent **status HUD** showing the
interface, running modules and live host / port / credential / event counts.
The prompt stays visible and live while any module runs, so you can issue new
commands mid-attack.

### Status glyphs

| Glyph | Meaning |
|-------|---------|
| `[*]` | info / running (white) |
| `[+]` | success (green) |
| `[!]` | warning (amber) |
| `[>]` | system (bold white) |
| `[-]` | neutral (dim) |
| `[x]` | hard error (red) |
| `[OK]` | verified / passed (green) |

### Core commands

| Command | Description |
|---------|-------------|
| `on <module> [key value ...]` | start a module, e.g. `on arp.spoof` |
| `off <module>` | stop a running module |
| `status` | list running modules and recently completed module runs |
| `set <module.key> <value>` | set a config value, e.g. `set arp.spoof.targets 192.168.8.0/24` |
| `get <module.key>` | show a config value |
| `config` | dump the current configuration |
| `modules [category]` | list all modules (optionally filtered) |
| `show <module>` | module metadata + preflight summary |
| `quit` | stop everything, restore the network, exit |

### Recon commands

| Command | Description |
|---------|-------------|
| `net.show` | discovered hosts (IP, MAC, vendor, OS guess) |
| `net.recon` | start passive HTTP/credential sniffing (`http.harvest`) |
| `net.profile` | build the network profile |
| `vectors.show` | ranked attack vectors for the current profile |

### Loot commands

| Command | Description |
|---------|-------------|
| `events.show [n]` | recent framework events |
| `creds.show` | captured credentials (source-tracked) |
| `sessions.show` | captured HTTP sessions |
| `hijack.dump` | dump captured sessions and cookies |
| `phish.list` | available phishing templates |
| `phish.serve <template>` | serve a standalone phishing page |
| `session.hijack` | manage cookie injection |

### Automation commands

| Command | Description |
|---------|-------------|
| `wizard` | guided attack setup |
| `report <file>` | write a session report |
| `run.caplet <file>` | execute a caplet |
| `sleep <seconds>` | pause (used by caplets/scripts) |
| `script <file.toha3ee>` | run a `.toha3ee` script |
| `build <file.toha3ee>` | dry-run validate a script |

## Machine-readable event stream

Every invocation can emit a JSONL event stream that agents and CI can consume
line-by-line, without scraping the terminal:

```
$ sudo toha3ee --eval "net.scan; net.show" --events session.jsonl
```

`--events` accepts `stdout`, `stderr`, or a file path. A file is created or
truncated with mode 0600. Each line is one self-describing event:

```
{"schema_version":"1.0","timestamp":"...","execution_id":"toha3ee-...",
 "framework":"toha3ee","level":"info","event":"run.started",
 "data":{"iface":"eth0","version":"0.1.0"}}
```

Events include the run lifecycle (`run.started`, `run.completed`), module
lifecycle (`module.started`, `module.stopped`, `module.completed`,
`module.failed`), findings
(`host.discovered`, `credential.discovered`, `session.captured`,
`arp.spoof.started/stopped`), `report.generated`, and `error`. Every module
that finishes emits `module.completed` carrying the structured run record
(`id`, `module`, `status` of `success|failed|stopped`, `summary`, and
`EvidenceRef` with `credentials:`/`sessions:` deltas), which is also how the
`status` command's completed-runs table and the report's `## Module Runs`
section stay in sync. The schema is
identical across the QYVORA frameworks so one consumer works for all of them.

## Example session

```
$ sudo toha3ee --iface eth0

# discover the subnet
toha3eeλ> on net.scan
[*] net.scan: preflight OK
[*] net.scan: sweeping 192.168.8.0/24 ...
toha3eeλ> net.show

# find open services and grab banners
toha3eeλ> on service.synscan
toha3eeλ> on service.fingerprint
toha3eeλ> on service.tls

# enumerate protocols
toha3eeλ> on service.protoscan
toha3eeλ> on smb.enum
toha3eeλ> on snmp.enum

# check for credential exposure
toha3eeλ> on auth.spray
toha3eeλ> on auth.asrep

# collect + report
toha3eeλ> report engagement-1.md
toha3eeλ> quit
```

## The wizard

`wizard` walks you through module selection with **risk gates**: before a
High/Critical module runs you are shown its blast radius and must confirm.
The risk model is described in [Security & responsible use](Security.md).

## Caplets

A caplet is a short sequence of console commands with a `.caplet` extension.
Caplets included with the project:

| Caplet | Purpose |
|--------|---------|
| `basic-recon.caplet` | subnet sweep → passive credential sniffing → show results |
| `mitm-arp.caplet` | full-duplex ARP spoof between gateway and targets |
| `ntlm-capture.caplet` | LLMNR/NBNS poisoning to capture NTLMv2 hashes |
| `phishing.caplet` | captive-portal phishing setup |
| `wireless-scan.caplet` | passive 802.11 scan |

Run one from the console (`run.caplet caplets/mitm-arp.caplet`), via the CLI
(`toha3ee run caplets/mitm-arp.caplet`), or combine several in a `.toha3ee`
script.

## Capability check: what actually works

- **ARP spoofing** works on any IPv4 Ethernet network where the attacker is
  on the same L2 segment as the victims.
- **DHCP rogue/starve** needs an active DHCP environment; on a network with
  DHCP snooping enabled on the switch, rogue DHCP replies are dropped.
- **IPv6 attacks** (RA/NDP) need IPv6 actually in use on the link.
- **Wireless modules** need the interface in monitor mode
  (`iw dev wlan0 set type monitor`).
- **HTTPS interception** requires clients to trust the framework CA; on a
  fresh system you must install `toha3ee-ca.pem` into the trust store of the
  test machine.

## HUD variables you can read in scripts

- `$(hosts.count)`, `$(net.hosts)` — host inventory
- `$(creds.count)` — captured credential count
- `$(sessions.count)` — captured session count
- `$(running.list)` — running modules
- `$(iface.ip)`, `$(iface.cidr)`, `$(iface.mac)`, `$(iface.gateway)` — interface facts
- `$(config.<module.key>)` — any config value

See [Scripting reference](Scripting.md) for the full language.

## Next steps

- [Scripting reference](Scripting.md) — automate entire engagements
- [Module reference](Module-Reference.md) — every module and its settings
- [Reporting](Reporting.md) — interpreting the assessment report
