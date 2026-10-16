# CLI Reference

`toha3ee` is a one-shot command-line tool. Every command follows the
shared QYVORA tier grammar:

```
toha3ee <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon` (discovery, collection, enumeration and
analysis), `exploit` (active testing and exploitation), or `report`
(findings, evidence and reports). Running `toha3ee` with no
arguments prints this help. Every pre-tier command remains available as
a hidden alias, so existing scripts keep working.

Exit codes: `0` success &middot; `1` runtime failure &middot; `2` usage error
&middot; `3` unsupported target &middot; `130` interrupted.

## recon

Discovery, collection, enumeration and analysis modules.

| Command | Purpose |
|---------|---------|
| `toha3ee recon cve` | cve modules |
| `toha3ee recon ldap` | ldap modules |
| `toha3ee recon net` | net modules |
| `toha3ee recon nfs` | nfs modules |
| `toha3ee recon osint` | osint modules |
| `toha3ee recon service` | service modules |
| `toha3ee recon smb` | smb modules |
| `toha3ee recon smtp` | smtp modules |
| `toha3ee recon snmp` | snmp modules |
| `toha3ee recon web` | web modules |

## exploit

Active-testing and exploitation modules.

| Command | Purpose |
|---------|---------|
| `toha3ee exploit arp` | arp modules |
| `toha3ee exploit auth` | auth modules |
| `toha3ee exploit default` | default modules |
| `toha3ee exploit dhcp` | dhcp modules |
| `toha3ee exploit dhcp6` | dhcp6 modules |
| `toha3ee exploit dns` | dns modules |
| `toha3ee exploit http` | http modules |
| `toha3ee exploit https` | https modules |
| `toha3ee exploit icmp` | icmp modules |
| `toha3ee exploit ipv6` | ipv6 modules |
| `toha3ee exploit llmnr` | llmnr modules |
| `toha3ee exploit ntlm` | ntlm modules |
| `toha3ee exploit phish` | phish modules |
| `toha3ee exploit smb` | smb modules |
| `toha3ee exploit ssl` | ssl modules |
| `toha3ee exploit switch` | switch modules |
| `toha3ee exploit web` | web modules |
| `toha3ee exploit wlan` | wlan modules |
| `toha3ee exploit wpad` | wpad modules |

## report

Findings, evidence and report rendering.

| Command | Purpose |
|---------|---------|
| `toha3ee report pcap` | pcap modules |
| `toha3ee report report` | report modules |
| `toha3ee report session` | session modules |

## Utilities

| Command | Purpose |
|---------|---------|
| `toha3ee build` | validate a .toha3ee script and print a dry-run plan |
| `toha3ee capabilities print the machine-readable capability contract` | — |
| `toha3ee eval` | run a one-shot command sequence and exit |
| `toha3ee modules` | list all registered modules |
| `toha3ee run` | execute a script or caplet non-interactively |
| `toha3ee script` | execute a .toha3ee script file |
| `toha3ee wizard` | guided attack setup |

## Global flags

| Flag | Purpose |
|------|---------|
| `--config string   config file path (default toha3ee.json)` | — |
| `--eval string     run a one-shot command sequence and exit, e.g. "net.scan; net.show"` | — |
| `--events string   emit JSONL event stream to stdout, stderr, or a file path (e.g. --events session.jsonl)` | — |
| `-h, --help            help for toha3ee` | — |
| `--iface string    network interface to attack from` | — |
| `--no-color        disable colored output` | — |
| `--no-sudo         do not auto-escalate to root via sudo` | — |
| `-o, --output string   output format: terminal, json, markdown, yaml, html (yaml/html for capabilities and report)` | — |
| `-q, --quiet           suppress informational status output` | — |
| `-v, --verbose         verbose logging` | — |

