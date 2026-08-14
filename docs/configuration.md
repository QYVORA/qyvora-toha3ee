# Configuration

toha3ee reads a single JSON configuration document, defaulting to
`toha3ee.json` in the current directory (override with `--config <path>`).
If the file does not exist, sane defaults are used and the file is created on
the first save.

## Setting values

```sh
# From the console
toha3eeλ> set arp.spoof.targets 192.168.8.0/24
toha3eeλ> get arp.spoof.targets
toha3eeλ> config          # dump everything

# From a .toha3ee script
set net.scan.targets -> "192.168.8.0/24"
get net.scan.timeout -> _t
```

Because module IDs are dotted, `set` splits on the **last** dot:
`set arp.spoof.targets 10.0.0.5` sets key `targets` on module `arp.spoof`.
An empty value removes the key.

## The config document

```json
{
  "iface": "eth0",
  "sniff_output": "capture.pcap",
  "ca_file": "toha3ee-ca.pem",
  "ca_private_key": "toha3ee-ca.key",
  "proxy_http_addr": ":8080",
  "proxy_https_addr": ":8443",
  "arp_refresh": "2s",
  "dns_upstream": "",
  "targets": ["192.168.8.0/24"],
  "settings": {
    "report.generate": { "out": "assessment.md" }
  },
  "confirmed_risks": {
    "arp.spoof": true
  }
}
```

### Top-level keys

| Key | Default | Meaning |
|-----|---------|---------|
| `iface` | `eth0` | primary network interface |
| `sniff_output` | `capture.pcap` | capture file used by `net.sniff`/`pcap.export` |
| `ca_file` / `ca_private_key` | `toha3ee-ca.pem` / `.key` | framework CA for HTTPS MITM |
| `proxy_http_addr` | `:8080` | HTTP MITM proxy listen address |
| `proxy_https_addr` | `:8443` | HTTPS CONNECT MITM proxy listen address |
| `arp_refresh` | `2s` | ARP spoof refresh interval |
| `dns_upstream` | *empty* | optional upstream resolver for DNS spoof forwarding |
| `targets` | *empty* | default target list used by L2/L3 modules |
| `settings` | *empty* | per-module key/value tuning knobs |
| `confirmed_risks` | *empty* | High/Critical modules the user already approved |

## Per-module settings

Modules read their knobs through `Config.Get*`, so **any** setting a module
consults can be overridden with `set <module.key> <value>`. Examples:

```sh
toha3eeλ> set report.generate.out assessment.md
toha3eeλ> set service.synscan.stealth_burst 128
toha3eeλ> set net.scan.stealth_jitter 5ms
toha3eeλ> set auth.spray.users admin,root
toha3eeλ> set cve.suggest.limit 20
```

Type-aware accessors (`GetBool`, `GetInt`, `GetDuration`) are used by modules,
so an invalid value silently falls back to the module's default rather than
crashing.

## Environment variables

| Variable | Meaning |
|----------|---------|
| `TOHA3EE_NO_SUDO=1` | skip the automatic sudo elevation |
| `TOHA3EE_VERSION=<tag>` | installer: pin a release version |

## Risk confirmation

High/Critical modules require confirmation before first use. Confirm from the
console (or a script) with:

```text
set <module>.risk_confirm true
```

Confirmations are persisted in `confirmed_risks`, so you are not re-prompted
every time in a later session. The guided wizard and `.toha3ee` scripts
confirm high/critical modules automatically on launch.

## Next steps

- [Architecture](architecture.md) — how modules read configuration
- [Module reference](module-reference.md) — the settings each module exposes
