# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Enumeration suite** (`enum`): `smtp.enum`, `snmp.enum`, `ldap.enum`,
  `nfs.enum`, `smb.enum` and `net.ip6sweep`, backed by new protocol clients
  in `internal/netx/snmp`, `internal/netx/ldap` and `internal/netx/rpc`.
- **OSINT expansion** (`osint`): `osint.asn`, `osint.shodan`, `osint.bucket`,
  `osint.wayback`, `osint.github`, `osint.hibp`, `osint.metadata`,
  `osint.dork` and `osint.harvest`.
- **Credential attacks** (`auth`): `auth.spray` (HTTP basic-auth password
  spraying), `auth.brute` (paced SSH password brute-force via
  `golang.org/x/crypto`), `auth.userenum` (SSH username timing enumeration)
  and `auth.asrep` (passive KDC discovery / AS-REP advisory).
- **Advanced scan techniques** (`recon`): `service.protoscan` (protocol scan),
  `service.idle` (idle / zombie scan), TCP-SYN and UDP ping modes for
  `net.ping`, plus decoy-source and IP-fragmentation support in the raw
  scanner (`internal/netx/ports`).
- **CVE live lookups** (`recon`): `cve.suggest` now queries the NVD REST API
  (keyword search) and the cve.org API (by CVE ID) live, with offline-tested
  parsers.
- MIT `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`, a full `docs/` tree, and GitHub Actions CI/CodeQL workflows.

### Changed
- `golang.org/x/crypto` added as a dependency for SSH auth.
- Registry test now pins the complete module catalogue, including the new
  enum/osint/auth/recon modules.

## [0.1.0] - 2026-08-05

### Added
- Initial release: interactive REPL, guided wizard, `--eval` one-shot mode,
  caplet runner and `.toha3ee` scripting engine.
- Module framework with self-registering modules and a
  `Preflight → Run → Verify → Cleanup` lifecycle.
- MITM modules: `arp.spoof`, `dns.spoof`, `dns.rebind`, `dhcp.rogue`,
  `dhcp.starve`, `dhcp6.spoof`, `icmp.redirect`, `ipv6.ra`, `ipv6.ndp`,
  `llmnr.poison`, `wpad.poison`.
- Espionage modules: `http.harvest`, `http.proxy`, `https.proxy`,
  `ssl.strip`, `phish.inject`.
- Recon modules: `net.scan`, `net.ping`, `net.traceroute`, `net.osdetect`,
  `service.synscan`, `service.tcpconnect`, `service.udpscan`,
  `service.finxmas`, `service.ack`, `service.fingerprint`, `service.tls`,
  `web.dir`, `cve.suggest`.
- OSINT modules: `osint.dns`, `osint.whois`, `osint.ct`.
- Auth advisory modules: `default.creds`, `smb.signing`, `smb.kerberoast`,
  `ntlm.relay`.
- Web modules: `web.misconfig`.
- Switch modules: `switch.flood`, `switch.portsteal`, `switch.vlanhop`,
  `switch.cdp`, `switch.stp`.
- Wireless modules: `wlan.scan`, `wlan.deauth`, `wlan.handshake`,
  `wlan.eviltwin`, `wlan.pmkid`, `wlan.beaconflood`, `wlan.karma`.
- Post modules: `report.generate`, `session.replay`, `pcap.export`.
- Stealth engine: randomized, jittered packet profiles applied across every
  packet-sending module.
- Safety lifecycle with cleanup registry, heartbeat watchdog and preflight /
  risk (blast-radius) gates.
- Multi-platform release pipeline (Linux/macOS/Windows) with SHA-256 checksums
  and installers for all three platforms.
