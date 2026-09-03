# Module reference

73 modules are registered across 10 categories. This reference documents every
module, its risk, targets and the configuration keys it reads. Run
`toha3ee modules` for the always-current catalogue.

**How to read the tables:**

- **Risk** — the framework's severity classification (see
  [Security & responsible use](Security.md)).
- **Targets** — what the module operates on: `host`, `gateway`, `subnet`,
  `ap`, `domain`, `service`.
- **Settings** — `set <module.key> <value>` keys the module reads; defaults
  apply when unset.

---

## auth

Credential discovery and authentication attacks.

### default.creds
*medium — targets: host, service*
Test bundled default credentials against device web logins (basic auth).

| Setting | Default | Meaning |
|---------|---------|---------|
| `default.creds.timeout` | (module) | per-target HTTP timeout |

### smb.signing
*info — targets: host, service*
Probe SMB (445) servers for whether message signing is enabled or required.

| Setting | Default | Meaning |
|---------|---------|---------|
| `smb.signing.port` | `445` | SMB port |
| `smb.signing.timeout` | (module) | probe timeout |

### smb.kerberoast
*info — targets: host*
Spot likely domain controllers and report whether Kerberoasting (SPN hash
extraction) is a viable next step. Advisory only.

### ntlm.relay
*critical — targets: host*
Challenge NTLM clients and capture NTLMv2 hashes for offline cracking.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ntlm.relay.port` | (module) | listener port |
| `ntlm.relay.domain` | (module) | realm/domain to advertise |

### auth.spray
*medium — targets: host, service*
Password spraying: one password across many usernames on HTTP basic-auth
portals.

| Setting | Default | Meaning |
|---------|---------|---------|
| `auth.spray.users` | `admin,root,user,administrator,test` | username list (comma/space separated) |
| `auth.spray.wordlist` | *same as users* | path to a wordlist file (overrides `users`) |
| `auth.spray.password` | (module) | the single password to spray |
| `auth.spray.delay` | (module) | delay between attempts |
| `auth.spray.timeout` | (module) | per-attempt HTTP timeout |

### auth.brute
*medium — targets: host, service*
Paced SSH password brute-force against hosts with port 22 open. Connection-level
errors abort to avoid account lockouts.

| Setting | Default | Meaning |
|---------|---------|---------|
| `auth.brute.delay` | (module) | delay between password attempts |
| `auth.brute.timeout` | (module) | per-connection timeout |

### auth.userenum
*info — targets: host, service*
SSH username enumeration by timing the server's password-auth response
(SHA256 password-hash delay; CVE-2016-6210 pattern).

| Setting | Default | Meaning |
|---------|---------|---------|
| `auth.userenum.probes` | `2` | probes per username |
| `auth.userenum.threshold` | `300ms` | timing threshold for "valid" |
| `auth.userenum.timeout` | (module) | per-connection timeout |

### auth.asrep
*info — targets: subnet*
Locate Kerberos KDCs and advise whether AS-REP roasting of pre-auth-disabled
accounts applies. Passive discovery; registers `kdcs` state.

---

## enum

Protocol-aware enumeration. The `enum` category landed alongside new protocol
clients in `internal/netx/snmp`, `internal/netx/ldap` and `internal/netx/rpc`.

### smtp.enum
*info — targets: host, service*
Enumerate mail users via SMTP `VRFY`/`EXPN`/`RCPT TO` and test for open-relay.

| Setting | Default | Meaning |
|---------|---------|---------|
| `smtp.enum.users` | (module) | usernames to probe |
| `smtp.enum.timeout` | (module) | connection timeout |

### snmp.enum
*info — targets: host, service*
SNMP community-string probing and MIB walk for system info, interfaces and
routes.

| Setting | Default | Meaning |
|---------|---------|---------|
| `snmp.enum.communities` | `CommonCommunities` | community strings to try |
| `snmp.enum.port` | `161` | SNMP UDP port |
| `snmp.enum.timeout` | (module) | timeout |

### ldap.enum
*info — targets: host, service*
Test LDAP servers for anonymous/simple binds and enumerate naming contexts
and directory objects.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ldap.enum.port` | `389` | LDAP port |
| `ldap.enum.timeout` | (module) | timeout |

### nfs.enum
*info — targets: host, service*
Enumerate NFS exports via rpcbind/MOUNT protocol and probe NFS service
presence.

| Setting | Default | Meaning |
|---------|---------|---------|
| `nfs.enum.timeout` | (module) | timeout |

### smb.enum
*info — targets: host, service*
Probe SMB servers for signing policy, dialect support and null-session
exposure.

| Setting | Default | Meaning |
|---------|---------|---------|
| `smb.enum.timeout` | (module) | timeout |

### net.ip6sweep
*low — targets: subnet*
Discover IPv6 hosts on the local link via Neighbor Discovery (NS/NA) sweep.

| Setting | Default | Meaning |
|---------|---------|---------|
| `net.ip6sweep.scanbits` | (module) | how many bits of the interface ID to scan |
| `net.ip6sweep.timeout` | (module) | sweep timeout |

---

## espionage

Traffic interception and credential harvesting.

### http.harvest
*medium — targets: subnet*
Passive capture of plaintext HTTP credentials and sessions. Requires
`arp.spoof` to redirect traffic through this host.

| Setting | Default | Meaning |
|---------|---------|---------|
| `http.harvest.pcap` | `toha3ee.pcap` | capture file (used by `pcap.export`) |

### http.proxy
*high — targets: host, service*
Inline HTTP MITM proxy: harvest credentials/sessions, inject JS and rewrite
pages.

| Setting | Default | Meaning |
|---------|---------|---------|
| `http.proxy.listen` | `:8080` (config) | proxy listen address |
| `http.proxy.javascript` | *empty* | JS snippet to inject into responses |
| `http.proxy.sslstrip` | (module) | rewrite `https://` to `http://` |

### https.proxy
*high — targets: host, service*
HTTPS MITM via a framework CA: decrypt, harvest and rewrite TLS traffic.
Clients must trust the framework CA.

| Setting | Default | Meaning |
|---------|---------|---------|
| `https.proxy.ca_cert` | `toha3ee-ca.pem` (config) | framework CA cert |
| `https.proxy.ca_key` | `toha3ee-ca.key` (config) | framework CA key |

### ssl.strip
*high — targets: host, service*
SSL strip + HSTS hijack: strip `Strict-Transport-Security`, drop HPKP and
rewrite `https://` links to `http://` through the proxy.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ssl.strip.sslstrip` | (module) | toggles the strip behaviour |

### phish.inject
*high — targets: host, service*
Rewrite login pages on real sites with embedded phishing templates and harvest
submitted credentials.

| Setting | Default | Meaning |
|---------|---------|---------|
| `phish.inject.brand` | (module) | which template brand to use |
| `phish.inject.capture_port` | (module) | credential capture listener |
| `phish.inject.domains` | (module) | domains to rewrite |

---

## mitm

Layer-2/3 man-in-the-middle attacks. Most require you to be on the same L2
segment and, for relayed traffic, IP forwarding.

### arp.spoof
*medium — targets: host, gateway*
Full-duplex ARP spoofing between the gateway and victim hosts — traffic relays
through this host.

| Setting | Default | Meaning |
|---------|---------|---------|
| `arp.spoof.targets` | config `targets` | victim IPs/CIDRs |
| `arp.spoof.refresh` | `2s` (config `arp_refresh`) | refresh interval |
| `arp.spoof.internal` | (module) | also spoof between internal hosts |

### dns.spoof
*medium — targets: subnet, service*
Spoof DNS answers for targeted domains while forwarding everything else
upstream.

| Setting | Default | Meaning |
|---------|---------|---------|
| `dns.spoof.domains` | (module) | domains to spoof |
| `dns.spoof.all` | (module) | answer every query |
| `dns.spoof.target` | (module) | IP to answer with (default: this host) |
| `dns.spoof.upstream` | config `dns_upstream` | upstream resolver for forwarded queries |

### dns.rebind
*high — targets: subnet, service*
DNS rebinding: alternate answers for a domain between this host and the
internal target to bypass same-origin policy.

| Setting | Default | Meaning |
|---------|---------|---------|
| `dns.rebind.domains` | (module) | domains to rebind |
| `dns.rebind.target_ip` | (module) | internal target to answer alternately |
| `dns.rebind.upstream` | (module) | upstream resolver |

### dhcp.rogue
*high — targets: subnet*
Rogue DHCP server: offer this host as gateway+DNS to every DHCP client to
capture their traffic. Disabled by switch DHCP snooping.

### dhcp.starve
*high — targets: subnet*
DHCP starvation: exhaust the DHCP lease pool with spoofed-MAC `DISCOVER`s to
deny address assignment.

### dhcp6.spoof
*medium — targets: subnet*
Rogue DHCPv6 server advertising this host's IPv6 as the DNS server.

### icmp.redirect
*medium — targets: host*
Forge ICMP redirects telling victims to route target subnets through this host.

| Setting | Default | Meaning |
|---------|---------|---------|
| `icmp.redirect.interval` | (module) | redirect injection interval |

### ipv6.ndp
*high — targets: host*
IPv6 neighbor advertisement flood: poison neighbor caches so the victim's
traffic flows to this host.

| Setting | Default | Meaning |
|---------|---------|---------|
| `ipv6.ndp.victim` | (module) | victim IPv6 / target prefix |

### ipv6.ra
*high — targets: subnet*
IPv6 router advertisement flood: become the default router on the link to
capture IPv6 traffic.

### llmnr.poison
*medium — targets: subnet*
Answer LLMNR (port 5355) resolution failures with this host's address to
capture NTLMv2 hashes.

### wpad.poison
*medium — targets: subnet*
Answer `wpad.dat` requests with a PAC file routing browser traffic through
this host.

| Setting | Default | Meaning |
|---------|---------|---------|
| `wpad.poison.proxy_port` | (module) | proxy port the PAC file points at |

---

## osint

Passive open-source intelligence. These modules talk to public services and
emit **zero** traffic toward the target — ideal for the recon phase of a
scoped engagement.

### osint.dns
*info — targets: domain*
Enumerate `A/AAAA/MX/NS/TXT/SOA/CNAME` records and attempt AXFR zone transfer
for a domain.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.dns.domain` | (module) | target domain |
| `osint.dns.types` | `A,AAAA,MX,NS,TXT,SOA,CNAME` | record types |
| `osint.dns.axfr` | (module) | attempt zone transfer |
| `osint.dns.resolver` | (module) | resolver to query |

### osint.whois
*info — targets: domain*
WHOIS lookup of domain ownership, registrar and registration dates via the
IANA referral chain.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.whois.query` | (module) | domain to look up |
| `osint.whois.server` | `whois.iana.org` | start of the referral chain |
| `osint.whois.timeout` | (module) | timeout |

### osint.ct
*info — targets: domain*
Enumerate subdomains from certificate transparency logs (crt.sh).

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.ct.domain` | (module) | target domain |
| `osint.ct.timeout` | (module) | timeout |

### osint.asn
*info — targets: domain*
Map the org's entire IP estate via ASN/BGP lookups (RIPEstat ip-to-asn +
announced prefixes).

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.asn.target` | (module) | org/domain/IP |
| `osint.asn.timeout` | (module) | timeout |

### osint.shodan
*info — targets: host*
Pre-indexed Shodan host lookup: open ports, banners and exposed CVEs without
touching the target. Requires an API key.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.shodan.key` | (module) | Shodan API key |
| `osint.shodan.target` | (module) | target IP |
| `osint.shodan.timeout` | (module) | timeout |

### osint.bucket
*info — targets: domain*
Discover publicly listable S3 / GCS / Azure storage buckets matching an org
naming pattern.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.bucket.target` | (module) | org name to pattern-match |
| `osint.bucket.suffixes` | (module) | bucket-name suffix candidates |
| `osint.bucket.timeout` | (module) | timeout |

### osint.wayback
*info — targets: domain*
Recover historical URLs and subdomains from the Wayback Machine CDX API.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.wayback.target` | (module) | domain |
| `osint.wayback.limit` | (module) | result cap |
| `osint.wayback.timeout` | (module) | timeout |

### osint.github
*info — targets: domain*
GitHub code-search for leaked secrets and internal references. Requires a
token.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.github.token` | (module) | GitHub API token |
| `osint.github.target` | (module) | search query/org |
| `osint.github.timeout` | (module) | timeout |

### osint.hibp
*info — targets: email*
Breach-exposure check via the Pwned Passwords k-anonymity range API — no
password leaves your machine.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.hibp.email` | (module) | email to check |
| `osint.hibp.password` | (module) | password to check for breach |
| `osint.hibp.timeout` | (module) | timeout |

### osint.metadata
*info — targets: file*
Extract author/tooling metadata from PDF, DOCX, XLSX and PPTX documents.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.metadata.path` | (module) | file to analyse |

### osint.dork
*info — targets: domain*
Run a search-engine dork and collect result URLs (DuckDuckGo HTML endpoint).

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.dork.query` | (module) | the dork query |
| `osint.dork.timeout` | (module) | timeout |

### osint.harvest
*info — targets: domain*
Harvest employee email addresses for a domain from search-engine indexes.

| Setting | Default | Meaning |
|---------|---------|---------|
| `osint.harvest.domain` | (module) | target domain |
| `osint.harvest.timeout` | (module) | timeout |

---

## post

Deliverables: reports, replay and pcap export.

### report.generate
*info — targets: subnet*
Generate a Markdown assessment report from the store (hosts, credentials,
sessions, event log). See [Reporting](Reporting.md).

| Setting | Default | Meaning |
|---------|---------|---------|
| `report.generate.out` | `toha3ee-report.md` | output path |

### session.replay
*medium — targets: host*
Replay a captured HTTP session against its host to prove the session is still
valid.

### pcap.export
*info — targets: subnet*
Export the packet capture written by `http.harvest` to a stable path.

| Setting | Default | Meaning |
|---------|---------|---------|
| `pcap.export.out` | `toha3ee-export.pcap` | export path |

---

## recon

Active and passive reconnaissance. The `net.ping` and scan modules run on the
stealth engine (randomized, jittered, shuffled) by default.

### net.scan
*low — targets: subnet*
ARP sweep of the subnet to discover live hosts and their MAC vendors.

| Setting | Default | Meaning |
|---------|---------|---------|
| `net.scan.targets` | config `targets` | CIDR/IP list |
| `net.scan.repeat` | (module) | repeat the sweep |
| `net.scan.timeout` | (module) | sweep timeout |

### net.ping
*low — targets: host, subnet*
Host discovery sweep: ICMP echo/timestamp/address-mask, TCP SYN ping, UDP
ping.

| Setting | Default | Meaning |
|---------|---------|---------|
| `net.ping.mode` | `echo` | `echo` \| `tcpsyn` \| `udp` |
| `net.ping.targets` | config `targets` | targets |
| `net.ping.ports` | (module) | ports for TCP SYN ping |
| `net.ping.udpport` | (module) | port for UDP ping |
| `net.ping.timeout` | (module) | timeout |

### net.traceroute
*info — targets: host*
UDP-mode traceroute to map the network path and intermediate hops.

| Setting | Default | Meaning |
|---------|---------|---------|
| `net.traceroute.target` | (module) | destination |
| `net.traceroute.max_hops` | (module) | hop cap |
| `net.traceroute.port` | (module) | base UDP port |
| `net.traceroute.probes` | (module) | probes per hop |
| `net.traceroute.timeout` | (module) | timeout |

### net.osdetect
*info — targets: host*
Passive-by-design OS fingerprinting of discovered hosts from TCP SYN-ACK stack
quirks.

| Setting | Default | Meaning |
|---------|---------|---------|
| `net.osdetect.port` | (module) | port to fingerprint |
| `net.osdetect.timeout` | (module) | timeout |

### service.synscan
*low — targets: host, service*
Half-open SYN scan of well-known ports on all discovered hosts.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.synscan.ports` | `CommonPorts` | port list |
| `service.synscan.timeout` | (module) | timeout |

### service.tcpconnect
*low — targets: host, service*
Full TCP connect scan (three-way handshake); no root needed, noisier than SYN.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.tcpconnect.ports` | `CommonPorts` | port list |
| `service.tcpconnect.workers` | (module) | parallel workers |
| `service.tcpconnect.timeout` | (module) | timeout |

### service.udpscan
*low — targets: host, service*
UDP port scan via connected-socket ICMP unreachable detection; slow, often
filtered.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.udpscan.ports` | (module) | UDP ports |
| `service.udpscan.workers` | (module) | parallel workers |
| `service.udpscan.timeout` | (module) | timeout |

### service.finxmas
*low — targets: host, service*
FIN/NULL/XMAS scan: unusual-flag probes that bypass stateless firewalls and
map stateful ones.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.finxmas.mode` | `fin` | `fin` \| `null` \| `xmas` |
| `service.finxmas.ports` | (module) | port list |
| `service.finxmas.timeout` | (module) | timeout |

### service.ack
*low — targets: host, service*
ACK scan: map firewall rule sets by distinguishing filtered from unfiltered
ports via RST replies.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.ack.ports` | (module) | port list |
| `service.ack.timeout` | (module) | timeout |

### service.protoscan
*low — targets: host, service*
IP protocol scan: which network-layer protocols a host accepts.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.protoscan.protocols` | `ProtocolSet` | IP protocols to probe |
| `service.protoscan.timeout` | (module) | timeout |

### service.idle
*low — targets: host, service*
Idle/zombie TCP scan: map open ports through an idle third host, hiding the
scanner's address.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.idle.zombie` | (module) | zombie IP |
| `service.idle.ports` | (module) | port list |
| `service.idle.timeout` | (module) | timeout |

### service.fingerprint
*low — targets: host, service*
Banner grab and HTTP title/session-cookie fingerprinting of open ports.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.fingerprint.timeout` | (module) | timeout |

### service.tls
*low — targets: host, service*
TLS handshake probe of HTTPS services: certificate, protocol, cipher and
weak-config findings.

| Setting | Default | Meaning |
|---------|---------|---------|
| `service.tls.ports` | (module) | ports to probe (default 443) |
| `service.tls.timeout` | (module) | timeout |

### web.dir
*low — targets: host, service*
Brute-force common web directories and files on discovered HTTP/HTTPS
services.

| Setting | Default | Meaning |
|---------|---------|---------|
| `web.dir.wordlist` | `common` | wordlist name or path |
| `web.dir.extensions` | (module) | extensions to append |
| `web.dir.timeout` | (module) | timeout |

The embedded `common` wordlist is a curated subset (~700 entries) covering
source-control and config exposure, admin panels, CMS paths and common
directories. Set `web.dir.wordlist` to a path to supply your own list; SecLists
`Discovery/Web-Content/*` is a good source for larger, operator-chosen lists.

### cve.suggest
*info — targets: host, service*
Map captured service banners to known CVEs from an embedded table, or look up
CVE IDs / keywords live via the NVD and cve.org APIs.

| Setting | Default | Meaning |
|---------|---------|---------|
| `cve.suggest.mode` | `table` | `table` \| `live` |
| `cve.suggest.lookup` | (module) | CVE ID or keyword for live mode |
| `cve.suggest.limit` | (module) | max live results |
| `cve.suggest.timeout` | (module) | HTTP timeout |

---

## switch

Switch-layer exploitation. Only works on un-hardened managed switches; Cisco
`switchport port-security` and DHCP snooping mitigate several of these.

### switch.flood
*critical — targets: subnet*
MAC flooding: overflow the switch CAM table with spoofed source MACs to force
hub-like flooding.

### switch.portsteal
*critical — targets: host*
Port stealing: continuously claim the victim's MAC so the switch forwards its
traffic to this port.

| Setting | Default | Meaning |
|---------|---------|---------|
| `switch.portsteal.victim_mac` | (module) | MAC address to steal |

### switch.vlanhop
*high — targets: host*
VLAN hopping via double 802.1Q tagging to reach hosts on a different VLAN.

| Setting | Default | Meaning |
|---------|---------|---------|
| `switch.vlanhop.vlan` | (module) | target VLAN ID |
| `switch.vlanhop.target_ip` | (module) | target host on that VLAN |

### switch.cdp
*medium — targets: subnet*
CDP/LLDP injection: advertise a forged neighbouring device to switch
management, VoIP and monitoring systems.

### switch.stp
*critical — targets: subnet*
STP takeover: send superior BPDUs to become the root bridge and reroute
inter-switch traffic.

---

## web

### web.misconfig
*info — targets: host, service*
Assess web servers for missing security headers, version disclosure,
directory listing and verbose error pages.

| Setting | Default | Meaning |
|---------|---------|---------|
| `web.misconfig.timeout` | (module) | timeout |

---

## wireless

802.11 attacks. All wireless modules need the interface in **monitor mode**,
e.g. `sudo iw dev wlan0 set type monitor`.

### wlan.scan
*low — targets: ap*
Passive 802.11 beacon scan to discover APs, clients and security modes.

### wlan.deauth
*high — targets: ap, station*
Deauthentication flood to disconnect clients from a target AP.

| Setting | Default | Meaning |
|---------|---------|---------|
| `wlan.deauth.bssid` | (module) | target AP |
| `wlan.deauth.station` | (module) | target client (blank = all) |

### wlan.handshake
*high — targets: ap*
Capture WPA/WPA2 4-way handshake for offline dictionary/brute-force cracking.

| Setting | Default | Meaning |
|---------|---------|---------|
| `wlan.handshake.bssid` | (module) | target AP |

### wlan.pmkid
*high — targets: ap*
Capture the RSN PMKID from EAPOL frames for offline WPA2 cracking (no client
deauth needed).

### wlan.beaconflood
*medium — targets: ap*
Beacon flood: broadcast fake 802.11 beacons to fill the AP list with phantom
networks.

| Setting | Default | Meaning |
|---------|---------|---------|
| `wlan.beaconflood.ssid` | (module) | SSID to broadcast |
| `wlan.beaconflood.channel` | (module) | channel |

### wlan.eviltwin
*critical — targets: ap, station*
Rogue AP impersonating a trusted SSID with a captive-phishing portal for
credential harvesting.

| Setting | Default | Meaning |
|---------|---------|---------|
| `wlan.eviltwin.ssid` | (module) | SSID to impersonate |
| `wlan.eviltwin.brand` | (module) | phishing template brand |
| `wlan.eviltwin.capture_port` | (module) | credential capture listener |

### wlan.karma
*high — targets: station*
KARMA: log client probe requests for every SSID they've ever joined;
optionally respond to lure them to a fake AP.

---

## Summary table

| Category | Count | Modules |
|----------|-------|---------|
| **auth** | 8 | `default.creds`, `smb.signing`, `smb.kerberoast`, `ntlm.relay`, `auth.spray`, `auth.brute`, `auth.userenum`, `auth.asrep` |
| **enum** | 6 | `smtp.enum`, `snmp.enum`, `ldap.enum`, `nfs.enum`, `smb.enum`, `net.ip6sweep` |
| **espionage** | 5 | `http.harvest`, `http.proxy`, `https.proxy`, `ssl.strip`, `phish.inject` |
| **mitm** | 11 | `arp.spoof`, `dns.spoof`, `dns.rebind`, `dhcp.rogue`, `dhcp.starve`, `dhcp6.spoof`, `icmp.redirect`, `ipv6.ndp`, `ipv6.ra`, `llmnr.poison`, `wpad.poison` |
| **osint** | 12 | `osint.dns`, `osint.whois`, `osint.ct`, `osint.asn`, `osint.shodan`, `osint.bucket`, `osint.wayback`, `osint.github`, `osint.hibp`, `osint.metadata`, `osint.dork`, `osint.harvest` |
| **post** | 3 | `report.generate`, `session.replay`, `pcap.export` |
| **recon** | 15 | `net.scan`, `net.ping`, `net.traceroute`, `net.osdetect`, `service.synscan`, `service.tcpconnect`, `service.udpscan`, `service.finxmas`, `service.ack`, `service.protoscan`, `service.idle`, `service.fingerprint`, `service.tls`, `web.dir`, `cve.suggest` |
| **switch** | 5 | `switch.flood`, `switch.portsteal`, `switch.vlanhop`, `switch.cdp`, `switch.stp` |
| **web** | 1 | `web.misconfig` |
| **wireless** | 7 | `wlan.scan`, `wlan.deauth`, `wlan.handshake`, `wlan.eviltwin`, `wlan.pmkid`, `wlan.beaconflood`, `wlan.karma` |
