# FAQ

## Installation & build

**Q: `make build` fails because libpcap headers are missing.**
Install them: `sudo apt install libpcap-dev` (Debian/Ubuntu) or
`sudo dnf install libpcap-devel` (Fedora). macOS ships libpcap with Xcode
Command Line Tools.

**Q: `toha3ee modules` prompts for a sudo password.**
Modules listing doesn't need root. Run `toha3ee --no-sudo modules` or set
`TOHA3EE_NO_SUDO=1`.

**Q: Why does toha3ee auto-escalate to sudo?**
Raw sockets, packet capture and IP forwarding require root. If it cannot find
sudo it will tell you to re-run as root. Use `--no-sudo` for unprivileged
operations (version, module listing, script dry-runs).

## Running

**Q: The console says "preflight blocked".**
Run `show <module>` to see which checks are blocked and why. Common causes:
not root, IP forwarding disabled (usually auto-fixed), wrong interface, no
targets configured, or missing prerequisites (e.g. monitor mode for WLAN).

**Q: `on net.scan` found nothing.**
- Confirm the interface: `--iface eth0` must be the L2 segment you're on.
- Confirm targets: `set net.scan.targets 192.168.8.0/24` (or config `targets`).
- Switches with ARP inspection or port isolation may hide neighbours.
- Try `net.ping mode tcpsyn` for hosts that drop ICMP.

**Q: I get an IP from the rogue DHCP server but no traffic.**
Switch DHCP snooping drops rogue offers. Also confirm IP forwarding is on
(`net.ip_forward` sysctl — `Preflight` should set it and restore it on
cleanup).

**Q: HTTPS interception shows certificate errors on the client.**
The client must trust the framework CA (`toha3ee-ca.pem`). Install it into
the test machine's trust store, and remove it after the engagement.

**Q: Wireless modules don't see anything.**
Put the interface in monitor mode: `sudo iw dev wlan0 set type monitor` and
disable network-manager interference. `wlan.scan` should list APs once that's
done.

## Modules

**Q: What does `service.idle` need?**
An "idle" zombie host whose IP-ID counter increments predictably, and
privileged raw sockets to read its IP-IDs. Most modern OSes randomise IP-IDs,
so this is often not viable — that's why it's `low` risk and often
inconclusive.

**Q: `auth.brute` stopped early.**
It is intentionally paced and aborts on connection-level errors to avoid
account lockouts. Increase `auth.brute.delay` or verify the target SSH version
supports the auth methods it uses.

**Q: How do OSINT modules differ from recon modules?**
OSINT queries public services (DNS, WHOIS, CT logs, Shodan, Wayback, etc.) and
emits zero traffic toward the target — good for scoping before you touch the
network. Recon modules are active and touch the target directly.

**Q: `cve.suggest mode live` is slow.**
The NVD API is rate-limited. Use `cve.suggest.lookup` for a specific CVE ID
when you know what you're after, and keep `limit` modest.

## Automation

**Q: How do I dry-run a script without sending packets?**
`toha3ee --no-sudo build scripts/full-pipeline.toha3ee` validates and prints
the plan. No packets are sent.

**Q: Can a script do something the console cannot?**
No. Every script statement drives the same module lifecycle and risk gates as
the REPL.

**Q: `wait for net.scan` hangs.**
`net.scan` is a bounded sweep, but some modules (sniffers, proxies, spoofers)
run until stopped. `wait for <module> max <secs>` bounds the wait.

## Reporting

**Q: The report is missing credentials.**
Nothing was captured. Run the harvest/proxy modules and redirect traffic first
(`http.harvest` needs `arp.spoof` to bring traffic through this host).

**Q: Does the report leave anything on disk?**
`report.generate` writes the Markdown you asked for. `pcap.export` copies the
capture. Everything else lives in the in-memory store until the session ends.

## Security & legality

**Q: Is toha3ee illegal?**
No — it's open-source software. Using it against networks you don't own is
illegal. Read [Security & responsible use](security.md).

**Q: Can toha3ee be detected?**
Possibly. The stealth engine randomizes/jitters packet timing and fields, but
no tool is undetectable, and that is not a goal — toha3ee is for
authorised testing, not evading detection in hostile networks.

**Q: Where do I report a bug or vulnerability?**
Bugs: the GitHub issue templates. Security problems: follow
[`SECURITY.md`](../SECURITY.md) (private disclosure, not a public issue).
