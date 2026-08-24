# Declined techniques

toha3ee is an **authorised-engagement** framework. This page documents, in one
place, the techniques that are **deliberately not implemented**, why, and —
where it helps the reader understand the gap — how each one would actually be
built.

There are two distinct lists:

1. **Ethically refused** — techniques that fall into malware/APT or
   large-blast-radius criminal territory. Implementing them would turn this
   tool into a weapon that mostly harms, regardless of its defensive framing.
2. **Technically declined** — techniques that are *in scope* (legitimate
   offensive-security work) but are not shipped, either because the honest
   implementation needs an external component, because hardware/radio
   constraints prevent a usable result, or because the effort-to-value ratio
   is wrong. These are documented as `Limitations` on the modules.

---

## 1. Ethically refused techniques

The line is drawn at *tradecraft whose primary purpose is to persist, evade
detection, destroy or exfiltrate* — i.e. the tool would become an APT-style
agent rather than an engagement console. Each entry below describes the
technique, sketches how it would work, and states why it is excluded.

### 1.1 Host persistence (autostart, registry/rc, scheduled tasks)

**How it would work.** After the first foothold, the tool would install a
launcher that survives reboot and re-establishes on the host:

- Windows: a service (`sc create`), a `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value, or a scheduled task pointing at a dropped binary.
- Linux/macOS: a systemd unit in `/etc/systemd/system/`, an entry in
  `/etc/rc.local`, a LaunchAgent plist in `~/Library/LaunchAgents/`, or a
  `.profile`/`.zshrc` line.
- The payload would typically re-download the framework's "agent" component
  at every boot so the operator keeps a foothold.

**Why it is excluded.** Persistence is the defining property of a
*compromise that outlives the engagement*. Authorised engagements have a
defined time window; leaving a backdoor on a client's machine after the test
is exactly the kind of damage a test lab needs to prove it did *not* cause.
There are legitimate frameworks (Cobalt Strike, Metasploit) that do this —
for the labs where such testing is authorised. toha3ee is a network/MITM
console, not an implant framework, and adding persistence would change its
risk profile from "intercepts traffic during a scoped test" to "maintains
access to a box the owner did not keep".

### 1.2 Command & control (C2) and beaconing

**How it would work.** An agent would periodically phone home:

- DNS beaconing: `GET <nonce>.<domain>/x` every N seconds, with the domain
  pointing at an attacker-controlled authoritative server, so the beacon is
  hidden in normal DNS traffic.
- HTTP(S) beaconing over a common port (443) with JA3-rotating TLS and
  `jitter` (random sleep) to defeat netflow baselining.
- Domain fronting: sending the beacon through a CDN (e.g. a blocked or trusted
  domain) with the real C2 in the `Host:` header.
- DGA: generating a rotating domain list from the current date so blocking one
  domain does not kill the channel.

**Why it is excluded.** A command channel is the infrastructure of a botnet.
Authorised engagements rarely *need* a persistent C2 channel — the operator
is already on the network with credentials. Building one would give the tool
the capacity to control compromised machines at scale, which is a far larger
blast radius than anything this console otherwise does, and it is the piece of
an attack that most clearly crosses into "creating a weapon".

### 1.3 Endpoint evasion (EDR/AV bypass)

**How it would work.**

- **AMSI patching:** write a tiny trampoline that overwrites the AMSI
  function pointers in `amsi.dll` in-process so PowerShell/.NET scans are
  neutered before a malicious script runs.
- **ETW blind spots:** patch `EtwEventWrite` to drop telemetry for a specific
  provider so EDR event sources go quiet.
- **Sleep obfuscation / memory carving:** after executing, encrypt the
  in-memory image while sleeping and decrypt on the next beacon, so memory
  scanners see only ciphertext.
- **Reflective DLL / module stomping:** map a DLL into the address space of a
  legitimate process (e.g. `svchost.exe`) without calling `LoadLibrary`, so
  on-disk forensics and most AV hooks see nothing.

**Why it is excluded.** These techniques exist specifically to hide from
defence on systems the attacker does not own the right to hide on. They have
essentially no legitimate lab use that a scoped engagement needs (an
authorised test does not require bypassing the client's EDR — the client
should know you are there). They also sharply increase the legal exposure of
everyone who downloads the tool. The framework instead documents its traffic
openly (see `docs/Reporting.md`) and leaves endpoint attacks out entirely.

### 1.4 Rootkit / kernel-level hiding

**How it would work.** A kernel module or rootkit would:

- hook the syscall table (`nt!NtQuerySystemFile` / Linux `sys_call_table`)
  to hide specific PIDs, files and connections,
- install an `ftrace`/kprobe filter on `getdents64` to hide file names,
- redirect network sockets with an LKM netfilter hook so an SSH listener or
  C2 socket is invisible to `ss`/`netstat`.

**Why it is excluded.** This is the most invasive category: it modifies the
target's kernel and hides the presence of the attacker. It is inseparable
from malware in function and purpose, requires the tool to ship unsigned
kernel code, and would make the project's "you will see exactly what we do"
promise impossible to keep. Excluded outright.

### 1.5 Anti-forensics / log and timeline tampering

**How it would work.**

- **Log scrubbing:** `truncate -s 0 /var/log/auth.log`, remove `bash_history`,
  or delete specific Event Log records (`wmic eventlog clear`).
- **Timestomping:** `touch -d` on files to rewrite mtimes, or rewrite
  `$STANDARD_INFORMATION` NTFS timestamps via direct file-attribute writes.
- **Memory and slack scrub:** zero out allocated memory on exit so the
  forensic image shows nothing.
- **Covering the trail:** deleting the tool binary after use, clearing shell
  rc, removing `~/.local/bin/toha3ee` and any captures.

**Why it is excluded.** The explicit intent of anti-forensics is to hide
evidence of *unauthorised* activity. A tool that ships a "clean up after
yourself" module would be indistinguishable from a malware stealer's cleanup
routine. toha3ee's philosophy is the opposite: it emits an audit trail
(`events`, session log, `report.generate`) precisely so a scoped test is
provable. Adding log destruction would betray that design and, again, is a
hallmark of criminal use.

### 1.6 Weaponised payload delivery (malware/dropper generation)

**How it would work.**

- Generate a staged executable: a loader that downloads the next stage,
  decodes it in memory and executes it without touching disk.
- Macro-embedded Office documents or ISO/shortcut `.lnk` bundles that run
  a PowerShell one-liner when opened.
- Binary packing / shellcode generation with `msfvenom`-style encoders to
  defeat signature scanning.

**Why it is excluded.** Shipping a payload builder is the point at which a
*network* tool becomes a *malware* tool. Authorised pentests often use such
builders (that is what Cobalt Strike and Metasploit are for), but toha3ee's
scope is network/MITM testing. There is no way to build a "delivery +
execution" feature that is used meaningfully on an authorised network but
does not trivially double as a phishing-campaign weapon for criminals.

### 1.7 Ransomware-style destructive payloads

**How it would work.** Encrypt user files with a symmetric key and post the
key off-host, or wipe disk/MBR/flash firmware, or delete backups first.

**Why it is excluded.** Pure destruction with no engagement value. Disruptive
modules here (DHCP starvation, MAC flooding, STP takeover) are **transient**:
they stop the moment `Cleanup` runs, which is the difference between "a test
that degrades the network for seconds/minutes" and "permanent damage to data".
Permanent destruction has no scoped-test justification.

### 1.8 Credential/data exfiltration to a third party

**How it would work.** After capture, POST credentials, hashes, cookies and
session tokens to an external attacker-controlled endpoint rather than the
local store.

**Why it is excluded.** Everything captured in toha3ee stays on the operator's
machine (local store, local `report.generate`). Adding an off-host channel is
the difference between "an operator is accountable for data they hold" and
"captured data silently leaves the network". The absence of this feature is a
deliberate accountability boundary.

---

## 2. Technically declined techniques (in scope, not shipped)

These are legitimate techniques that toha3ee does *not* implement — either
because the correct implementation is an external tool, because the radio or
hardware cannot deliver the result, or because the honest version needs
infrastructure the project cannot bundle. They are listed with the technical
reason, so nobody mistakes a gap for a secret feature.

### 2.1 Offline password cracking (WPA handshake, PMKID, NTLM)

- **Status:** out of scope — capture is in, cracking is not.
- **How it would work:** after `wlan.handshake` or `wlan.pmkid`, run hashcat
  mode 22000/22100 on the captured data with a wordlist; the NTLMv2 captures
  from `ntlm.relay` feed hashcat mode 5600.
- **Why not bundled:** cracking is a wordlist/GPU/graph optimisation problem
  with heavy dependencies (CUDA/OpenCL, rule engines, GB-scale wordlists).
  Bundling it would make the binary enormous and the whole point of the
  capture modules is that the operator takes the hash to their preferred
  cracker. Documented in module `Limitations`.

### 2.2 Full KARMA association response (`wlan.karma`)

- **Status:** passive probe logging only.
- **How it would work:** respond to every probe request with a matching SSID
  beacon, bring the client through association and open authentication, then
  serve a captive portal.
- **Why not bundled:** doing it honestly requires a full AP stack
  (hostapd-mana). Writing an 802.11 AP in pure Go with reliable association
  handling is a large, driver-fragile project. The module documents that
  `hostapd-mana` (external) is the association half.

### 2.3 Evil-twin AP beacon injection (`wlan.eviltwin`)

- **Status:** configuration + harvest half present; the RF half is external.
- **How it would work:** set up a virtual AP (`iw dev ... type ap`), configure
  hostapd with the target SSID, run a captive portal that mirrors the chosen
  phish template, and redirect DNS so every connected client hits the portal.
- **Why not bundled:** creating a real AP requires `hostapd` and monitor+
  managed-interface juggling that varies per driver; the framework would
  otherwise be shipping a system service. The module wires the capture side
  and delegates the beacon side to hostapd.

### 2.4 WPA3/SAE handshake capture

- **Status:** not supported.
- **How it would work:** SAE (Simultaneous Authentication of Equals) uses
  a Dragonfly key exchange; the PMK is derived from a password-confirmation
  element rather than a 4-way handshake you can passively capture and crack
  offline.
- **Why not bundled:** there is no practical offline attack — that is the
  point of WPA3. `wlan.pmkid` explicitly documents "PMF and WPA3 (SAE)
  networks do not leak it". Nothing to implement.

### 2.5 Deauth against 802.11w (PMF) networks

- **Status:** not supported; documented limitation.
- **How it would work:** with protected management frames enabled, a forged
  deauth must carry a valid MIC derived from the PMK, which the attacker does
  not have. 
- **Why not bundled:** there is no valid attack here; the honest answer is
  that PMF networks are not deauthable, and the module says so.

### 2.6 TLS 1.3 passive decryption

- **Status:** `https.proxy` does active MITM; passive TLS 1.3 decryption is
  impossible by design.
- **How it would work:** TLS 1.3 removes RSA key exchange and forward secrets
  are per-session with ephemeral keys, so there is no client/server static key
  that lets a passive observer decrypt the stream.
- **Why not bundled:** mathematically excluded. The tool decrypts only by
  inserting itself as the endpoint (active MITM with the framework CA), which
  is the documented approach.

### 2.7 DHCP starvation against DHCP-snooping switches

- **Status:** implemented; limited by switch config.
- **How it would work:** DHCP snooping classifies ports as trusted/untrusted
  and drops DISCOVERs whose `chaddr` source MAC does not match the learned
  binding, so spoofed-chaddr starvation packets are dropped at the edge.
- **Why not bundled as a bypass:** bypassing snooping (e.g. via a trusted
  trunk port) is a configuration matter, not a code matter; the module's
  `Limitations` field tells the operator when it will fail.

### 2.8 VLAN hopping without a trunk port

- **Status:** implemented as double-tagging; limited by topology.
- **How it would work:** double-tagging only succeeds when the attacker port
  is on a trunk or a native-VLAN-misconfigured port; replies almost never
  return to the attacker because the inner tag is stripped asymmetrically.
- **Why not bundled:** the other mainstream technique — dynamic trunking
  protocol (DTP) negotiation — relies on an ancient Cisco default that most
  modern switches disable; the module documents the trunk-port precondition.

### 2.9 IPv4+IPv6 full-host MITM automation

- **Status:** implemented per-protocol (`arp.spoof`, `ipv6.ndp`, `dhcp.rogue`,
  `ipv6.ra`, `dns.spoof`); not unified into one "take over the subnet" button.
- **How it would work:** a meta-module that runs the poisoning stack,
  configures IP forwarding, drops the real gateway's responses and adds all
  protocol variants at once.
- **Why not bundled:** unifying them multiplies the blast radius and the
  cleanup surface; the safety contract (every attack restores the network)
  is harder to guarantee across a whole stack. The wizard and
  `scripts/full-pipeline.toha3ee` sequence them deliberately instead.

### 2.10 In-browser payload execution / drive-by RCE

- **Status:** never planned.
- **How it would work:** a `phish.inject` variant that, instead of harvesting
  credentials, injects a browser exploit (e.g. a Chrome/WebKit 0-day) so
  visiting the page drops a shell.
- **Why not bundled:** this is the "weaponised payload delivery" category from
  section 1.6 — an RCE payload is malware, not a phishing test. The phishing
  modules stop at credential capture, which is the scoped-test deliverable.

### 2.11 Physical/OSINT integrations that need paid APIs

- **Status:** partial.
- **How it would work:** e.g. full Shodan export search, VirusTotal bulk, or
  paid WHOIS/bucket indexes.
- **Why not bundled:** several OSINT modules need API keys, rate limits and,
  for some providers, paid plans. The modules implement the protocol shape and
  clearly surface the missing key in Preflight; the operator supplies the key.

---

## 3. How the boundary is enforced in code

The line is not just documentation:

- The module registry (`internal/attacks/registry.go`) enforces the
  `Meta()/Preflight()/Run()/Verify()/Cleanup()` contract. Everything is
  **network-visible and transient**; there is no "post-compromise" module
  surface to build an implant on.
- Every attack registers cleanup and a heartbeat; the safety manager
  (`internal/safety`) will not leave state behind on stop/error/panic/SIGINT.
- The store and `report.generate` keep everything local; there is no network
  egress path for captured material.
- A code review of "what does toha3ee do after you stop it" answers: it
  restores the network. That is the property that makes the ethical line
  enforceable rather than aspirational.

## 4. Summary table

| Technique | Category | Declined because |
|-----------|----------|------------------|
| Persistence / autostart | ethically refused | converts a scoped test into a lasting compromise |
| C2 / beaconing / DGA | ethically refused | botnet infrastructure |
| EDR/AV evasion, AMSI/ETW patching | ethically refused | exists only to hide from defence |
| Rootkit / kernel hiding | ethically refused | kernel compromise, unprovable behaviour |
| Anti-forensics / log destruction | ethically refused | destroys the audit trail by design |
| Payload generation / droppers | ethically refused | turns a network tool into a malware tool |
| Ransomware-style destruction | ethically refused | permanent damage, no test value |
| Third-party exfiltration | ethically refused | removes operator accountability for captured data |
| Offline hash cracking | technically declined | external GPU/wordlist tool (hashcat) |
| Full KARMA association | technically declined | needs hostapd-mana |
| Evil-twin RF beaconing | technically declined | needs hostapd |
| WPA3/SAE capture | technically declined | no practical offline attack exists |
| PMF deauth bypass | technically declined | mathematically invalid (MIC) |
| Passive TLS 1.3 decryption | technically declined | forward secrecy by design |
| DHCP-snooping bypass | technically declined | switch configuration, not code |
| Trunkless VLAN hopping | technically declined | topology precondition |
| In-browser RCE delivery | ethically refused | malware, not phishing |
| Paid-API OSINT | technically declined | external credentials needed |
