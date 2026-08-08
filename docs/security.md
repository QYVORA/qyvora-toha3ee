# Security & responsible use

toha3ee is a **dual-use network security tool**. It is designed to be used by
security professionals and researchers on networks they own or are explicitly
authorised to test. This page documents the risk model, the legal/ethical
position, and the operational guardrails.

## The hard rule

> **Use toha3ee only on networks you own or have explicit written permission
> to test.**

Running these modules against networks you do not control is illegal in most
jurisdictions (in many places, *probing* alone is an offence) and can cause
real, sustained damage to production networks, businesses and people. The tool
ships prominent warnings; abuse of the tool is the user's responsibility, not
a defect in the tool.

## What this tool can do

toha3ee can:

- **Poison** ARP, DHCP, DHCPv6, IPv6 RA/NDP, DNS, LLMNR and WPAD to intercept
  traffic.
- **Decrypt** HTTPS traffic via a locally-installed CA.
- **Disrupt** the network: DHCP starvation, deauth floods, MAC flooding, STP
  takeover, beacon floods.
- **Harvest** credentials, cookies, NTLMv2 hashes, WPA handshakes and PMKIDs.
- **Move** laterally on the switch layer via VLAN hopping and port stealing.

This is its documented function. Blast radius is declared per module (below)
and High/Critical modules require explicit confirmation before they run.

## Risk model

Every module declares a risk level. The framework uses it to gate execution
and to warn you before disruptive actions.

| Risk | Blast radius |
|------|--------------|
| **info** | no significant footprint (passive or advisory) |
| **low** | minimal footprint; mostly passive observation |
| **medium** | adds noise but does not drop traffic; captured data may be sensitive |
| **high** | interrupts connectivity for targeted hosts for the duration of the attack (~seconds to minutes) |
| **critical** | may drop all clients from the network/AP for a sustained period and trigger network-wide alarms |

High/critical modules show their blast radius and require `y` confirmation in
the wizard; confirmations are persisted per module in the config
(`confirmed_risks`).

## Examples of safe vs. unsafe use

| Scenario | Verdict |
|----------|---------|
| Testing your own home router's ARP handling | Safe |
| A scoped, written-authorized pentest of a client VLAN | Safe |
| CTF / bug bounty labs and isolated VM networks | Safe |
| Running `wlan.deauth` on a café's Wi-Fi to see the passphrase | **Illegal** |
| Probing a cloud provider's IP range you don't own | **Illegal** |
| Using a captured cookie to log into someone else's account | **Illegal** |

## Operational guardrails

1. **Scope in writing.** Define the target IP ranges, domains and times before
   you start; include it in your engagement report.
2. **Test in a lab first.** Every module behaves differently on real hardware
   (DHCP snooping, port-security, 802.1X, IDS). Learn the blast radius on
   equipment you own.
3. **Use the blast radius.** Prefer `info`/`low`/`medium` modules (recon,
   OSINT, enum, fingerprinting) over `high`/`critical` ones where they answer
   the same question.
4. **Watch the clock.** Deauth floods, STP takeover and MAC flooding have
   sustained impact. Run them for the shortest time that answers your question
   and stop them.
5. **Clean up.** The framework's `Cleanup()` contract restores the network on
   stop, error, panic or SIGINT. Verify afterwards: `arp -a`, `ping`, and the
   `[OK]` verdicts from module `Verify` output.
6. **Handle loot carefully.** Credentials, hashes, cookies and captures are
   sensitive. Store them in the engagement vault, not your desktop, and
   destroy them at the end of the engagement.

## HTTPS interception caution

`https.proxy` decrypts TLS with a **framework CA**. Installing that CA on
machines makes them trust toha3ee for everything — never install it on a
machine you don't control, and remove it after the engagement. Only MITM hosts
that are in scope.

## Wireless caution

Wireless attacks are the noisiest and most legally exposed category. A single
`wlan.deauth` burst can be heard by every nearby device and triggers alarms on
most enterprise WIDS. `wlan.eviltwin` impersonates a trusted SSID — make sure
you have the right to impersonate that network.

## Vulnerability reporting

Found a bug in toha3ee? Follow [SECURITY.md](../SECURITY.md) — do **not** open
a public issue for security problems. Note that "toha3ee can ARP-spoof" is the
documented function, not a vulnerability.

## License and responsibility

toha3ee is MIT-licensed. The license grants you freedom to use, modify and
distribute the code — it does **not** grant you permission to use it against
networks you don't own. That permission comes from the network owner, in
writing.
