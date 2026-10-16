# CLI Reference

`toha3ee` follows the shared QYVORA tier grammar:

```
toha3ee <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

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

| Command | Purpose |
|---------|---------|
| `toha3ee report pcap` | pcap modules |
| `toha3ee report report` | report modules |
| `toha3ee report session` | session modules |

## Utilities

| Command | Purpose |
|---------|---------|
| `toha3ee build` | validate a .toha3ee script and print a dry-run plan |
| `toha3ee eval` | run a one-shot command sequence and exit |
| `toha3ee modules` | list all registered modules |
| `toha3ee run` | execute a script or caplet non-interactively |
| `toha3ee script` | execute a .toha3ee script file |
| `toha3ee wizard` | guided attack setup |

