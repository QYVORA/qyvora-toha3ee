# QYVORA TOHA3EE — Security Capability Audit

| Field | Value |
|-------|-------|
| Repository | `frameworks/qyvora-toha3ee` |
| Branch / commit | `main` @ `aae0573` (clean tree at audit start and after probes/tests) |
| Binaries under test | `bin/toha3ee` (16,506,136 B), root `./toha3ee` (16,506,168 B) — both untracked build artefacts |
| Reported version | `dev` / commit `none` (both binaries) |
| Audit date | 2026-10-21 |
| Audit type | Static source review + local probes (`--no-sudo`) + test/vet execution |
| Feature code changed | **None** (this file is the only artefact created) |

**Status vocabulary:** `IMPLEMENTED` · `PARTIALLY IMPLEMENTED` · `STUBBED` · `PLANNED` · `MISSING` · `UNVERIFIED`.  
**Priority vocabulary:** `P0` critical · `P1` high · `P2` medium · `P3` low.  
**Provenance:** marked **verified** (executed binary/test) or **inferred** (source only).

---

## 1. Framework identity and intended domain

TOHA3EE is an **authorised-engagement network offensive/assessment console**. Its scope is local/network-layer testing against targets under explicit authorisation: host discovery, service enumeration/scanning, wireless reconnaissance/capture, MITM/traffic manipulation, credential harvesting, session capture/replay, and operator-facing reporting. 

Per the ecosystem definition and source evidence:
- Tiers/verbs registered: `build`, `capabilities`, `completion`, `eval`, `exploit`, `help`, `modules`, `recon`, `report`, `run`, `script`, `updates`, `version`, `wizard` (help capture `docs/audit/help/toha3ee.txt`).
- Module catalogue: **73 live modules** across **10 categories** (auth, enum, espionage, mitm, osint, post, recon, switch, web, wireless) — verified by `comm` between `internal/capabilities/capabilities.go:90` catalog and `toha3ee modules -o json --no-sudo` (0 diff).
- Interactive surfaces: `tui`, `wizard`, `eval`, `run`, `script` are declared; `recon`/`exploit`/`report` are tier stubs in the grammar.
- Safety is treated as first-class: stealth defaults, preflight checks, a safety manager, risk confirmation, and an explicit "declined techniques" policy (`docs/Declined-Techniques.md`).

It is a tool for *active* assessment under authorisation, not a passive DFIR triage tool (contrast with Timbuktu).

## 2. Audit scope and evidence sources

| Evidence | Detail | Result |
|----------|--------|--------|
| Git state | `git status --porcelain`, `git log -1` | Clean; `main` ahead of origin by 1 commit @ `aae0573` |
| Help capture | `docs/audit/help/toha3ee.txt` (12984 bytes, 2026-10-19) | Top-level commands listed (includes `tui`, `wizard`, `exploit`) |
| Binary probes | `version -o json`; `capabilities -o json\|yaml\|markdown\|html`; `modules -o json`; `--help`; unknown cmd/flag; bare invocation; `tui/repl/shell/interactive/console`; `eval ""`; `build /nonexistent.toha3ee`; `report` with no report; `wizard --help` | Recorded below |
| Source review | `internal/` (many packages), `cmd/toha3ee` (main.go, tui.go build-ignored, update.go), `internal/attacks/*` (10 category dirs), `internal/session`, `internal/safety`, `internal/events` | Reviewed |
| Tests | `GOPROXY=off go test ./... -count=1 -timeout 180s` | **PASS** (exit 0) |
| Static analysis | `GOPROXY=off go vet ./...` | **PASS** (exit 0) |
| Docs/spec | `README.md`, `docs/Module-Reference.md`, `docs/Declined-Techniques.md`, `docs/Reporting.md`, `man/toha3ee.1`, `QYVORA-TOOL-OUTPUT-SPEC.md`, `shared/qyvora-common/*` | Reviewed |
| Layout | `bin/`, root `toha3ee`, `.toha3ee_history`, `scripts/`, `caplets/` | Reviewed |

All unsafe/interactive paths were probed with `--no-sudo`. Probes isolated under `/tmp/opencode/th`; repo not modified.

## 3. Existing capability inventory

### 3.1 Module counts (verified)
- **Live modules:** 73 (exact set matches `capabilities.json` catalog; 0 diff vs `modules` listing).
- **Categories:** 10 (auth 8, enum 6, espionage 5, mitm 11, osint 12, post 3, recon 15, switch 5, web 1, wireless 7) — sum 73.
- **Docs drift:** `README.md:29` and `docs/Module-Reference.md` intro claim **70 modules**; actual count is **73**. Tables in Module-Reference enumerate all 73.

### 3.2 Command surface (declared vs present)
Declared in `internal/capabilities/capabilities.go:94-105`: `tui`, `wizard`, `eval`, `run`, `script`, `build`, `modules`, `capabilities`, `version`, `report`. Cobra registers these plus `recon`, `exploit`, `completion`, `updates`, `help` (`cmd/toha3ee/main.go:150-488`).

### 3.3 Event/contract elements
- **Event verbs:** `run.started, run.completed, module.started, module.stopped, module.failed, module.completed, host.discovered, credential.discovered, session.captured, report.generated, warning, error` (`capabilities.go:76-83`).
- **Event envelope (JSONL):** `schema_version: "1.0"`, `timestamp`, `execution_id`, `framework`, `level`, `event`, `data` (`internal/events/jsonl.go:41-62`).
- **Exit codes:** `0/1/2/130` (`cmd/toha3ee/main.go:56-80`, `man/toha3ee.1:282-295`).
- **Output formats:** `terminal, json, markdown, yaml, html` (all verified except YAML is JSON-with-header per `capabilities.go:171-174`).
- **Risk levels:** `info,low,medium,high,critical`; **severity levels:** `critical,high,medium,low,info` (`capabilities.go:84-89`).

### 3.4 Key subsystems
- **Session engine** (`internal/session`): owns bus, store, config, safety, UI, module lifecycle; `New` wires defaults; `Report()` snapshots `store` (`report.go:120-123`).
- **Store** (`internal/store`): ring buffer of hosts/creds/sessions/runs/events (5000 entries), concurrency-safe.
- **Safety/Preflight** (`internal/safety`): profiles, checks, risk confirmation, preflight orchestration.
- **Stealth** (`internal/stealth`): packet engineering defaults (jitter/burst/randomisation) — `internal/stealth/stealth.go` package doc.
- **Networking** (`internal/netx/*`): ARP, DHCP/DHCPv6, DNS, NDP, LLMNR, proxy, SMB, SNMP, RPC, ports, sniffing, wireless helpers.
- **Vectors/engine** (`internal/vectors`): ranks attack suggestions from store+module metadata.
- **Phishing** (`internal/phish`): templates + injection support.
- **Hijack** (`internal/hijack`): cookie/session injection replay.
- **Self-update** (`internal/selfupdate`).
- **qyvora-tui** linked (`go.mod`), **qyvora-script** linked.

## 4. Capability status matrix

| Area | Status | Evidence | Notes |
|------|--------|----------|-------|
| Module catalogue (73) | **IMPLEMENTED** | `capabilities.Build()` + attacks registry; verified count/exact match | All marked `implemented:true`, categories correct |
| Recon (15) | **IMPLEMENTED** | modules present; `Limitations` documented per module | Includes ARP sweep, pings, various scans, fingerprinting, web dir, CVE suggest |
| Enum (6) | **IMPLEMENTED** | LDAP/SMB/NFS/SMTP/SNMP/IP6 sweep | Mix passive/active |
| Auth (8) | **IMPLEMENTED** | brute/spray/userenum/asrep/kerberoast/smb.signing/default.creds/ntlm.relay | Many have constraints documented |
| MITM (11) | **IMPLEMENTED** | ARP/DHCP/DHCPv6/DNS spoof/rebind/ICMP redirect/IPv6 RA/NDP/LLMNR/WPAD | Requires privileges/root and correct iface; relies on arp.spoof in places |
| Espionage (5) | **IMPLEMENTED** | http.harvest/proxy, https.proxy, ssl.strip, phish.inject | Some need ARP/redirection |
| Switch (5) | **IMPLEMENTED** | CDP, MAC flood, port steal, STP, VLAN hop | Switch-dependent |
| Wireless (7) | **PARTIALLY IMPLEMENTED** | beacon flood/deauth/handshake/pmkid/scan present; `karma`/`eviltwin` partially constrained | External deps noted |
| Web (1) | **IMPLEMENTED** | `web.misconfig` |
| Post (3) | **IMPLEMENTED** | `pcap.export`, `report.generate`, `session.replay` |
| OSINT (12) | **IMPLEMENTED** | ASN/bucket/ct/dns/dork/github/harvest/hibp/metadata/shodan/wayback/whois | Some need tokens/egress |
| Interactive TUI (`tui` cmd) | **MISSING (build-ignored)** | `cmd/toha3ee/tui.go:1` `//go:build ignore`; `tui` subcommand exists? Cobra registers it (`cmd/toha3ee/main.go:666-688` references `NewTUI`?) but source ignored; binary probe: `./bin/toha3ee tui` → **exit 2 "unknown command \"tui\""** | Declared in capabilities and README |
| REPL/bare invocation | **PARTIALLY IMPLEMENTED** | Bare prints help; README documents `toha3eeλ>` REPL (`README.md:198,264-290`) but not present in this build (probe: bare exits 0 with help). Leftover REPL header `internal/ui/ui.go:322` prints "type 'help'..." even when not in TUI | Stale docs vs build |
| Wizard | **IMPLEMENTED** | `wizard --help` exits 0, "guided attack setup" | Source present (`cmd/toha3ee/main.go:221`, wizard files) |
| `eval` | **IMPLEMENTED** | Accepts `--eval` or positional; empty → exit 2 with usage message | Verified |
| `run`/`script`/`build` | **IMPLEMENTED** | Dispatches `.toha3ee/.qs` to script engine or caplet; dry-run plan works (`build scripts/full-pipeline.toha3ee --no-sudo` exit 0) | Verified |
| `modules`/`capabilities`/`version` | **IMPLEMENTED** | All work; capabilities includes full catalog |
| `report` | **IMPLEMENTED** | Renders from `toha3ee-report.json` / session state; missing file → exit 1 with message | Verified |
| `recon`/`exploit`/`report` tiers | **STUBBED** | Tier commands exist but `exploit`/tier behaviour not exercised as module trees in the same way; modules are invoked via action grammar under tier/group/action? Or via `eval/run/on` in REPL/TUI. CLI registers `recon/exploit/report` as commands but module execution is through the action tree (`attachModuleTree`) | Grammar exists; full tier UX depends on TUI/REPL |

## 5. Reconnaissance and discovery findings

- **Comprehensive network recon:** 15 recon modules cover ARP, ping variants, TCP/UDP/FIN/NULL/XMAS/ACK/idle/IP protocol scans, traceroute, OS detection, service fingerprinting/TLS, web dir, CVE mapping. All have documented `Limitations` (most note raw sockets/privileges/range).
- **Wireless recon:** `wlan.scan` passive, others active/deauth/handshake/PMKID/capture.
- **OSINT:** broad coverage including CT logs, Wayback, GitHub search (token-gated), Shodan, ASN, buckets, WHOIS, metadata, HIBP (k-anonymity).
- **Module discovery:** `modules` lists all 73; filterable by category. Orchestrator can enumerate reliably.
- **Auto-select iface:** `netx.AutoSelectIface()` used when `-iface` omitted (`cmd/toha3ee/main.go:756-815`).

## 6. Analysis and assessment findings

- **Session state:** `store` accumulates hosts, creds, sessions, runs, events; `Report()` serializes to the `session.Report` shape (§4 earlier) with `generated`, `running_modules`, `hosts`, `credentials`, `sessions`, `runs`, `events`. This is tool-specific, not `contract.Result`.
- **Event stream:** JSONL with `schema_version: "1.0"`, envelope matches the contract spirit (shared with Jabari/Anansi per comment in `jsonl.go:11`). Emitted when `--events` specified; routing rules in `run()` prevent combining `--events stdout` with machine report formats.
- **Report outputs:** `report` command + `-o json|markdown|yaml|html` on relevant commands render from session state (`session/report.go`).
- **Risk/vectors:** `internal/vectors` ranks suggestions using module metadata and store state; confidence is a float in `[0,1]` per output spec.
- **Safety integration:** Risk confirmation auto-satisfied on explicit CLI invocation (`cmd/toha3ee/main.go:681`), preflight runs, profiles constrain noise.
- **Logging routing:** Machine formats send human output to stderr; JSONL events can own stdout in configured modes.

## 7. Exploitation-related capability findings

- **Extensive active capabilities:** MITM (11), auth (8 including relay/brute/spray), switch attacks (5), wireless active/capture (4+), phishing/https proxy/ssl strip, session replay. 
- **Authorization model (declared):** `capabilities.go:90-92` states "all active attack modules require explicit authorization via --authorized flag or AUTHORIZED=yes in caplet; passive reconnaissance modules do not require authorization".
- **Implementation status of authorization:** **MISSING / NOT ENFORCED**. Grepped for `--authorized`, `AUTHORIZED` handling — none found in `cmd/toha3ee`, `internal/session`, `internal/safety`. The gate is **only** risk confirmation (`ConfirmRisk`) which is auto-approved on CLI invocation (line 681). There is no CLI flag, no env var, no caplet parser enforcement, and no preflight check requiring authorization. This directly contradicts the declared contract.
- **Ethical boundaries:** `docs/Declined-Techniques.md` explicitly refuses persistence, C2/beaconing, EDR/AV bypass, rootkits, anti-forensics/tampering, weaponised droppers, ransomware, third-party exfiltration (section 1). 11 techniques are technically declined with reasons (section 2) — boundary is documented and enforced by absence + limitations.
- **Tier `exploit`:** help lists it; module tree exists; invocable via grammar. Behaviour depends on modules (no blanket refusal like Timbuktu).

## 8. High-level implementation candidates

None implemented. Recommendations for a later authorised phase:

| Candidate | Why | Prerequisite | Priority |
|-----------|-----|--------------|----------|
| Implement `--authorized` flag + `AUTHORIZED` env + caplet parsing | Enforce the declared authorization model; prevent accidental misuse and match the contract | CLI parsing, session/config plumbing, preflight check, audit log entry | **P0** (safety/compliance) |
| Fix version stamping in dev builds / enforce semver | `make build` produces `dev`/`none`; conformance runner masks via `-X` to `9.9.9` (`shared/qyvora-common/conformance/runner.go:147,155`); violates "release artifacts must never report dev" | Update Makefile ldflags to inject version/commit/date/user (like goreleaser), or fail build if unstamped in release | **P0** |
| Implement or remove TUI/REPL | Declared everywhere but `tui.go` build-ignored, bare invocation not REPL; `internal/ui/ui.go:322` leftover header. Misleads users and orchestrators | Either restore TUI build or remove commands/docs | **P1** |
| Make `--help`/capabilities consistent with reality | Module count 70 vs 73; TUI advertised but missing; authorization model false | Sync docs and capabilities | **P1** |
| Add `schema_version` to `session.Report` JSON | Event stream has it; session report (used by `report -o json`) does not | Add field + version constant | **P1** (orchestration) |
| Enforce `--events stdout` + machine format conflict in all paths | Already checked in `run()`; ensure all report paths consistent | Test coverage | P2 |
| Richer module capability metadata | Per-module `requires`/`privileges`/`platforms` surfaced in `capabilities`/`modules -o json` | Extend Meta/Capability structs | P2 |
| Structured error taxonomy | Distinguish "missing iface", "not root", "preflight blocked", "usage" clearly | Error wrapping | P2 |

## 9. Low-level deferred technique inventory

Per `docs/Declined-Techniques.md` (reviewed):

### Ethically refused (not implemented)
1. Host persistence (autostart/registry/rc/scheduled tasks) — engagement scope
2. C2 and beaconing (DNS/HTTP beacons, domain fronting, DGA) — weaponisation
3. Endpoint evasion (AMSI/ETW, sleep obfuscation, heap encryption) — malware
4. Rootkit/kernel-level hiding — kernel exploitation territory
5. Anti-forensics/log/timeline tampering — evidence integrity
6. Weaponised payload delivery/dropper generation — malware
7. Ransomware-style destructive payloads — harm
8. Credential/data exfiltration to third party — exfiltration beyond engagement

### Technically declined (in scope but not shipped)
1. Offline password cracking (WPA/PMKID/NTLM) — capture-only; cracking external
2. Full KARMA association response — needs hostapd-mana/full AP stack
3. Evil-twin AP beacon injection — needs hostapd + interface juggling
4. WPA3/SAE handshake capture — no practical offline attack
5. Deauth against 802.11w (PMF) — not supported, documented
6. TLS 1.3 passive decryption — no key material
7. DHCP starvation against DHCP-snooping switches — often blocked
8. VLAN hopping without trunk port — misconfig-dependent
9. IPv4+IPv6 full-host MITM automation — complex, partial
10. In-browser payload execution/drive-by RCE — content injection present but not full drive-by
11. Physical/OSINT integrations needing paid APIs — external, not bundled

**Status:** all correctly absent. Documentation is honest and detailed. Modules that are limited (e.g. `wlan.karma`, `wlan.eviltwin`) carry `Limitations` in code; `Declined-Techniques.md` explains the boundary.

## 10. Common-layer conformance

| Area | Status | Evidence |
|------|--------|----------|
| Exit codes 0/1/2/130 | **CONFORMANT** | Verified: unknown cmd/flag → 2, empty eval → 2, missing script → 1, no report → 1, success paths → 0, interrupted → 130 documented |
| Exit code 3 | **MISSING** | Not defined; spec allows it, toha3ee doesn't use it |
| Version JSON | **NON-CONFORMANT** | Reports `version:"dev", commit:"none"` for both binaries; contract expects semver + commit/date (`contract.VersionResult`). Conformance runner stamps `9.9.9` to mask this (`shared/qyvora-common/conformance/runner.go:147,155`) |
| Capability manifest | **NON-CONFORMANT SHAPE + FALSE CLAIM** | Has rich local schema (matches some needs) but `authorization_model` line 90-92 is **unimplemented**. Not `contract.CapabilityManifest` shape; `commands` list includes `tui` which doesn't exist |
| Result/report envelope | **NON-CONFORMANT** | `session.Report` has no `identity/context/schema_version`; different shape from `contract.Result` and from Timbuktu's result |
| Event envelope | **CONFORMANT** | `schema_version: "1.0"`, fields match contract style (`jsonl.go:41-62`) |
| Event verbs | **CONFORMANT-ish** | Uses dotted verbs aligned with contract examples |
| TUI/qyvora-tui linkage | **PARTIAL** | Go module linked, build disabled; `banner` references it |
| Shared contracts | **NOT ADOPTED** | Does not import `qyvora-common`; implements locally |
| Conformance runner | **INACCURATE** | Skips `CapJSON` for `toha3ee` (line 147) and stamps version, hiding defects |

## 11. AI orchestration readiness

| Requirement | Status | Notes |
|-------------|--------|-------|
| Identity/version discovery | **BLOCKED (false)** | Reports `dev`/`none` — orchestrator cannot reliably version-gate; must detect or reject |
| Capability discovery | **PARTIALLY READY** | 73 modules discoverable; but authorization claim false, TUI listed but missing, module count docs wrong |
| Command enumeration | **PARTIAL** | Missing accurate picture of what runs (TUI/REPL absent) |
| Invocation | **READY** | `eval/run/script` programmable; action grammar under tiers; `--no-sudo` for testing |
| Monitoring | **READY** | JSONL events with execution id, module lifecycle, host/cred/session events |
| Result interpretation | **PARTIAL** | Report JSON exists but no canonical envelope/schema_version; tool-specific |
| Safety/authorization | **BLOCKED** | Declared but unenforced — orchestrator cannot rely on it |
| Prerequisite checks | **PARTIAL** | Preflight exists; iface/root/deps vary, not surfaced as machine-readable prerequisites in capabilities |
| Cancellation/interrupt | **READY** | Exit 130 documented; cleanup logic in `run()` |
| Offline tests | **READY** | `--no-sudo` allows safe probing |

**Verdict:** Feature-rich and monitorable in structure, but **orchestration is not safe/reliable** due to (1) version reporting, (2) false authorization claim, (3) TUI/REPL advertised but absent, (4) no canonical result envelope/schema_version.

## 12. CLI, repository-layout, and documentation findings

### 12.1 CLI correctness
| Finding | Evidence | Priority |
|---------|----------|----------|
| Version/dev build | Both binaries report `dev`/`none`; Makefile lacks ldflags; goreleaser has ldflags | **P0** |
| Authorization model false | `capabilities.go:90-92` no implementation | **P0** |
| TUI command missing in binary | `cmd/toha3ee/tui.go` build-ignored; probe returns unknown command; capabilities lists it | **P1** |
| Bare invocation not REPL | README claims `toha3eeλ>`; actual prints help; leftover header in ui.go:322 | **P1** |
| Module count docs wrong | README 70 vs 73; Module-Reference says 70 | **P1** |
| `wizard` exists but not in old help? Help shows it; binary has it | OK but advertised surfaces need consistency | P2 |
| `updates` command exists; selfupdate code present | OK | — |

### 12.2 Repository layout
- Clean Go module, many packages, good separation (`attacks/*`, `netx/*`, `session`, `safety`).
- **Root binaries:** `toha3ee` (16.5 MB) and `bin/toha3ee` (16.5 MB) untracked; `.toha3ee_history` untracked.
- **Scripts:** `scripts/install.sh` differs from root `install.sh` (different byte/line); `scripts/install.ps1` differs from root. Both present.
- **Caplets:** 5 sample caplets present (`basic-recon`, `mitm-arp`, `ntlm-capture`, `phishing`, `wireless-scan`) — useful for auth model testing once enforced.
- **Docs:** `docs/Declined-Techniques.md` excellent; `docs/Module-Reference.md` detailed but count stale; `man/toha3ee.1` accurate on exit codes.
- **No zero-byte files** (count 0). Tracked files are substantive.
- **TUI source build-ignored:** technical debt / half-implemented feature.

### 12.3 Documentation accuracy
| Doc | Claim | Reality |
|-----|-------|---------|
| README:29 | "all 70 modules" | 73 live modules |
| README:111,136,198 | TUI/REPL/bare REPL | TUI not built; bare prints help |
| capabilities.authorization_model | requires `--authorized` or `AUTHORIZED=yes` | not implemented |
| Module-Reference.md intro | 70 modules | 73 modules |

## 13. Testing and verification findings

| Check | Command | Result |
|-------|---------|--------|
| Tests | `GOPROXY=off go test ./... -count=1 -timeout 180s` | **PASS** (exit 0) |
| Vet | `GOPROXY=off go vet ./...` | **PASS** (exit 0) |
| Version JSON | `version -o json --no-sudo` | `dev`/`none` (non-conformant) |
| Capabilities all formats | `capabilities -o {terminal,json,yaml,markdown,html} --no-sudo` | all exit 0 (YAML header+JSON) |
| Modules count | `modules -o json --no-sudo` | 73 modules, 10 categories |
| Invalid format | `capabilities -o bogus` | exit 2, correct message |
| Unknown command/flag | `bogus` / `--bogus` | exit 2 |
| Empty eval | `eval ""` | exit 2, usage message |
| Missing script | `build /nonexistent.toha3ee` | exit 1, file-not-found |
| No report | `report` | exit 1, file-not-found |
| Wizard help | `wizard --help` | exit 0 |
| TUI/REPL/shell/interactive/console | all | exit 2 (unknown command) |
| Script build | `build scripts/full-pipeline.toha3ee --no-sudo` | exit 0, plan printed |

Tests are extensive (65 test files, ~7.5k LOC). Coverage exists for events, safety, caplets, release naming, etc. Gaps: no tests asserting the false authorization model; no tests for TUI absence; no conformance-shape tests.

## 14. Prioritized gaps and recommendations

**P0 — critical**

1. **Enforce or correct authorization model**  
   *Why:* Declared in capabilities and implies safety gating; currently unenforced (auto-confirm risk only). Violates "do not claim functionality not implemented" and could mislead operators/orchestrators.  
   *Evidence:* `capabilities.go:90-92`, grep for `AUTHORIZED/--authorized` found nothing, `main.go:681` auto-confirms risk.  
   *Recommendation (later phase):* Add `--authorized` flag, `AUTHORIZED` env, caplet `authorized` directive, thread through session/preflight, log authorization, block active modules if not authorized. *Or* change the capability claim to truth.  
   *Prerequisite:* Config/session plumbing, tests.

2. **Fix version stamping for dev/build**  
   *Why:* Conformance and orchestration need real version/commit; current `dev`/`none` fails contract expectations and is masked by conformance runner.  
   *Evidence:* `version/version.go`, `Makefile:40` has no ldflags, `goreleaser.yaml:43-47` has them.  
   *Recommendation:* Update `Makefile` to inject `-X ...Version/...Commit/...Date/...BuildUser` (git describe + commit + date), fail or warn on unstamped in CI/release, ensure local builds report real values or `dev-<commit>`.  
   *Prerequisite:* git available.

**P1 — high**

3. **Resolve TUI/REPL surface**  
   *Why:* Capabilities lists `tui`, help lists it, README documents REPL; build-ignored + binary says unknown. Orchestration confusion.  
   *Recommendation:* Either restore TUI build or remove from capabilities/commands/docs/help. If removing, clean `ui.go:322` leftover.

4. **Sync module count in docs**  
   *Why:* 70 vs 73 is inaccurate.  
   *Evidence:* `README.md:29`, `docs/Module-Reference.md` intro vs verified 73.

5. **Add `schema_version` to `session.Report` JSON**  
   *Why:* Event stream has it; report used by `report -o json` lacks it.  
   *Recommendation:* Add `schema_version` to `Report` struct.

6. **Make capabilities contract truthful**  
   *Why:* Lists non-existent `tui` as command; authorization model false.  
   *Recommendation:* Remove `tui` until implemented, correct authorization text or implement gating.

**P2 — medium**

7. **Script installers differ** (`root/install.*` vs `scripts/install.*`): document which is canonical or unify.
8. **Add machine-readable prerequisites** (iface/root/CAP_NET_RAW needs) to capabilities/modules for orchestrator.
9. **Harden `--events stdout` + machine format conflicts** (already handled in `run()` but test coverage).
10. **Document module limitations more prominently** in `modules -o json` (Limitations exist in code but not surfaced).

**P3 — low**

11. Stale history file `.toha3ee_history` (untracked) — not harmful.
12. Consider `report` command behavior when no session state exists (exit 1 is reasonable, message clear).

## 15. Dependencies, prerequisites, and unresolved questions

**Dependencies (`go.mod`):** `qyvora-script v0.1.0`, `qyvora-tui v0.11.0`, `cobra`, `readline`, `gopacket`, `dns`, `goproxy`, `termenv`. Go 1.26.5.

**Prerequisites:** Many modules require root/CAP_NET_RAW, monitor mode for wireless, specific interfaces. `--no-sudo` disables some paths but scanning/MITM/wireless need privileges.

**Unresolved questions:**
1. Is the authorization model supposed to be enforced now or was it aspirational? The capabilities document states it as fact.
2. Is TUI intentionally disabled (WIP) or broken? `tui.go` is `//go:build ignore` with no explanation in code.
3. Why does conformance runner skip `CapJSON` for toha3ee and stamp version? Masks defects; should be fixed or documented.
4. Should `session.Report` adopt `contract.Result` envelope? Would improve orchestration.
5. Are `scripts/install.*` vs root installers both maintained? They differ.

## 16. Statement of no implementation

No feature was implemented, no code was refactored, no dependency was added or changed, and no existing user work was discarded during this audit. The only file created is this `AUDIT.md`. All probes were run with `--no-sudo` where applicable and isolated outside the repo; tests/vet ran without modifying source. `git status` remained clean before and after (only this new untracked file). Every item in §§8 and §14 is a proposal for a later, separately authorised phase.
