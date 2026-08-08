# Architecture

toha3ee is built around a single idea: **everything is a module**, and every
module obeys one lifecycle contract. The framework core knows nothing about
what any attack does — it only knows how to run, verify and clean up modules.

## High-level layout

```
┌─────────────────────────────────────────────────────────────┐
│  cmd/toha3ee  CLI (cobra): console / wizard / eval / run /  │
│               script / build / modules / version             │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  internal/session  REPL, wizard, caplet & script runner,    │
│                    command dispatch, report                   │
└───────┬───────────────────────────────┬─────────────────────┘
        │                               │
┌───────▼──────────┐          ┌─────────▼─────────────────────┐
│ attacks registry │          │   safety  cleanup / heartbeat │
│ (module contract)│          │   lifecycle + risk gates      │
└───────┬──────────┘          └─────────┬─────────────────────┘
        │                               │
        │  self-register via init()     │
┌───────▼───────────────────────────────────────────────────┐
│  attack packages under internal/attacks/                  │
│  mitm · espionage · auth · recon · osint · enum · web ·   │
│  switch · wlan · post                                     │
│  each uses netx protocol primitives + store + events       │
└───────┬──────────────────────────────────┬────────────────┘
        │                                  │
┌───────▼────────────┐        ┌────────────▼───────────────┐
│ internal/netx      │        │ internal/store  shared data │
│ ARP DHCP DNS NDP   │        │ store + event bus (single   │
│ 802.11 SMB SNMP    │        │ source of truth for reports)│
│ LDAP RPC proxy …   │        └────────────┬────────────────┘
└────────────────────┘                     │
              ┌────────────────────────────▼────────────────┐
              │ internal/vectors  attack-vector profiler     │
              │ internal/ui  console rendering (banner, HUD, │
              │             tables, glyphs)                  │
              │ internal/config  JSON config                 │
              │ internal/script  .toha3ee language           │
              │ pkg/certutil  framework CA + TLS certs       │
              └───────────────────────────────────────────────┘
```

## Module contract

Every module implements the `attacks.Module` interface
(`internal/attacks/registry.go`):

| Method | Responsibility | Must return |
|--------|----------------|-------------|
| `Meta()` | static metadata: ID, category, risk, targets, description, limitations | `ModuleMeta` |
| `Preflight(ctx)` | validate the environment; auto-fix what it can | `PreflightReport` with **no blocked checks** |
| `Run(ctx, opts)` | do the work; block until `ctx.Done` or error | `error` |
| `Verify(ctx)` | prove the attack worked; quantify impact | `Impact` |
| `Cleanup(ctx)` | restore the network, always | `error` |

Modules **self-register** in their package `init()`:

```go
func init() { attacks.Register(&MyModule{}) }
```

Duplicate IDs panic at startup so mistakes surface immediately. The registry
(`attacks.Registry`) is the only place modules are known; the CLI blank-imports
every category package so registration happens on `init`.

### The lifecycle

1. **Preflight** — modules run environment checks and report each as OK /
   fixed / fixable / blocked. `Run` is refused if anything is blocked. Examples:
   *root* (`safety.RequireRoot`), *IP forwarding* (`safety.EnableIPForward`,
   which restores the prior value on cleanup), *interface mode* (monitor mode
   for WLAN), *target presence*.
2. **Run** — the attack. Long-running modules (ARP spoof, proxies, sniffers)
   loop in a goroutine and must:
   - `select` on `ctx.Done` to stop cleanly when `off <module>` is issued;
   - call `ctx.Heartbeat()` periodically so the watchdog can detect a dead
     loop;
   - register a cleanup with `ctx.Safety.RegisterCleanup(...)`.
3. **Verify** — produce an `Impact{Summary, Metrics}` proving the result
   (e.g. "3 credentials captured" with counts).
4. **Cleanup** — undo everything: restore MAC tables, unregister DNS entries,
   stop forwarding, flush the ARP cache. The safety manager runs *all*
   registered cleanups even on panic or SIGINT, so the network is restored.

### AttackCtx

`Run`/`Verify`/`Cleanup` receive an `*attacks.AttackCtx`:

| Field | Purpose |
|-------|---------|
| `Conf` | live config (module knobs via `Get*`) |
| `Store` | shared host / credential / session / event store |
| `Iface` | the primary network interface |
| `Bus` | process-wide event bus (`events.TopicLog`, `events.TopicCredFound`) |
| `Safety` | cleanup registry + heartbeat |
| `Done` | closed when the module is told to stop / session shuts down |
| `Heartbeat` | call periodically from long loops |
| `State` | per-instance key/value bag for passing state Run → Verify → Cleanup |
| `Out` / `Logger` | console + structured logging |

## Risk model

Every module declares a `Risk` (`info` → `low` → `medium` → `high` →
`critical`). The wizard shows the **blast radius** and requires explicit
confirmation for High/Critical modules (persisted in `confirmed_risks`). See
[Security & responsible use](security.md) for the full model.

## Stealth engine

`internal/stealth` ships a randomized, jittered profile applied by default to
every packet-sending module — there is nothing to enable. Key behaviours:

| Behaviour | Default |
|-----------|---------|
| Probe-target **shuffle** so sweeps never walk the subnet in order | on |
| Per-probe **jitter** before each send | `3ms` max |
| **Burst** sending with pauses between bursts | burst 64, pause 20ms |
| Random **source port** per probe (ephemeral range) | on |
| Random **IP ID**, **TTL**, **TCP sequence** and **window** | on |
| Random Ethernet **padding** instead of zeros | on |
| Occasional **DF-bit clear** to break tool signature | on |
| Realistic browser **user agents** for HTTP probing | on |

Tunables are read per module: `set net.scan.stealth_jitter 5ms`,
`set service.synscan.stealth_burst 128`, `set <module>.stealth false`.
Disabling stealth is not supported by design intent; `stealth_test.go` pins
the defaults.

## Data flow

- Modules write observations into `store.Store`: hosts (`Host` with ports,
  OS guess, vendor), credentials (`Cred` with service/source/victim),
  sessions, and an event log.
- Events also flow over the `events.Bus` (`TopicLog`, `TopicCredFound`) so
  the HUD and listeners stay live.
- `report.generate` renders a Markdown assessment purely from `Store` state —
  the report is only ever as good as what the session captured.
- `internal/vectors` profiles the host set and ranks attack vectors (e.g.
  "host X runs HTTP → suggest `web.dir` / `http.proxy`").

## Scripting engine

`internal/script` is a small lexer/parser/engine for the `.toha3ee` language.
Every script statement drives the *same* module lifecycle and risk gates as
the REPL, so **a script cannot do anything the console cannot**. See
[Scripting reference](scripting.md).

## Layer reference

| Path | Purpose |
|------|---------|
| `cmd/toha3ee` | CLI entrypoint; blank-imports every attack category |
| `internal/ui` | console rendering: banner, palette, sections, tables, HUD |
| `internal/session` | REPL, wizard, caplet/script runners, report |
| `internal/script` | `.toha3ee` lexer, parser, engine |
| `internal/attacks/` | all modules by category |
| `internal/netx/` | protocol primitives (ARP, DHCP, DNS, NDP, 802.11, SNMP, LDAP, RPC, SMB/NTLM, proxy, sniff) |
| `internal/hijack` | HTTP/HTTPS MITM proxy + credential/session interception |
| `internal/phish` | captive-portal phishing and login-page clones |
| `internal/store` | concurrency-safe shared data store + event log |
| `internal/safety` | cleanup registry, heartbeat watchdog, preflight/risk gates |
| `internal/stealth` | packet randomization and pacing |
| `internal/vectors` | attack-vector profiling |
| `internal/config` | JSON config loading |
| `internal/oui` | MAC vendor database |
| `pkg/certutil` | framework CA and per-host TLS certificates |

## Next steps

- [Module reference](module-reference.md) — the 73 modules and their settings
- [Contributing](contributing.md) — how to add a module to this architecture
