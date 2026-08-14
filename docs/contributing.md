# Contributing

Developer guide for toha3ee. For the fast version see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Scope

toha3ee is an **authorised-engagement network security framework**. Accepted
contributions: recon, protocol testing, credential testing, network
manipulation, reporting, docs, CI, tests.

**Not accepted:** malware/APT tradecraft — EDR evasion, rootkits, host
persistence, command-and-control, anti-forensics, or weaponised exploit
delivery. Contributions must operate under the responsible-use policy in
[Security & responsible use](security.md).

## Environment

```sh
sudo apt install libpcap-dev   # Linux
make fmt vet test build        # all quality gates
go test ./...                  # the full suite
```

## Codebase map

- `cmd/toha3ee/` — cobra CLI; blank-imports every attack category so modules
  self-register.
- `internal/attacks/` — one package per category, each implementing the
  `attacks.Module` contract.
- `internal/netx/` — protocol clients (ARP, DHCP, DNS, NDP, 802.11, SNMP,
  LDAP, RPC, SMB/NTLM, proxy). New protocol support starts here.
- `internal/store/` — concurrency-safe shared data layer (hosts, creds,
  sessions, events). **All cross-module state goes through this.**
- `internal/safety/` — cleanup registry, heartbeat watchdog, preflight/risk.
- `internal/stealth/` — packet randomization/pacing shared by every
  packet-sending module.
- `internal/script/` — `.toha3ee` lexer/parser/engine.
- `internal/vectors/` — profiling/ranking of attack vectors.
- `internal/ui/` — console rendering.
- `docs/` — this documentation.

## Writing a module

Modules are the unit of functionality. A minimal module:

```go
package mycat

import "github.com/QYVORA/qyvora-toha3ee/internal/attacks"

func init() { attacks.Register(&MyModule{}) }

type MyModule struct{}

func (*MyModule) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "mycat.mything",
		Category:    "mycat",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Description: "what it does, honestly",
		Limitations: "known environmental limits",
	}
}

func (*MyModule) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("targets", "resolved")
	return rep, nil
}

func (*MyModule) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// do the work; for long loops select on ctx.Done and call ctx.Heartbeat()
	return nil
}

func (*MyModule) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	imp := &attacks.Impact{Summary: "done"}
	return imp, nil
}

func (*MyModule) Cleanup(ctx *attacks.AttackCtx) error {
	return nil // restore the network, always
}
```

Checklist:

1. Read config through `ctx.Conf.Get*` with sane defaults, never hardcode user
   facing knobs.
2. Write observations into `ctx.Store` / emit events via `ctx.Emit`; render
   user output via `ctx.Printf` with status glyphs.
3. Long-running modules: `select` on `ctx.Done`, call `ctx.Heartbeat()`,
   register cleanups with `ctx.Safety.RegisterCleanup`.
4. Honest risk and limitations in `Meta()`.
5. Unit test in the same package. Registry-test pinning: add your module ID to
   `internal/attacks/registry_test.go`.
6. Make the module reachable: add a blank import in `cmd/toha3ee/main.go`,
   update `README.md` and `docs/module-reference.md` tables.
7. `gofmt`, `go vet`, `go test ./...` green.

## Conventions

- Comments only where they earn their place; prefer package doc comments.
- Follow existing glyph/output style — never print to `os.Stdout` directly.
- Never reach into another module's internals; use the store and event bus.
- New external dependencies must be justified; prefer stdlib + existing deps.
- Keep the module catalogue in `attacks.Registry` as the single source of
  truth; the live listing is generated from it (`toha3ee modules`). The
  human-readable `docs/module-reference.md` is maintained by hand, so keep
  its module table in sync when adding or renaming a module.

## Testing

```sh
go test ./...        # full suite (store, frame crafters, stealth, registry, modules)
go vet ./...
make fmt            # fails on unformatted Go files
```

Network-touching tests are avoided; protocol clients are tested with canned
payloads and offline parsers. Keep it that way so CI stays hermetic.

## Branching, commits, PRs

- Branch from `main`: `git checkout -b feat/my-thing`.
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `build:`, `chore:`.
- Open a PR; CI (`.github/workflows/ci.yml`) runs build + vet + test + fmt
  across OSes. CodeQL runs static analysis.
- The PR template asks for: what changed, why, testing performed, and
  confirmation of the responsible-use policy.

## Code review

Reviewers check for: scope compliance (no malware/APT tradecraft), honest risk
classification, cleanup correctness (network must be restored on every path),
stealth defaults (new packet-sending modules must use the stealth engine),
and concurrency safety (all shared state via the store).
