# Contributing to toha3ee

Thanks for wanting to contribute. This project is a **dual-use network security
tool** — it is research and authorised-penetration-testing software. Before you
do anything else, read [`docs/Security.md`](docs/Security.md) and agree that
your contribution will only be used on networks you own or are authorised to
test.

**Scope note:** contributions that implement or assist with malware/APT
tradecraft — EDR evasion, rootkits, host persistence, command-and-control,
anti-forensics, or weaponised exploit delivery — are **not** accepted. toha3ee
is an engagement framework: reconnaissance, protocol testing, credential
testing, network manipulation and reporting. If your idea falls outside that,
it will likely be closed.

## Development setup

Requirements: Go 1.26+, and libpcap headers on Linux.

```sh
# Debian/Ubuntu
sudo apt install libpcap-dev

git clone https://github.com/QYVORA/qyvora-toha3ee.git
cd toha3ee

# quality gates that CI runs
make fmt vet test build
```

Run the interactive console (needs root for raw sockets):

```sh
sudo ./toha3ee --iface eth0
# or without a real interface for dry runs:
./toha3ee --no-sudo build scripts/full-pipeline.toha3ee
```

## Project layout

| Path | Purpose |
|------|---------|
| `cmd/toha3ee/` | CLI entrypoint (cobra); blank-imports every attack category |
| `internal/attacks/` | all attack modules, one package per category |
| `internal/netx/` | protocol primitives (ARP, DHCP, DNS, NDP, 802.11, SNMP, LDAP, RPC, SMB/NTLM, proxy, …) |
| `internal/script/` | the `.toha3ee` scripting language (lexer/parser/engine) |
| `internal/session/` | REPL, wizard, caplet runner, script runner |
| `internal/store/` | shared concurrency-safe data store + event bus |
| `internal/safety/` | cleanup/heartbeat lifecycle + preflight/risk gates |
| `internal/vectors/` | attack-vector profiling engine |
| `internal/ui/` | console rendering (banner, tables, HUD, glyphs) |
| `docs/` | user + developer documentation |

## Adding a module

Modules self-register; there is no central list to edit for the tool to see
them (the registry test pins IDs though).

1. Pick a category package under `internal/attacks/` (create one if needed).
2. Implement the `attacks.Module` contract — see
   [`docs/Architecture.md`](docs/Architecture.md#module-contract):

   ```go
   func init() { attacks.Register(&MyModule{}) }

   type MyModule struct{}

   func (*MyModule) Meta() attacks.ModuleMeta { /* ID, Category, Risk, Targets, Description, Limitations */ }
   func (*MyModule) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) { /* check + auto-fix */ }
   func (*MyModule) Run(ctx *attacks.AttackCtx, opts map[string]string) error { /* the work; respect ctx.Done */ }
   func (*MyModule) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) { /* prove it worked */ }
   func (*MyModule) Cleanup(ctx *attacks.AttackCtx) error { /* restore the network, always */ }
   ```

3. Long-running modules must `select` on `ctx.Done` and call `ctx.Heartbeat()`
   periodically so the watchdog can detect a dead loop.
4. Add a unit test in the package. The full suite runs `go test ./...`.
5. If your module should appear in the CLI, ensure `cmd/toha3ee/main.go` has a
   blank import for its package. Then update
   `internal/attacks/registry_test.go` and the module table in
   `README.md` / `docs/Module-Reference.md`.

See [`docs/Contributing.md`](docs/Contributing.md) for the full developer guide.

## Coding conventions

- **No comments unless they earn their place** — prefer a package doc comment
  and self-describing names.
- `gofmt`-clean (enforced by `make fmt` and CI).
- `go vet ./...` clean.
- Concurrency: all shared state goes through `internal/store`; never reach into
  another module's internals.
- Output: modules log via `ctx.Printf` with status glyphs (`[*]`, `[+]`, etc.)
  and record structured data through `ctx.Emit` / the store — never print to
  `os.Stdout` directly.

## Commit & PR process

1. Branch from `main`: `git checkout -b feat/my-thing`.
2. Make focused commits with conventional prefixes: `feat:`, `fix:`,
   `docs:`, `test:`, `refactor:`, `build:`, `chore:`.
3. Run `make fmt vet test build` locally and make CI green.
4. Open a PR. The template asks for: what changed, why, how it was tested,
   and a confirmation of the responsible-use policy.
5. Address review; maintainers merge.

## Reporting issues

- Bug reports: use the **Bug report** template (`.github/ISSUE_TEMPLATE/`).
- Feature requests: use the **Feature request** template.
- Security issues: **do not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md).

## Community

Be kind, be precise, and keep contributions within the engagement-framework
scope. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
