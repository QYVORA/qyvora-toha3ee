## What changed

Describe the change and the problem it solves.

## Why

Link the issue this addresses (if any) and explain the rationale.

## Testing performed

- [ ] `make fmt` clean
- [ ] `go vet ./...` clean
- [ ] `go test ./...` green
- [ ] Manual verification described below

Describe what you verified and in which environment (lab network, VM, etc.).

## Module registration

- [ ] Module blank-imported in `cmd/toha3ee/main.go` (if a new module)
- [ ] ID added to `internal/attacks/registry_test.go`
- [ ] `README.md` / `docs/Module-Reference.md` module tables updated

## Responsible use

I confirm this contribution operates within the scope defined in
`docs/Security.md` (recon, protocol/credential testing, network manipulation,
reporting) and does not implement malware/APT tradecraft.
