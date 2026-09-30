# Governance

## Maintainers

The project is maintained by QYVORA OffSec. Maintainer contact for security
issues is provided in [SECURITY.md](SECURITY.md).

## Decision process

- **Small fixes and docs:** reviewed and merged by a maintainer.
- **New features and API changes:** discussed in an issue first, then
  implemented in a PR.
- **Security-sensitive changes:** reviewed by a maintainer and referenced
  against [SECURITY.md](SECURITY.md).

## Releases

- Semantic versioning per [CHANGELOG.md](CHANGELOG.md).
- Releases are tagged from `main` after CI passes.
- `main` must remain buildable and green.

## Module registry governance

TOHA3EE's 70 registered modules are part of its public contract, and the
registry enforces this in code:

- `internal/attacks.Register` **panics** on an empty or duplicate module ID, so
  a module cannot silently shadow another in the REPL or wizard.
- `List()` sorts by ID, which keeps REPL completion and `toha3ee modules`
  output deterministic.
- `TestRegistryCompleteness` pins the catalogue, so removing a module is a
  deliberate, test-visible change.
- Changes to a module ID are therefore **breaking changes** and require a
  major/minor version bump plus a [CHANGELOG.md](CHANGELOG.md) entry.

See [docs/Module-Reference.md](docs/Module-Reference.md) for the catalogue and
each module's risk metadata.

## Safety and preflight governance

Every module carries risk metadata and is subject to the safety manager and
preflight checks. The `Cleanup()` contract is mandatory: a module that mutates
network state must restore it on exit, including on interrupt. Breaking that
contract is treated as a security defect, not a style issue — see the
"What is in scope" section of [SECURITY.md](SECURITY.md).

## Scope of authority

Maintainers may decline contributions that conflict with the project's purpose
(authorized network security assessment, no unauthorized access, no
persistence or malware delivery) even if technically sound. This is a
deliberate boundary, not an error.

## Community

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Code
of conduct reports are handled by the maintainers documented there.
