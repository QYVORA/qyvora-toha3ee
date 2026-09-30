# Support

## Documentation

Start with the [README](README.md), which covers installation, configuration,
and the command reference. `toha3ee help` lists everything available;
`toha3ee modules` prints the live catalogue of all **70 registered modules**
across 10 categories. Full per-module detail is in
[docs/Module-Reference.md](docs/Module-Reference.md).

## Getting help

- Open an issue for bugs and feature requests (see
  [CONTRIBUTING.md](CONTRIBUTING.md)).
- The repository is hosted under `github.com/QYVORA/qyvora-toha3ee`. For
  issues on other QYVORA projects, use their respective repositories.
- Report security vulnerabilities privately per [SECURITY.md](SECURITY.md) —
  never in a public issue.

## Build and platform requirements

TOHA3EE is the one framework in the ecosystem that **requires elevated
privileges and a C toolchain**:

- it binds `libpcap`, so it is built with `CGO_ENABLED=1`;
- `cmd/toha3ee/main.go` escalates via `sudo` at startup when not already root.

If `toha3ee` will not start, check for `libpcap-dev` and a working `sudo`
first. `qyvora-dist` records this in `tools.def` (`Q_CGO_ENABLED=1` for this
tool, `1` for every other tool).

## Operating responsibility

TOHA3EE is an **authorized-engagement** tool. It poisons, redirects, and
intercepts network traffic by design. It must only be used on networks you
own or are explicitly authorised to test, inside a lab or an isolated virtual
network. Read [SECURITY.md](SECURITY.md) and
[docs/Security.md](docs/Security.md) before organizational use, and confirm
authorization with the documented `--authorized` / `QYVORA_AUTHORIZED`
mechanics.
