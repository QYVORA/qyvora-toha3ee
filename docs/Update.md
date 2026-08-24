# Updating toha3ee

How to update to the latest version, reinstall, and keep your configuration
and collected data between updates.

## Self-update (recommended)

```sh
toha3ee updates        # `toha3ee update` works as an alias
```

The command never escalates privileges on its own (it is a read-only verb for
the sudo re-exec logic) and requires no Go toolchain, Git, or source checkout.

What it does:

1. Reads the installed version — the same value `toha3ee version` reports.
2. Queries the official QYVORA GitHub releases
   (`github.com/QYVORA/qyvora-toha3ee/releases`); no other source is ever contacted.
3. Compares versions semantically (`v1.10.0 > v1.9.0`) and reports whether an
   update exists.
4. Downloads the release artifact built for your platform
   (`toha3ee_linux_amd64.tar.gz`, `toha3ee_darwin_arm64.tar.gz`,
   `toha3ee_windows_amd64.zip`; windows-on-arm64 runs the x64 build).
5. Verifies its SHA-256 against the per-artifact `.sha256` checksum published
   with the release; installation never proceeds on a mismatch.
6. Extracts only the `toha3ee` binary from the archive, swaps it in
   atomically, and preserves the original file permissions.
7. Cleans up all temporary files and confirms the new version.

Notes:

- If the binary lives somewhere like `/usr/local/bin` that your user cannot
  write to, the updater stops with clear guidance instead of escalating on its
  own. Re-run with the appropriate permissions or reinstall into `~/.local/bin`.
- Downgrades are refused: an installed version newer than the latest release is
  left alone.
- Offline or GitHub unreachable? The command fails cleanly; your installed
  binary stays exactly as it was.

Use `-o json` or `-o markdown` for machine-readable output.

## Check your current version

```sh
toha3ee --no-sudo version
```

## Update an install (prebuilt)

Re-run the installer; it always fetches the latest release, so an existing
install is upgraded in place. Your binary is replaced, your config and
session data are untouched. Use this instead of `toha3ee updates` when you
also want the desktop entry/icon refreshed.

```sh
# user install (defaults to ~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh

# system-wide install (requires root)
curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sudo sh

# pin a specific release instead of latest
TOHA3EE_VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.ps1 | iex
```

## Update a source install

If you installed from a git checkout, pull and rebuild:

```sh
git pull
make install          # rebuilds and reinstalls (~/.local/bin, or /usr/local/bin as root)
```

If the build needs the man pages re-generated or the desktop integration
refreshed, `make install` handles both (it installs `man/*` and the app
icon/.desktop entry).

## Reinstall from source (full rebuild)

To force a clean rebuild of the current checkout into the default location:

```sh
sh scripts/install.sh --from-source
```

Or target a custom prefix:

```sh
sh scripts/install.sh --from-source --prefix ~/bin
```

`--from-source` always builds from the current directory when it contains the
toha3ee module; otherwise it clones the repository first.

## What is preserved

| Item | Location | Preserved on update? |
|------|----------|----------------------|
| Config file | `toha3ee.json` (current dir) | yes |
| Session data / store | the store kept under your working directory | yes |
| Shell PATH line | your shell rc (e.g. `~/.zshrc`) | yes |
| Reports | `toha3ee-report.md` in your working directory | yes |

## What is replaced

- the `toha3ee` binary itself,
- the man pages (`toha3ee(1)`, `scripting(7)`, `security(7)`) if installed,
- the app icon + `.desktop` entry on Linux.

## After updating

1. Verify the new version: `toha3ee --no-sudo version`
2. Check for new modules: `toha3ee --no-sudo modules`
3. Re-validate any scripts you run: `toha3ee build your-script.toha3ee`

## Rollback

Binary releases are checksum-verified at install time. To roll back to a
previous release, install with the pinned tag:

```sh
TOHA3EE_VERSION=<previous-tag> curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh
```

See the [CHANGELOG](../CHANGELOG.md) for what changed between versions.
