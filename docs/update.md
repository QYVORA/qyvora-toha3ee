# Updating toha3ee

How to update to the latest version, reinstall, and keep your configuration
and collected data between updates.

## Check your current version

```sh
toha3ee --no-sudo version
```

## Update an install (prebuilt)

Re-run the installer; it always fetches the latest release, so an existing
install is upgraded in place. Your binary is replaced, your config and
session data are untouched.

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
