#!/usr/bin/env sh
#
# TOHA3EE CLI — DEPRECATED installer entry point
#
# This file used to be toha3ee's real installer. It is now a thin shim that
# forwards to the canonical installer at the repository root, so there is one
# audited implementation instead of two that had already drifted apart.
#
# The old script did not verify checksums, did not validate the executable
# format, had no Android handling, and had no uninstall. The canonical installer
# has all of those. Keeping this file avoids breaking the Makefile and the
# documentation URLs that point here; it is not a second implementation.
#
#   Canonical entry points:
#     curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-toha3ee/main/install.sh | bash
#     # Windows:
#     irm https://raw.githubusercontent.com/QYVORA/qyvora-toha3ee/main/install.ps1 | iex
#
set -eu

CANONICAL_URL="https://raw.githubusercontent.com/QYVORA/qyvora-toha3ee/main/install.sh"

warn() { printf 'warning: %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Locate the canonical installer.
#
# This only works when the shim is run as a file. The old script could be piped
# straight into `sh`, in which case there is no file on disk to resolve a
# sibling path against. Detect that and say what to do instead of failing with
# a confusing "not found" — this is a real usage difference, not a formality,
# so it is worth being explicit about.
# ---------------------------------------------------------------------------
case "$0" in
    */*) ;;
    *)
        warn "scripts/install.sh cannot run when piped into sh."
        warn "Use the canonical installer instead:"
        warn "  curl -fsSL $CANONICAL_URL | bash"
        exit 2
        ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANONICAL="$SCRIPT_DIR/../install.sh"

if [ ! -f "$CANONICAL" ]; then
    warn "canonical installer not found at $CANONICAL"
    warn "Fetch it directly:"
    warn "  curl -fsSL $CANONICAL_URL | bash"
    exit 2
fi

# ---------------------------------------------------------------------------
# Re-exec under bash.
#
# The canonical installer is bash-specific (set -o pipefail, [[ ]], arrays), and
# so is the argument translation below: an install directory may legitimately
# contain spaces ("--prefix ~/my tools"), and building the forwarded argument
# list as a string in POSIX sh word-splits it into two arguments. Doing the
# translation in bash with a real array keeps such a path intact.
#
# The guard variable makes this a one-time hop even though the Makefile invokes
# this file with `sh`.
# ---------------------------------------------------------------------------
if [ -z "${QYVORA_SHIM_REEXEC:-}" ]; then
    command -v bash >/dev/null 2>&1 || {
        warn "bash is required to run the canonical installer."
        exit 2
    }
    QYVORA_SHIM_REEXEC=1
    export QYVORA_SHIM_REEXEC
    exec bash "$0" "$@"
fi

# =========================== bash from here on ==============================

warn "scripts/install.sh is deprecated and will be removed."
warn "Forwarding to the canonical installer: install.sh"

# Translate the old interface. Only flags this shim historically accepted are
# remapped; everything else passes through untouched, so the canonical installer
# stays the authority on what is valid and can gain flags without this file
# being updated.
args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --from-source)
            # The old script's "always build the checkout" flag. The canonical
            # installer spells it as an environment variable.
            QYVORA_SOURCE=1
            export QYVORA_SOURCE
            shift
            ;;
        --prefix=*)
            args+=(--prefix "${1#--prefix=}")
            shift
            ;;
        --prefix)
            if [ "$#" -lt 2 ]; then
                warn "--prefix requires a value"
                exit 1
            fi
            args+=(--prefix "$2")
            shift 2
            ;;
        *)
            args+=("$1")
            shift
            ;;
    esac
done

# TOHA3EE_VERSION was the old pin mechanism; QYVORA_VERSION is the shared one.
# Honouring it keeps existing automation and pinned-tag installs working.
if [ -n "${TOHA3EE_VERSION:-}" ]; then
    QYVORA_VERSION="$TOHA3EE_VERSION"
    export QYVORA_VERSION
fi

exec bash "$CANONICAL" ${args+"${args[@]}"}
