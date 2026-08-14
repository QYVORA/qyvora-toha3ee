#!/bin/sh
# toha3ee installer for Linux and macOS (also works on other BSDs).
#
# Fetches the latest prebuilt binary from the GitHub release matching this
# platform, verifies its SHA-256 checksum, installs it and adds the install
# directory to your PATH. If no release binary is available yet it falls back
# to building from source (requires Go, and libpcap on Linux; macOS ships it).
# On Linux it also installs the app icon and a .desktop entry so toha3ee shows
# up in the GNOME shell with its logo, and (from a source checkout) the man
# pages so `man toha3ee` works.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.sh | sh
#   curl -fsSL ... | sudo sh          # install to /usr/local/bin
#   sh scripts/install.sh --prefix ~/.local/bin
#
# Options (env or flags):
#   TOHA3EE_VERSION   pinned release tag, e.g. v0.1.0 (default: latest)
#   TOHA3EE_PREFIX    install directory (default: /usr/local/bin as root, else ~/.local/bin)
#   TOHA3EE_SKIP_PATH skip editing your shell rc file (flag: --no-path)
#   --from-source     always build from the current checkout instead of downloading
set -eu

REPO="qyvora/qyvora-toha3ee"
MODULE="github.com/QYVORA/qyvora-toha3ee"
BIN="toha3ee"
VERSION="${TOHA3EE_VERSION:-}"
PREFIX="${TOHA3EE_PREFIX:-}"
SKIP_PATH=false
FROM_SOURCE=false

while [ $# -gt 0 ]; do
  case "$1" in
    --no-path) SKIP_PATH=true; shift ;;
    --from-source) FROM_SOURCE=true; shift ;;
    --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
    --prefix)
      [ $# -ge 2 ] || { echo "error: --prefix requires a value" >&2; exit 1; }
      PREFIX="$2"; shift 2
      ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

# --- detect platform -------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) echo "error: unsupported OS: $OS" >&2; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# --- install directory -----------------------------------------------------
if [ -z "$PREFIX" ]; then
  if [ "$(id -u)" = "0" ]; then
    PREFIX="/usr/local/bin"
  else
    PREFIX="${XDG_BIN_HOME:-$HOME/.local/bin}"
  fi
fi
mkdir -p "$PREFIX"

# --- helpers ---------------------------------------------------------------
say() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[!]\033[0m %s\n' "$*" >&2; }

build_from_source() {
  say "building $BIN from source..."
  command -v go >/dev/null 2>&1 || { err "go is required to build from source"; exit 1; }
  if [ "$OS" = "linux" ] && [ -z "${CGO_CFLAGS:-}" ] && [ -z "${CGO_LDFLAGS:-}" ]; then
    if ! { command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcap 2>/dev/null; } \
       && [ ! -f /usr/include/pcap/pcap.h ]; then
      err "libpcap development headers are missing (on Debian/Ubuntu: 'sudo apt install libpcap-dev', on Fedora: 'sudo dnf install libpcap-devel')"
      exit 1
    fi
  fi
  if [ ! -f "$PWD/go.mod" ] || ! grep -qs "^module $MODULE$" "$PWD/go.mod"; then
    command -v git >/dev/null 2>&1 || { err "git is required to fetch the source"; exit 1; }
    say "cloning $REPO..."
    TMP_SRC="$(mktemp -d)"
    trap 'rm -rf "${TMP:-}" "${TMP_SRC:-}"' EXIT
    git clone --depth 1 "https://github.com/$REPO" "$TMP_SRC/qyvora-toha3ee" >/dev/null 2>&1
    SRC="$TMP_SRC/qyvora-toha3ee"
  else
    SRC="$PWD"
  fi
  (cd "$SRC" && go build -trimpath -ldflags="-s -w" -o "$PREFIX/$BIN" ./cmd/toha3ee)
  chmod 0755 "$PREFIX/$BIN"
  say "built $BIN from source"
}

resolve_latest() {
  curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
    grep '"tag_name"' | head -n1 |
    sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

# --- desktop integration (Linux only) --------------------------------------
# Installs the hicolor app icon and a .desktop entry so toha3ee shows up with
# its logo in GNOME's search/app grid. Data goes next to the install prefix:
#   PREFIX=/usr/local/bin  -> /usr/local/share
#   PREFIX=~/.local/bin    -> ~/.local/share
install_desktop_integration() {
  [ "$OS" = "linux" ] || return 0
  case "$PREFIX" in
    */bin) DATAROOT="$(dirname "$PREFIX")/share" ;;
    *) DATAROOT="$PREFIX/share" ;;
  esac

  ICON_SRC=""
  if [ -f "$PWD/assets/toha3ee.png" ]; then
    ICON_SRC="$PWD/assets/toha3ee.png"
  elif [ -f "${SRC:-}/assets/toha3ee.png" ]; then
    ICON_SRC="$SRC/assets/toha3ee.png"
  elif [ -f "${TMP:-}/toha3ee.png" ]; then
    ICON_SRC="$TMP/toha3ee.png"
  fi
  [ -n "$ICON_SRC" ] || { say "no icon found; skipping desktop integration"; return 0; }

  ICON_DIR="$DATAROOT/icons/hicolor/256x256/apps"
  APPS_DIR="$DATAROOT/applications"
  mkdir -p "$ICON_DIR" "$APPS_DIR"
  install -m 0644 "$ICON_SRC" "$ICON_DIR/toha3ee.png"
  say "installed icon to $ICON_DIR/toha3ee.png"

  DESKTOP="$APPS_DIR/toha3ee.desktop"
  [ -f "$DESKTOP" ] || cat >"$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=toha3ee
GenericName=Network security console
Comment=network exploitation & MITM framework
Exec=$PREFIX/$BIN
Icon=$ICON_DIR/toha3ee.png
Terminal=true
Categories=Utility;Network;Security;
EOF
  chmod 0644 "$DESKTOP"
  say "installed .desktop entry to $DESKTOP"

  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache "$DATAROOT/icons/hicolor" >/dev/null 2>&1 || true
}

# --- man pages --------------------------------------------------------------
# Installs the bundled man pages (toha3ee(1), scripting(7), security(7)) into
# the share/man tree next to the install prefix, so `man toha3ee` works after
# a source install. Requires the checkout (man/ directory) to be present.
install_man_pages() {
  SRC_DIR=""
  [ -d "$PWD/man" ] && SRC_DIR="$PWD"
  [ -z "$SRC_DIR" ] && [ -d "${SRC:-}/man" ] && SRC_DIR="$SRC"
  [ -n "$SRC_DIR" ] || { say "no man/ directory found; skipping man pages"; return 0; }
  case "$PREFIX" in
    */bin) MANROOT="$(dirname "$PREFIX")/share/man" ;;
    *) MANROOT="$PREFIX/share/man" ;;
  esac
  [ -d "$MANROOT" ] || mkdir -p "$MANROOT"
  for page in "$SRC_DIR"/man/*.[17]; do
    [ -f "$page" ] || continue
    sect="$(basename "$page" | sed -E 's/.*\.([0-9])$/\1/')"
    install -d "$MANROOT/man$sect"
    install -m 0644 "$page" "$MANROOT/man$sect/"
    say "installed man page $(basename "$page")"
  done
  command -v mandb >/dev/null 2>&1 && mandb -q "$MANROOT" >/dev/null 2>&1 || true
}

# --- install ---------------------------------------------------------------
if [ "$FROM_SOURCE" = "true" ]; then
  build_from_source
else
  command -v curl >/dev/null 2>&1 || { err "curl is required"; exit 1; }
  if [ -z "$VERSION" ]; then
    VERSION="$(resolve_latest)"
    [ -n "$VERSION" ] || {
      err "no release found for $REPO (no tagged releases yet?)"
      err "install from source instead: sh scripts/install.sh --from-source"
      exit 1
    }
  fi
  URL="https://github.com/$REPO/releases/download/$VERSION/${BIN}_${OS}_${ARCH}.tar.gz"
  say "downloading $BIN $VERSION ($OS/$ARCH)..."
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP:-}" "${TMP_SRC:-}"' EXIT
  if curl -fsSL "$URL" -o "$TMP/$BIN.tar.gz"; then
    if curl -fsSL "$URL.sha256" -o "$TMP/$BIN.sha256" 2>/dev/null; then
      EXPECTED="$(awk '{print $1}' "$TMP/$BIN.sha256")"
      ACTUAL="$(sha256sum "$TMP/$BIN.tar.gz" | awk '{print $1}')"
      [ "$EXPECTED" = "$ACTUAL" ] || { err "checksum mismatch (got $ACTUAL, want $EXPECTED)"; exit 1; }
      say "checksum verified"
    else
      say "no checksum published for $VERSION; skipping verification"
    fi
    tar -xzf "$TMP/$BIN.tar.gz" -C "$TMP"
    install -m 0755 "$TMP/$BIN" "$PREFIX/$BIN"
    say "installed $PREFIX/$BIN ($VERSION)"
  else
    say "no prebuilt binary for $OS/$ARCH at $VERSION; building from source..."
    build_from_source
  fi
fi

# --- desktop integration ----------------------------------------------------
install_desktop_integration

# --- man pages --------------------------------------------------------------
install_man_pages

# --- PATH ------------------------------------------------------------------
if [ "$SKIP_PATH" = "false" ]; then
  case ":$PATH:" in
    *":$PREFIX:"*) : ;;
    *)
      if [ -n "${ZSH_VERSION:-}" ]; then RC="$HOME/.zshrc"
      elif [ -n "${BASH_VERSION:-}" ]; then RC="$HOME/.bashrc"
      elif [ -n "${FISH_VERSION:-}" ]; then RC="$HOME/.config/fish/config.fish"
      else RC="$HOME/.profile"; fi
      mkdir -p "$(dirname "$RC")"
      grep -qs "export PATH=.*$PREFIX" "$RC" 2>/dev/null || printf '\nexport PATH="%s:$PATH"\n' "$PREFIX" >>"$RC"
      say "added $PREFIX to PATH via $RC (open a new shell)"
      ;;
  esac
fi

say "done. run 'toha3ee' to start the console."
