#!/usr/bin/env bash
#
# Build and install TeaGarden from this source tree.
#
#   scripts/install.sh                 # build and install into ~/.local/bin
#   scripts/install.sh --deps          # also install the system packages it needs (uses sudo)
#   scripts/install.sh --prefix /usr/local
#   scripts/install.sh --no-dev        # leave out the TeaGarden block device
#
# It never downloads a prebuilt binary. It runs `cargo install --locked` on the
# checked-out source, so what you install is exactly what you can read here.
# Remove it again with scripts/uninstall.sh.

set -euo pipefail

PREFIX="${HOME}/.local"
INSTALL_DEPS=0
FEATURES_ARGS=()
ASSUME_YES=0

usage() {
    sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --deps) INSTALL_DEPS=1; shift ;;
        --no-dev) FEATURES_ARGS=(--no-default-features); shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -n "$PREFIX" ] || die "--prefix needs a directory"

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ -t 0 ] || die "$1 needs confirmation; rerun with --yes to proceed without a terminal"
    printf '%s [y/N] ' "$1"
    read -r answer
    case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

SRC="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$SRC/Cargo.toml" ] && [ -d "$SRC/crates/teagarden-cli" ] \
    || die "run this script from a teagarden source tree (scripts/install.sh)"

OS="$(uname -s)"
case "$OS" in
    Linux|Darwin) ;;
    *) die "unsupported system: $OS (teagarden supports Linux and macOS)" ;;
esac

# --- System packages ---------------------------------------------------------

linux_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt-get install -y build-essential libclang-dev fuse3 curl"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf install -y gcc gcc-c++ make clang-devel fuse3 curl"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman -S --needed --noconfirm base-devel clang fuse3 curl"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper install -y gcc gcc-c++ make clang-devel fuse3 curl"
    else
        echo ""
    fi
}

if [ "$INSTALL_DEPS" = 1 ]; then
    if [ "$OS" = Linux ]; then
        cmd="$(linux_packages)"
        [ -n "$cmd" ] || die "no supported package manager found; install a C compiler, libclang (clang development files) and fuse3 yourself"
        SUDO=""
        [ "$(id -u)" = 0 ] || SUDO="sudo"
        say "system packages: $SUDO $cmd"
        if confirm "Install these packages now?"; then
            case "$cmd" in apt-get*) $SUDO apt-get update -qq ;; esac
            # shellcheck disable=SC2086
            $SUDO $cmd
        else
            die "packages not installed"
        fi
    else
        xcode-select -p >/dev/null 2>&1 || die "install the Xcode command line tools first: xcode-select --install"
        command -v brew >/dev/null 2>&1 || die "Homebrew is needed to install pkg-config and macFUSE (https://brew.sh)"
        say "system packages: brew install pkg-config; brew install --cask macfuse"
        if confirm "Install these packages now?"; then
            brew install pkg-config
            brew install --cask macfuse
            warn "approve the macFUSE system extension in System Settings > Privacy & Security, then reboot before mounting"
        else
            die "packages not installed"
        fi
    fi
fi

# --- Rust toolchain ----------------------------------------------------------

if [ -x "$HOME/.cargo/bin/cargo" ] && ! command -v cargo >/dev/null 2>&1; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
if ! command -v cargo >/dev/null 2>&1; then
    if [ "$INSTALL_DEPS" = 1 ] && confirm "Rust is not installed. Install it with rustup (https://rustup.rs) for this user?"; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        die "Rust is not installed; install it from https://rustup.rs (or rerun with --deps)"
    fi
fi

need="$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' "$SRC/Cargo.toml" | head -1)"
have="$(rustc --version | awk '{print $2}')"
if [ -n "$need" ] && [ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -1)" != "$need" ]; then
    die "Rust $have is older than the required $need; run: rustup update stable"
fi

# --- Prerequisite checks (report, do not guess) -------------------------------

missing=()
command -v cc >/dev/null 2>&1 || missing+=("a C compiler")
if [ "$OS" = Darwin ]; then
    command -v pkg-config >/dev/null 2>&1 || missing+=("pkg-config")
    pkg-config --exists fuse 2>/dev/null || missing+=("macFUSE (brew install --cask macfuse)")
fi
if [ ${#missing[@]} -gt 0 ]; then
    die "missing: ${missing[*]}. Rerun with --deps to install them, or see docs/GETTING_STARTED.md"
fi

# --- Build and install ---------------------------------------------------------

say "building teagarden (release) from $SRC; this takes a few minutes"
if ! cargo install --locked --path "$SRC/crates/teagarden-cli" --root "$PREFIX" ${FEATURES_ARGS[@]+"${FEATURES_ARGS[@]}"}; then
    if [ "$OS" = Linux ]; then
        die "the build failed. If the error mentions libclang, clang or stdarg.h, install the clang development files (Debian/Ubuntu: libclang-dev) or rerun with --deps"
    fi
    die "the build failed; see the error above and docs/GETTING_STARTED.md"
fi

BIN="$PREFIX/bin/teagarden"
[ -x "$BIN" ] || die "the build finished but $BIN is missing"
say "installed: $("$BIN" --version)"

if [ "$OS" = Linux ]; then
    if ! command -v fusermount3 >/dev/null 2>&1; then
        warn "fusermount3 was not found; mounting needs the fuse3 package"
    elif [ ! -e /dev/fuse ]; then
        warn "/dev/fuse does not exist; mounting needs the fuse kernel module (modprobe fuse)"
    fi
fi

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) warn "$PREFIX/bin is not on your PATH; add it, for example: export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac

cat <<EOF

Next steps:
  teagarden auth login                  # connect your Telegram account (asks for what it needs)
  teagarden volume create --name NAME   # create an encrypted volume
  teagarden volume mount NAME DIR       # mount it

See docs/GETTING_STARTED.md for the full walkthrough.
EOF
