#!/usr/bin/env bash
# install.sh - Floodles installation script
# Debian/Ubuntu/Kali and Arch Linux

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# ---- Colors ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
info() { echo -e "[*] $*"; }

# ---- Detect distro ----
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    warn "Unknown package manager. Install gcc, python3, python3-venv manually."
    PKG_MGR=""
fi

echo ""
echo "  Floodles — Installation"
echo "  ========================"
echo ""

# ---- System packages ----
info "Installing system packages..."
if [ "$PKG_MGR" = "apt" ]; then
    sudo apt-get update -qq
    sudo apt-get install -y gcc build-essential python3 python3-venv git
elif [ "$PKG_MGR" = "pacman" ]; then
    sudo pacman -Sy --noconfirm gcc python git
fi
ok "System packages ready."

# ---- Detect pre-built binaries (release tarball) ----
PREBUILT_C="$SCRIPT_DIR/native/c/libsender.so"
PREBUILT_RS="$SCRIPT_DIR/native/rust/target/release/libfloodles_packets.so"
PREBUILT_GO="$SCRIPT_DIR/native/go/floodles-engine"

if [ -f "$PREBUILT_C" ] && [ -f "$PREBUILT_RS" ] && [ -f "$PREBUILT_GO" ]; then
    SKIP_BUILD=1
    ok "Pre-built native binaries detected — skipping compilation."
else
    SKIP_BUILD=0
fi

if [ "$SKIP_BUILD" = "0" ]; then
    # ---- Rust ----
    info "Checking Rust/cargo..."
    if ! command -v cargo &>/dev/null; then
        info "Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        source "$HOME/.cargo/env"
        ok "Rust installed."
    else
        ok "cargo found: $(cargo --version)"
    fi

    # Ensure a default toolchain is set (fresh rustup installs have none)
    if ! rustup default 2>/dev/null | grep -q "stable\|nightly\|beta"; then
        info "Setting rustup default toolchain to stable..."
        rustup default stable
    fi

    # ---- Go ----
    info "Checking Go..."
    if ! command -v go &>/dev/null; then
        if [ "$PKG_MGR" = "apt" ]; then
            sudo apt-get install -y golang-go
        elif [ "$PKG_MGR" = "pacman" ]; then
            sudo pacman -Sy --noconfirm go
        else
            warn "Go not found. Install from https://go.dev/dl/ then re-run this script."
        fi
    fi
    command -v go &>/dev/null && ok "go found: $(go version)" || warn "Go not available. Go engine will not be built."
fi

# ---- Clean stale system-level install ----
for STALE in "$HOME/.local/bin/floodles" "/usr/local/bin/floodles"; do
    if [ -f "$STALE" ]; then
        warn "Removing stale system install: $STALE"
        rm -f "$STALE"
    fi
done

# ---- Python venv ----
info "Creating virtual environment at $VENV_DIR..."
python3 -m venv "$VENV_DIR"
ok "venv created."

info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --quiet -e "$SCRIPT_DIR"
ok "Floodles installed in venv."

# ---- Build native backends ----
if [ "$SKIP_BUILD" = "0" ]; then
    info "Building native backends (C, Rust, Go)..."
    cd "$SCRIPT_DIR"
    make 2>&1 | grep -E "^\[|\berror\b" || true
    ok "Native build complete."
else
    info "Skipping native build (pre-built binaries already present)."
fi

# ---- Shell aliases ----
echo ""
info "Add these aliases to ~/.bashrc or ~/.zshrc:"
echo ""
echo "  alias floodles='$VENV_DIR/bin/floodles'"
echo "  alias sfloodles='sudo $VENV_DIR/bin/floodles'"
echo ""

# Auto-append to shell RC if confirmed
for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$RC" ] || continue
    if ! grep -q "alias floodles=" "$RC"; then
        printf "\n# Floodles\nalias floodles='%s/bin/floodles'\nalias sfloodles='sudo %s/bin/floodles'\n" \
            "$VENV_DIR" "$VENV_DIR" >> "$RC"
        ok "Aliases added to $RC"
    else
        warn "Aliases already present in $RC — skipping."
    fi
done

echo ""
info "Reload your shell: source ~/.bashrc  (or ~/.zshrc)"
echo ""

# ---- Validate ----
info "Running floodles detect..."
"$VENV_DIR/bin/floodles" detect

echo ""
ok "Installation complete."
