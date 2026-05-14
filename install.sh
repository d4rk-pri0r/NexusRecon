#!/usr/bin/env bash
# ============================================================
# NexusRecon — Dependency Installer
# Supports: Kali Linux, Debian/Ubuntu, macOS (Homebrew)
# Usage:  chmod +x install.sh && ./install.sh [--skip-system] [--skip-python] [--yes]
#         PYTHON=python3.13 ./install.sh   # override interpreter
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }
info() { echo -e "${BLUE}[*]${NC} $*"; }

PYTHON=${PYTHON:-python3}
PIP=${PIP:-pip3}
OS=$(uname -s)

echo ""
echo "  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗"
echo "  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝"
echo "  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗"
echo "  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║"
echo "  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║"
echo "  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
echo "                                    RECON v0.5.0"
echo ""
echo "  Agentic OSINT Orchestration Framework"
echo "  Authorized use only. See DISCLAIMER.md"
echo ""

# ── Python version check (Fix 3) ────────────────────────────
info "Checking Python version..."
PYTHON_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

# Lower bound: 3.11
if [[ $PY_MAJOR -lt 3 ]] || { [[ $PY_MAJOR -eq 3 ]] && [[ $PY_MINOR -lt 11 ]]; }; then
    err "Python 3.11+ required. Found: $PYTHON_VERSION"
    err "Install Python 3.13 (recommended) and re-run with PYTHON=python3.13 ./install.sh"
    exit 1
fi

# Upper bound: <3.14 (tracks crewai's requires-python constraint)
if [[ $PY_MAJOR -gt 3 ]] || { [[ $PY_MAJOR -eq 3 ]] && [[ $PY_MINOR -ge 14 ]]; }; then
    err "Python $PYTHON_VERSION is too new — crewai requires <3.14"
    err ""
    err "Detected Python is: $("$PYTHON" -c 'import sys; print(sys.executable)')"
    err ""
    err "To fix: install Python 3.13 and re-run with:"
    err "    PYTHON=python3.13 ./install.sh"
    err ""
    err "On macOS:    brew install python@3.13"
    err "On Debian:   apt-get install python3.13 python3.13-venv"
    exit 1
fi

log "Python $PYTHON_VERSION OK"

# ── System package installation ──────────────────────────────
install_system_packages() {
    if [[ "$OS" == "Darwin" ]]; then
        install_macos
    elif [[ -f /etc/debian_version ]]; then
        install_debian
    else
        warn "Unsupported OS: $OS — install binary tools manually"
    fi
}

install_macos() {
    info "macOS detected — using Homebrew"
    if ! command -v brew &>/dev/null; then
        err "Homebrew not found. Install from https://brew.sh"
        exit 1
    fi
    brew update -q

    # Fix 4: only real Homebrew formulae — waybackurls/gau/dnstwist are not brew formulae
    # B5: cairo + pkg-config required to build pycairo (pulled in by maigret/pipx)
    # B3/B4: pipx for isolated maigret install
    BREW_PKGS=(
        go
        subfinder
        amass
        httpx
        dnsx
        git
        jq
        cairo
        pkg-config
        pipx
    )

    for pkg in "${BREW_PKGS[@]}"; do
        if brew list "$pkg" &>/dev/null 2>&1; then
            log "$pkg already installed"
        else
            info "Installing $pkg..."
            brew install "$pkg" 2>/dev/null && log "$pkg installed" || warn "Failed to install $pkg (optional)"
        fi
    done

    # Fix 4: Go tools not in Homebrew (waybackurls, gau, gowitness, nuclei, katana)
    if command -v go &>/dev/null; then
        install_go_tools
    fi
}

install_debian() {
    info "Debian/Ubuntu/Kali detected"
    sudo apt-get update -qq

    # B5: libcairo2-dev + pkg-config for pycairo source build (needed by maigret)
    # B3/B4: python3-pipx for isolated maigret install
    APT_PKGS=(
        git
        curl
        wget
        jq
        dnsutils
        whois
        libmagic1
        libcairo2
        libcairo2-dev
        pkg-config
        libpango-1.0-0
        libpangocairo-1.0-0
        libgdk-pixbuf2.0-0
        libffi-dev
        libssl-dev
        python3-dev
        build-essential
        python3-pipx
    )

    for pkg in "${APT_PKGS[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            log "$pkg already installed"
        else
            sudo apt-get install -y -qq "$pkg" && log "$pkg installed" || warn "Failed: $pkg"
        fi
    done

    # Go-based tools via apt or direct download
    if command -v go &>/dev/null; then
        log "Go already installed"
    else
        info "Installing Go..."
        sudo apt-get install -y -qq golang-go || warn "Go install failed — install manually from go.dev"
    fi

    # Install Go tools if go is available
    if command -v go &>/dev/null; then
        install_go_tools
    fi
    # Note: dnstwist is PyPI-only — installed in install_python_packages()
}

# Fix 4: expanded list; called on both macOS and Debian
install_go_tools() {
    info "Installing Go-based OSINT tools..."
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/sensepost/gowitness@latest"
    )
    for tool in "${GO_TOOLS[@]}"; do
        bin=$(basename "${tool%@*}")
        if command -v "$bin" &>/dev/null; then
            log "$bin already installed"
        else
            info "Installing $bin..."
            # B1: no 2>/dev/null — let stderr through so users see the real error
            go install "$tool" && log "$bin installed" || warn "$bin install failed (optional — see error above)"
        fi
    done

    # B2: Go tools land in $HOME/go/bin which may not be on PATH yet
    if [[ -d "$HOME/go/bin" ]] && [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        if [[ "${ASSUME_YES:-0}" -eq 1 ]]; then
            SHELL_RC="$HOME/.zshrc"
            [[ "$SHELL" == */bash ]] && SHELL_RC="$HOME/.bashrc"
            echo 'export PATH="$HOME/go/bin:$PATH"' >> "$SHELL_RC"
            log "Added \$HOME/go/bin to PATH in $SHELL_RC"
            warn "Restart your shell or run: source $SHELL_RC"
        else
            warn "\$HOME/go/bin is not on your PATH."
            warn "Add this line to your shell rc file (~/.zshrc or ~/.bashrc):"
            warn '    export PATH="$HOME/go/bin:$PATH"'
            warn "Then restart your shell or run: source ~/.zshrc"
        fi
    fi
}

# ── gitleaks ─────────────────────────────────────────────────
install_gitleaks() {
    if command -v gitleaks &>/dev/null; then
        log "gitleaks already installed"
        return
    fi
    info "Installing gitleaks..."
    GITLEAKS_VERSION="8.18.4"
    if [[ "$OS" == "Darwin" ]]; then
        brew install gitleaks 2>/dev/null && return
    fi
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="x64" || ARCH="arm64"
    URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz"
    curl -sL "$URL" | sudo tar xz -C /usr/local/bin gitleaks && log "gitleaks installed" || warn "gitleaks install failed"
}

# ── trufflehog ───────────────────────────────────────────────
install_trufflehog() {
    if command -v trufflehog &>/dev/null; then
        log "trufflehog already installed"
        return
    fi
    info "Installing trufflehog..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install trufflesecurity/trufflehog/trufflehog 2>/dev/null && return
    fi
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin 2>/dev/null && log "trufflehog installed" || warn "trufflehog install failed"
}

# ── amass ────────────────────────────────────────────────────
install_amass() {
    if command -v amass &>/dev/null; then
        log "amass already installed"
        return
    fi
    info "Installing amass..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install amass 2>/dev/null && return
    fi
    AMASS_VERSION="4.2.0"
    ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    URL="https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_${ARCH}.zip"
    curl -sL "$URL" -o /tmp/amass.zip && sudo unzip -jo /tmp/amass.zip "*/amass" -d /usr/local/bin/ \
        && log "amass installed" || warn "amass install failed"
    rm -f /tmp/amass.zip
}

# ── Venv management (Fix 2) ──────────────────────────────────
ensure_venv() {
    # If user already activated a venv, respect it
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        info "Using active venv: $VIRTUAL_ENV"
        return 0
    fi

    # Existing project venv?
    if [[ -d "./venv" && -f "./venv/bin/activate" ]]; then
        info "Activating existing ./venv"
        # shellcheck disable=SC1091
        source ./venv/bin/activate || { err "venv activation failed — delete ./venv and retry"; exit 1; }
        return 0
    fi

    # Create one with the validated Python
    info "Creating ./venv with $PYTHON"
    "$PYTHON" -m venv ./venv
    # shellcheck disable=SC1091
    source ./venv/bin/activate || { err "venv activation failed — delete ./venv and retry"; exit 1; }
    log "venv created. After install, run: source venv/bin/activate"
}

# ── pipx-isolated CLI tools (B3/B4) ─────────────────────────
# maigret has fragile transitive deps (pycairo, old aiohttp) that can conflict
# with the project venv.  nexusrecon only shells out to the `maigret` binary,
# so there's no reason for maigret's deps to share the project venv.
install_pipx_tools() {
    info "Installing pipx-isolated CLI tools..."
    if ! command -v pipx &>/dev/null; then
        warn "pipx not found — skipping pipx tools (maigret will be unavailable)"
        return
    fi
    # Ensure ~/.local/bin is on PATH for future shells
    pipx ensurepath --quiet 2>/dev/null || true

    if command -v maigret &>/dev/null; then
        log "maigret already installed"
    else
        pipx install maigret 2>&1 && log "maigret installed" || warn "maigret pipx install failed (optional)"
    fi

    info "pipx tools land in ~/.local/bin — new shells need 'source ~/.zshrc' for that to take effect."
}

# ── Python package installation ──────────────────────────────
install_python_packages() {
    info "Installing Python dependencies..."
    if [[ -f pyproject.toml ]]; then
        python -m pip install -e ".[dev]" && log "Python packages installed" || {
            err "pip install failed"
            exit 1
        }
    else
        python -m pip install -r requirements.txt && log "Python packages installed" || {
            err "pip install from requirements.txt failed"
            exit 1
        }
    fi

    # Fix 4: PyPI-only tools (not available as brew formulae)
    python -m pip install dnstwist --quiet && log "dnstwist installed" || warn "dnstwist install failed (optional)"
    python -m pip install arjun --quiet && log "arjun installed" || warn "arjun install failed (optional)"

    # B3/B4: install maigret in an isolated pipx env to avoid dep conflicts
    install_pipx_tools
}

# ── .env setup ───────────────────────────────────────────────
setup_env() {
    if [[ ! -f .env ]]; then
        cp .env.example .env
        log ".env created from .env.example — populate with your API keys"
    else
        log ".env already exists"
    fi
}

# ── Post-install verification (Fix 6) ───────────────────────
verify_install() {
    info "Verifying install..."
    local failed=0

    if [[ "${SKIP_PYTHON:-0}" -eq 0 ]]; then
        # Python deps importable?
        if ! python -c "import nexusrecon; from nexusrecon.tools.registry import get_registry" 2>/dev/null; then
            err "nexusrecon package not importable inside venv"
            failed=1
        else
            log "nexusrecon package imports OK"
        fi

        # CLI entry point present?
        if ! command -v nexusrecon >/dev/null 2>&1; then
            err "nexusrecon CLI not on PATH (venv may not be activated)"
            failed=1
        else
            log "nexusrecon CLI on PATH: $(command -v nexusrecon)"
        fi

        # Tool registry populates?
        tool_count=$(python -c "
import nexusrecon.tools.domain, nexusrecon.tools.pretext, nexusrecon.tools.cloud
import nexusrecon.tools.intel, nexusrecon.tools.web, nexusrecon.tools.vuln
import nexusrecon.tools.identity, nexusrecon.tools.mobile
from nexusrecon.tools.registry import get_registry
print(len(list(get_registry()._tools.values())))
" 2>/dev/null) || tool_count=0

        if [[ "${tool_count:-0}" -lt 80 ]]; then
            warn "Tool registry returned only ${tool_count:-0} tools (expected ~89)"
        else
            log "Tool registry OK: ${tool_count} tools registered"
        fi
    fi

    # Binaries present (informational; missing is OK for optional tools)
    info "External binary presence check:"
    for b in subfinder amass httpx dnsx nuclei katana gowitness gau waybackurls gitleaks trufflehog maigret arjun; do
        if command -v "$b" >/dev/null 2>&1; then
            echo "  [+] $b"
        else
            echo "  [ ] $b — gated tool will be unavailable"
        fi
    done

    return $failed
}

# ── Main (Fix 5 + wiring) ────────────────────────────────────
main() {
    # Fix 5: phased operation flags
    SKIP_SYSTEM=0
    SKIP_PYTHON=0
    ASSUME_YES=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-system) SKIP_SYSTEM=1; shift ;;
            --skip-python) SKIP_PYTHON=1; shift ;;
            --yes|-y)      ASSUME_YES=1; shift ;;
            --help|-h)
                echo "Usage: ./install.sh [--skip-system] [--skip-python] [--yes]"
                echo ""
                echo "  --skip-system   Skip Homebrew/apt + binary tool install"
                echo "  --skip-python   Skip Python venv + pip install"
                echo "  --yes, -y       Non-interactive; assume defaults"
                echo ""
                echo "Override Python interpreter:"
                echo "  PYTHON=python3.13 ./install.sh"
                exit 0 ;;
            *)
                err "Unknown flag: $1"; exit 1 ;;
        esac
    done

    log "Starting NexusRecon installation..."

    if [[ $SKIP_SYSTEM -eq 0 ]]; then
        install_system_packages
        install_gitleaks
        install_trufflehog
        install_amass
    else
        info "Skipping system package installation (--skip-system)"
    fi

    if [[ $SKIP_PYTHON -eq 0 ]]; then
        # Fix 2: create/activate venv before any pip call
        ensure_venv
        # After venv activation, point all pip/python calls at the venv interpreter
        PIP="python -m pip"
        PYTHON="python"
        install_python_packages
    else
        info "Skipping Python venv + pip install (--skip-python)"
    fi

    setup_env

    # Fix 6: end-of-install verification
    verify_install || {
        err "Install verification failed — see errors above"
        exit 1
    }

    echo ""
    log "Installation complete!"
    echo ""
    info "Next steps:"
    echo "  1. Activate the venv (if not already active):  source venv/bin/activate"
    echo "  2. Edit .env with your API keys"
    echo "  3. Create a scope file:  cp examples/scopes/m365_enterprise.yaml my-scope.yaml"
    echo "  4. Run:  nexusrecon validate my-scope.yaml"
    echo "  5. Run:  nexusrecon run --scope my-scope.yaml"
    echo ""
    warn "Authorized use only. Ensure you have written permission before running against any target."
    echo ""
}

main "$@"
