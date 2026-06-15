#!/usr/bin/env bash
# NmapReconFlow installer
# Installs nmapReconFlow to a system directory and optionally installs dependencies.
#
# Usage:
#   sudo ./install.sh [--with-deps] [--prefix /path/to/install]
#
# Examples:
#   sudo ./install.sh
#   sudo ./install.sh --with-deps
#   sudo ./install.sh --prefix /opt/nmapReconFlow --with-deps

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_INSTALL_DIR="/usr/local/share/nmapReconFlow"
SYMLINK_PATH="/usr/local/bin/nmapReconFlow"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colors ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf "${GREEN}[+]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
error() { printf "${RED}[-]${NC} %s\n" "$1" >&2; }
die()   { error "$1"; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --prefix <DIR>    Install directory (default: /usr/local/share/nmapReconFlow)
  --with-deps       Install system dependencies (nmap, curl, etc.)
  -h, --help        Show this help message

Examples:
  sudo ./install.sh
  sudo ./install.sh --with-deps
  sudo ./install.sh --prefix /opt/nmapReconFlow
EOF
}

# ── Platform detection ───────────────────────────────────────────────────────

detect_platform() {
    local uname_s
    uname_s="$(uname -s)"

    PLATFORM=""
    DISTRO=""
    DISTRO_FAMILY=""

    case "${uname_s}" in
        Darwin)
            PLATFORM="macos"
            DISTRO="macOS"
            DISTRO_FAMILY="macos"
            ;;
        Linux)
            PLATFORM="linux"
            if [ -f /etc/os-release ]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                DISTRO="${ID:-unknown}"
                case "${ID:-}" in
                    debian|ubuntu|kali|linuxmint|pop)
                        DISTRO_FAMILY="debian"
                        ;;
                    fedora|rhel|centos|rocky|alma)
                        DISTRO_FAMILY="rhel"
                        ;;
                    arch|manjaro)
                        DISTRO_FAMILY="arch"
                        ;;
                    *)
                        DISTRO_FAMILY="unknown"
                        ;;
                esac
            else
                DISTRO="unknown"
                DISTRO_FAMILY="unknown"
            fi
            ;;
        *)
            die "Unsupported platform: ${uname_s}"
            ;;
    esac

    info "Detected platform: ${PLATFORM} (${DISTRO})"
}

# ── Bash version check ──────────────────────────────────────────────────────

check_bash_version() {
    if [ -z "${BASH_VERSINFO[0]:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] || \
       { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
        error "NmapReconFlow requires bash 4.3+. Current: ${BASH_VERSION:-unknown}"
        if [ "${PLATFORM}" = "macos" ]; then
            warn "macOS ships with bash 3.x. Install newer bash with: brew install bash"
        fi
        exit 1
    fi
    info "Bash version ${BASH_VERSION} meets requirement (4.3+)"
}

# ── Root/sudo check ─────────────────────────────────────────────────────────

check_privileges() {
    local installDir="$1"

    # Check if install path is under a system directory that typically needs root
    case "${installDir}" in
        /usr/*|/opt/*|/etc/*)
            if [ "$(id -u)" -ne 0 ]; then
                warn "Installing to ${installDir} typically requires root/sudo privileges"
                warn "Re-run with: sudo $0 $*"
                die "Insufficient privileges for install directory: ${installDir}"
            fi
            ;;
    esac

    # Also check the symlink location
    local symlinkDir
    symlinkDir="$(dirname "${SYMLINK_PATH}")"
    if [ ! -w "${symlinkDir}" ] && [ "$(id -u)" -ne 0 ]; then
        warn "Cannot write to ${symlinkDir} for symlink creation"
        warn "Re-run with sudo or choose a different --prefix"
    fi
}

# ── Install dependencies ────────────────────────────────────────────────────

install_deps() {
    info "Installing dependencies for ${DISTRO} (${DISTRO_FAMILY})..."

    case "${DISTRO_FAMILY}" in
        debian)
            apt-get update -qq
            apt-get install -y nmap curl dnsutils
            ;;
        macos)
            if ! command -v brew >/dev/null 2>&1; then
                die "Homebrew is required to install dependencies on macOS. Visit https://brew.sh"
            fi
            brew install nmap bash
            ;;
        rhel)
            dnf install -y nmap curl bind-utils
            ;;
        arch)
            pacman -Sy --noconfirm nmap curl bind-tools
            ;;
        *)
            warn "Unknown distro family '${DISTRO_FAMILY}' — cannot auto-install dependencies"
            warn "Please manually install: nmap, curl, and DNS utilities"
            return 1
            ;;
    esac

    info "Dependencies installed successfully"
}

# ── Install project files ───────────────────────────────────────────────────

install_files() {
    local installDir="$1"

    # Verify source files exist
    if [ ! -f "${SCRIPT_DIR}/nmapReconFlow.sh" ]; then
        die "Cannot find nmapReconFlow.sh in ${SCRIPT_DIR}. Run install.sh from the project root."
    fi
    if [ ! -d "${SCRIPT_DIR}/lib" ]; then
        die "Cannot find lib/ directory in ${SCRIPT_DIR}. Run install.sh from the project root."
    fi

    # Create install directory (idempotent)
    info "Installing to ${installDir}"
    mkdir -p "${installDir}"

    # Copy main script
    cp -f "${SCRIPT_DIR}/nmapReconFlow.sh" "${installDir}/nmapReconFlow.sh"
    chmod +x "${installDir}/nmapReconFlow.sh"

    # Copy lib directory
    mkdir -p "${installDir}/lib"
    cp -f "${SCRIPT_DIR}"/lib/*.sh "${installDir}/lib/"

    # Copy example config if it exists
    if [ -f "${SCRIPT_DIR}/nmapReconFlow.conf.example" ]; then
        cp -f "${SCRIPT_DIR}/nmapReconFlow.conf.example" "${installDir}/nmapReconFlow.conf.example"
    fi

    info "Project files copied to ${installDir}"

    # Create symlink (idempotent — remove old one if it exists)
    local symlinkDir
    symlinkDir="$(dirname "${SYMLINK_PATH}")"
    if [ -d "${symlinkDir}" ] && [ -w "${symlinkDir}" -o "$(id -u)" -eq 0 ]; then
        if [ -L "${SYMLINK_PATH}" ] || [ -e "${SYMLINK_PATH}" ]; then
            rm -f "${SYMLINK_PATH}"
        fi
        ln -s "${installDir}/nmapReconFlow.sh" "${SYMLINK_PATH}"
        info "Symlink created: ${SYMLINK_PATH} -> ${installDir}/nmapReconFlow.sh"
    else
        warn "Could not create symlink at ${SYMLINK_PATH} (no write access)"
        warn "You can manually add ${installDir} to your PATH"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    local installDir="${DEFAULT_INSTALL_DIR}"
    local withDeps=false

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --prefix)
                if [ -z "${2:-}" ]; then
                    die "--prefix requires a directory argument"
                fi
                installDir="$2"
                shift 2
                ;;
            --with-deps)
                withDeps=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown argument: $1 (see --help)"
                ;;
        esac
    done

    printf "${BOLD}${GREEN}NmapReconFlow Installer${NC}\n"
    echo "────────────────────────────────────"

    detect_platform
    check_bash_version
    check_privileges "${installDir}"

    if [ "${withDeps}" = true ]; then
        install_deps
    fi

    install_files "${installDir}"

    echo ""
    printf "${BOLD}${GREEN}Installation complete!${NC}\n"
    echo "────────────────────────────────────"
    echo ""
    info "Usage:  nmapReconFlow -H <target> -t <scan-type>"
    info "Help:   nmapReconFlow --help"
    echo ""
    if [ "${withDeps}" = false ]; then
        warn "Dependencies were not installed. Run with --with-deps to install them,"
        warn "or ensure nmap and other recon tools are available in your PATH."
    fi
}

main "$@"
