#!/usr/bin/env bash
# NmapReconFlow - Configuration, platform detection, and defaults
# Based on nmapAutomator by @21y4d

NMAPRF_VERSION="2.0.0"

detect_platform() {
    PLATFORM="$(uname -s)"
    case "$PLATFORM" in
        Linux)  IS_LINUX=true;  IS_MACOS=false ;;
        Darwin) IS_LINUX=false; IS_MACOS=true  ;;
        *)      IS_LINUX=true;  IS_MACOS=false ;;
    esac

    if $IS_LINUX; then
        PING_TIMEOUT_FLAG="W"
    else
        PING_TIMEOUT_FLAG="t"
    fi
}

sed_inplace() {
    if $IS_MACOS; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

detect_dns_server() {
    if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
    elif $IS_MACOS; then
        DNSSERVER="$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3; exit}')"
    else
        DNSSERVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
    fi
    if [ -n "${DNSSERVER}" ]; then
        DNSSTRING="--dns-server=${DNSSERVER}"
    else
        DNSSTRING="--system-dns"
    fi
}

find_wordlist() {
    local name="$1"
    local search_paths=(
        "${WORDLIST_BASE_DIR:-}"
        "/usr/share/wordlists"
        "/usr/share/seclists"
        "/usr/local/share/wordlists"
        "/opt/homebrew/share/wordlists"
        "${HOME}/.local/share/wordlists"
    )
    for base in "${search_paths[@]}"; do
        [ -z "$base" ] && continue
        [ -f "${base}/${name}" ] && printf '%s' "${base}/${name}" && return 0
    done
    return 1
}

find_nmap_scripts_dir() {
    local datadir
    datadir="$(${NMAPPATH:-nmap} --datadir 2>/dev/null | head -1)"
    if [ -n "$datadir" ] && [ -d "${datadir}/scripts" ]; then
        printf '%s' "${datadir}/scripts"
        return 0
    fi
    local dirs=(/usr/share/nmap/scripts /usr/local/share/nmap/scripts /opt/homebrew/share/nmap/scripts)
    for d in "${dirs[@]}"; do
        [ -d "$d" ] && printf '%s' "$d" && return 0
    done
    return 1
}

set_defaults() {
    : "${TIMEOUT_NMAP_PORT:=600}"
    : "${TIMEOUT_NMAP_FULL:=1800}"
    : "${TIMEOUT_NMAP_SCRIPT:=900}"
    : "${TIMEOUT_NMAP_UDP:=900}"
    : "${TIMEOUT_NMAP_VULNS:=1200}"
    : "${TIMEOUT_RECON_DEFAULT:=600}"
    : "${TIMEOUT_CAMPAIGN:=0}"

    : "${NMAP_MAX_RATE:=500}"
    : "${NMAP_TIMING:=4}"
    : "${NMAP_MAX_RETRIES:=1}"
    : "${NMAP_MAX_SCAN_DELAY:=20}"
    : "${NMAP_MIN_CVSS:=7.0}"

    : "${DEFAULT_SCAN_TYPE:=All}"
    : "${AUTOPILOT:=false}"
    : "${CAMPAIGN_PARALLEL:=1}"

    : "${WORDLIST_BASE_DIR:=}"
    : "${WORDLIST_DIRB:=dirb/common.txt}"
    : "${WORDLIST_USERS:=metasploit/unix_users.txt}"

    : "${PREFER_FFUF:=true}"
    : "${SKIP_RECON_TOOLS:=}"

    : "${EXTRA_WEB_PORTS:=8080,8443,3000,9090,8000,8888,4443,8008}"

    : "${GOBUSTER_THREADS:=30}"
    : "${FFUF_RATE:=0}"
    : "${WPSCAN_THROTTLE:=0}"

    : "${GENERATE_REPORT:=true}"
    : "${REPORT_MAX_TOOL_OUTPUT:=200}"
    : "${REPORT_FORMAT:=markdown}"
    : "${DRY_RUN:=false}"
}

load_config() {
    local config_file=""

    if [ -n "${CLI_CONFIG:-}" ] && [ -f "${CLI_CONFIG}" ]; then
        config_file="${CLI_CONFIG}"
    elif [ -f "./nmapReconFlow.conf" ]; then
        config_file="./nmapReconFlow.conf"
    elif [ -f "${HOME}/.config/nmapReconFlow/config" ]; then
        config_file="${HOME}/.config/nmapReconFlow/config"
    elif [ -f "${HOME}/.nmapReconFlow.conf" ]; then
        config_file="${HOME}/.nmapReconFlow.conf"
    fi

    set_defaults

    if [ -n "$config_file" ]; then
        if grep -qvE '^([[:space:]]*#|[[:space:]]*$|[A-Z_][A-Z_0-9]*=)' "$config_file" 2>/dev/null; then
            printf "${RED:-}Warning: Config file contains invalid lines. Skipping.${NC:-}\n" >&2
            return 1
        fi
        if grep -qE '\$\(|`' "$config_file" 2>/dev/null; then
            printf "${RED:-}Warning: Config file contains command substitutions. Skipping.${NC:-}\n" >&2
            return 1
        fi
        # shellcheck disable=SC1090
        source "$config_file"
        printf "${GREEN:-}Loaded config: ${config_file}${NC:-}\n"
    fi
}

resolve_hostname() {
    local hostname="$1"
    local dns_server="${2:-}"
    local result=""

    if command -v host >/dev/null 2>&1; then
        result="$(host -4 -W 1 "${hostname}" ${dns_server} 2>/dev/null | grep "${hostname}" | head -n 1 | awk '{print $NF}')"
    elif command -v dig >/dev/null 2>&1; then
        result="$(dig +short -4 "${hostname}" ${dns_server:+@${dns_server}} 2>/dev/null | head -n 1)"
    elif command -v getent >/dev/null 2>&1; then
        result="$(getent ahostsv4 "${hostname}" 2>/dev/null | head -n 1 | awk '{print $1}')"
    fi

    [ -n "${result}" ] && printf '%s' "${result}"
}

detect_nmap_binary() {
    if [ -z "${NMAPPATH:-}" ] && command -v nmap >/dev/null 2>&1; then
        NMAPPATH="$(command -v nmap)"
    elif [ -n "${NMAPPATH:-}" ]; then
        NMAPPATH="$(cd "$(dirname "${NMAPPATH}")" && pwd -P)/$(basename "${NMAPPATH}")"
        if [ ! -x "$NMAPPATH" ]; then
            printf "${RED}\nFile is not executable! Attempting chmod +x...${NC}\n"
            chmod +x "$NMAPPATH" 2>/dev/null || { printf "${RED}Could not chmod. Running in Remote mode...${NC}\n\n"; REMOTE=true; return; }
        fi
        if [[ "$($NMAPPATH -h 2>/dev/null | head -c4)" != "Nmap" ]]; then
            printf "${RED}\nStatic binary does not appear to be Nmap! Running in Remote mode...${NC}\n\n"
            REMOTE=true
            return
        fi
        printf "${GREEN}\nUsing static nmap binary at ${NMAPPATH}${NC}\n"
    else
        printf "${RED}\nNmap is not installed and -s is not used. Running in Remote mode...${NC}\n\n"
        REMOTE=true
    fi
}
