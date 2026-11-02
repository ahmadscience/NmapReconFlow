#!/usr/bin/env bash
# NmapReconFlow - Configuration, platform detection, and defaults
# Based on nmapAutomator by @21y4d

NMAPRF_VERSION="2.1.0"

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

    # Distro + package manager, used for install hints for missing tools.
    DISTRO_ID="unknown"
    PKG_MANAGER="unknown"
    if $IS_MACOS; then
        DISTRO_ID="macos"
        PKG_MANAGER="brew"
    elif [ -r /etc/os-release ]; then
        local _id _like
        _id="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-unknown}")"
        _like="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID_LIKE:-}")"
        DISTRO_ID="${_id}"
        case " ${_id} ${_like} " in
            *" debian "*|*" ubuntu "*|*" kali "*|*" parrot "*|*" linuxmint "*|*" pop "*) PKG_MANAGER="apt" ;;
            *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) PKG_MANAGER="dnf" ;;
            *" arch "*|*" manjaro "*) PKG_MANAGER="pacman" ;;
        esac
    fi
}

# Map a recon tool name to the package that provides it on this platform.
tool_package() {
    local tool="$1"
    case "${PKG_MANAGER:-unknown}:${tool}" in
        apt:ldapsearch)            echo "ldap-utils" ;;
        apt:snmpwalk)              echo "snmp" ;;
        apt:snmp-check)            echo "snmpcheck" ;;
        apt:dig|apt:host)          echo "dnsutils" ;;
        apt:searchsploit)          echo "exploitdb" ;;
        apt:showmount)             echo "nfs-common" ;;
        apt:nxc)                   echo "netexec" ;;
        apt:xsltproc)              echo "xsltproc" ;;
        brew:searchsploit)         echo "exploitdb" ;;
        brew:snmpwalk|brew:snmp-check) echo "net-snmp" ;;
        brew:xsltproc)             echo "libxslt" ;;
        brew:smbclient)            echo "samba" ;;
        dnf:dig|dnf:host)          echo "bind-utils" ;;
        dnf:ldapsearch)            echo "openldap-clients" ;;
        dnf:snmpwalk)              echo "net-snmp-utils" ;;
        dnf:showmount)             echo "nfs-utils" ;;
        pacman:dig|pacman:host)    echo "bind" ;;
        pacman:ldapsearch)         echo "openldap" ;;
        pacman:snmpwalk)           echo "net-snmp" ;;
        pacman:showmount)          echo "nfs-utils" ;;
        *)                         echo "${tool}" ;;
    esac
}

# Print the install command for a space-separated list of tools.
install_hint() {
    local pkgs="" t p
    for t in $1; do
        p="$(tool_package "${t}")"
        case " ${pkgs} " in *" ${p} "*) ;; *) pkgs="${pkgs:+${pkgs} }${p}" ;; esac
    done
    case "${PKG_MANAGER:-unknown}" in
        apt)    echo "sudo apt install -y ${pkgs}" ;;
        brew)   echo "brew install ${pkgs}" ;;
        dnf)    echo "sudo dnf install -y ${pkgs}" ;;
        pacman) echo "sudo pacman -S ${pkgs}" ;;
        *)      echo "install with your package manager: ${pkgs}" ;;
    esac
}

# Decide how to run privileged nmap scans (UDP). Sets SUDO_PREFIX to "" when
# already root, "sudo" when sudo is usable. Returns 1 when neither works
# (e.g. autopilot/no TTY and sudo would need a password) so the caller can
# skip instead of hanging on a password prompt.
resolve_privilege() {
    SUDO_PREFIX=""
    if [ "$(id -u 2>/dev/null)" = "0" ]; then
        return 0
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        return 1
    fi
    # "sudo -n": the scan itself runs in a background process group and must
    # never sit on a password prompt; the ticket is primed in the foreground.
    if sudo -n true 2>/dev/null; then
        SUDO_PREFIX="sudo -n"
        return 0
    fi
    if ${AUTOPILOT:-false} || [ ! -t 0 ]; then
        return 1
    fi
    echo "UDP needs root; asking for your sudo password..." >&2
    if sudo -v; then
        SUDO_PREFIX="sudo -n"
        return 0
    fi
    return 1
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

# Resolve symlinks without GNU readlink -f / realpath (absent on older macOS).
_resolve_path() {
    local p="$1" link i=0
    while [ -L "${p}" ] && [ $i -lt 20 ]; do
        link="$(readlink "${p}")"
        case "${link}" in
            /*) p="${link}" ;;
            *)  p="$(dirname "${p}")/${link}" ;;
        esac
        i=$((i + 1))
    done
    printf '%s/%s' "$(cd "$(dirname "${p}")" 2>/dev/null && pwd -P)" "$(basename "${p}")"
}

# Locate nmap's data directory (scripts/, nmap.xsl). Checks $NMAPDIR, the
# installed binary's ../share/nmap (Homebrew Intel/ARM, /usr, /usr/local,
# static builds), then well-known locations.
find_nmap_datadir() {
    local d bin
    local -a dirs=()
    [ -n "${NMAPDIR:-}" ] && dirs+=("${NMAPDIR}")
    bin="${NMAPPATH:-$(command -v nmap 2>/dev/null)}"
    bin="${bin%% *}"
    if [ -n "${bin}" ] && [ -e "${bin}" ]; then
        bin="$(_resolve_path "${bin}")"
        dirs+=("$(dirname "$(dirname "${bin}")")/share/nmap")
    fi
    dirs+=(/usr/share/nmap /usr/local/share/nmap /opt/homebrew/share/nmap /opt/local/share/nmap)
    for d in "${dirs[@]}"; do
        [ -d "${d}/scripts" ] && printf '%s' "${d}" && return 0
    done
    return 1
}

find_nmap_scripts_dir() {
    local datadir
    datadir="$(find_nmap_datadir)" || return 1
    printf '%s' "${datadir}/scripts"
}

# Path to nmap.xsl (for HTML reports), if nmap ships it here.
find_nmap_xsl() {
    local datadir
    datadir="$(find_nmap_datadir)" || return 1
    [ -f "${datadir}/nmap.xsl" ] || return 1
    printf '%s' "${datadir}/nmap.xsl"
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

    # Scan timing profile: stealth|normal|aggressive. Tunes the nmap knobs
    # below (timing, rate, retries, scan-delay). See apply_scan_profile().
    : "${SCAN_PROFILE:=normal}"

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

    # Nmap XML output alongside -oN (enables HTML report + searchsploit)
    : "${NMAP_XML:=true}"

    # Fast port discovery feeding nmap: none|rustscan|naabu|masscan
    : "${FAST_DISCOVERY:=none}"
    : "${FAST_DISCOVERY_RATE:=1000}"

    # Suggest searchsploit lookups on detected service versions
    : "${ENABLE_SEARCHSPLOIT:=true}"

    # Group per-port recon output under recon/<port>/ (AutoRecon-style) instead
    # of the flat recon/<tool>_<host>_<port>.txt layout. Off = backward compat.
    : "${RECON_PER_PORT_DIRS:=false}"

    # HTML report generated from the nmap XML (requires NMAP_XML + xsltproc)
    : "${REPORT_HTML:=false}"

    # Grepable nmap output (-oG .gnmap) alongside -oN/-oX, like nmap -oA.
    # Consumed by brutespray, nmap-parse-output, grep/awk one-liners.
    : "${NMAP_GNMAP:=true}"

    # Write exports/ (CSV, host:port, URLs, port lists, merged XML) after
    # each scan, for feeding other tools.
    : "${GENERATE_EXPORTS:=true}"

    # Scope exclusions: file of IPs/CIDRs/hostnames never to scan.
    : "${EXCLUDE_FILE:=}"

    # Web fingerprinting with whatweb (-a 1, one request per URL).
    : "${ENABLE_WHATWEB:=true}"
    # Targeted, non-intrusive NSE scripts per detected service (NFS, MySQL,
    # MSSQL, RDP, Redis, MongoDB, VNC, SMTP, IMAP/POP3, memcached...).
    : "${ENABLE_SERVICE_NSE:=true}"
    # ssh-audit against SSH services (only when installed).
    : "${ENABLE_SSH_AUDIT:=true}"

    # nuclei template scan against discovered web URLs (opt-in: active checks).
    : "${RUN_NUCLEI:=false}"
    : "${NUCLEI_SEVERITY:=low,medium,high,critical}"
    # Web screenshots with gowitness (opt-in).
    : "${RUN_SCREENSHOTS:=false}"

    # Completion notification webhook (Slack/Discord/generic). Empty = disabled.
    : "${NOTIFY_WEBHOOK:=}"
    # Webhook payload style: slack|discord|generic (JSON {"text": ...})
    : "${NOTIFY_STYLE:=slack}"

    # Actually run intrusive brute-force/spray commands instead of only
    # writing them to recon/_manual_commands.txt. Off by default (lockout risk).
    : "${RUN_BRUTE:=false}"
    # Wordlists used when RUN_BRUTE=true (resolved via find_wordlist).
    : "${BRUTE_USERLIST:=metasploit/unix_users.txt}"
    : "${BRUTE_PASSLIST:=rockyou.txt}"
}

# Build the nmap output flags for a given basename (without extension).
# Honors NMAP_XML. Echoes flags to be word-split into an nmap arg list.
nmap_output_flags() {
    local base="$1"
    printf -- '-oN %s.nmap' "${base}"
    [ "${NMAP_XML}" = "true" ] && printf -- ' -oX %s.xml' "${base}"
    [ "${NMAP_GNMAP:-true}" = "true" ] && printf -- ' -oG %s.gnmap' "${base}"
    return 0
}

# nmap reads a bare --max-scan-delay number as SECONDS (and refuses values
# >= ~100 as a likely mistake). Our knob is documented in milliseconds, so
# append "ms" to plain numbers; values with a unit (500ms, 1s) pass through.
nmap_delay_arg() {
    local v="${1:-${NMAP_MAX_SCAN_DELAY}}"
    if [[ "${v}" =~ ^[0-9]+$ ]]; then
        printf '%sms' "${v}"
    else
        printf '%s' "${v}"
    fi
}

# Apply the SCAN_PROFILE preset to the nmap tuning knobs. Uses := so an
# explicit config/CLI/env value always wins over the profile; the profile
# only fills knobs the user has not set. Unknown names fall back to normal.
# Called from load_config BEFORE set_defaults so profile values take effect
# before the built-in defaults would otherwise fill them.
apply_scan_profile() {
    local profile="${SCAN_PROFILE:-normal}"
    case "${profile}" in
        stealth|normal|aggressive) ;;
        *)
            printf "${YELLOW:-}Unknown scan profile '%s'; falling back to 'normal'.${NC:-}\n" "${profile}" >&2
            profile="normal"
            ;;
    esac
    SCAN_PROFILE="${profile}"

    case "${profile}" in
        stealth)
            # Slow and quiet: minimise footprint and lockout/IDS risk.
            : "${NMAP_TIMING:=2}"
            : "${NMAP_MAX_RATE:=100}"
            : "${NMAP_MAX_RETRIES:=2}"
            : "${NMAP_MAX_SCAN_DELAY:=200}"
            ;;
        aggressive)
            # Fast and loud: for labs/CTFs where speed beats stealth.
            : "${NMAP_TIMING:=5}"
            : "${NMAP_MAX_RATE:=5000}"
            : "${NMAP_MAX_RETRIES:=1}"
            : "${NMAP_MAX_SCAN_DELAY:=5}"
            ;;
        normal)
            # Balanced defaults (same as the built-in defaults).
            : "${NMAP_TIMING:=4}"
            : "${NMAP_MAX_RATE:=500}"
            : "${NMAP_MAX_RETRIES:=1}"
            : "${NMAP_MAX_SCAN_DELAY:=20}"
            ;;
    esac
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

    # Source the config file first (if any) so SCAN_PROFILE and any explicit
    # tuning overrides are known, then let the profile fill unset knobs, then
    # fill everything still unset with built-in defaults. An invalid config is
    # skipped but defaults are still applied.
    if [ -n "$config_file" ]; then
        if grep -qvE '^([[:space:]]*#|[[:space:]]*$|[A-Z_][A-Z_0-9]*=)' "$config_file" 2>/dev/null; then
            printf "${RED:-}Warning: Config file contains invalid lines. Skipping.${NC:-}\n" >&2
        elif grep -qE '\$\(|`' "$config_file" 2>/dev/null; then
            printf "${RED:-}Warning: Config file contains command substitutions. Skipping.${NC:-}\n" >&2
        else
            # shellcheck disable=SC1090
            source "$config_file"
            printf "${GREEN:-}Loaded config: ${config_file}${NC:-}\n"
        fi
    fi

    apply_scan_profile
    set_defaults
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
