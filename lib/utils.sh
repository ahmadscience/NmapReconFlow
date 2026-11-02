#!/usr/bin/env bash
# NmapReconFlow - Utility functions

origIFS="${IFS}"

is_valid_scan_type() {
    case "$1" in
        [Nn]etwork|[Pp]ort|[Ss]cript|[Ff]ull|UDP|udp|[Vv]ulns|[Rr]econ|[Aa]ll) return 0 ;;
        *) return 1 ;;
    esac
}

validate_host_safe() {
    [[ "$1" =~ ^[a-zA-Z0-9._:/-]+$ ]]
}

# True for a dotted-quad IPv4 address with every octet in 0-255.
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[@]:1}"; do
        [ $((10#${o})) -le 255 ] || return 1
    done
    return 0
}

# True for a DNS hostname: dot-separated labels of letters/digits/hyphens,
# max 63 chars each, last label starting with a letter (so "10.0.0.999" is
# not a hostname). Single labels (localhost, dc01) and long TLDs (.internal,
# .localdomain) are accepted.
is_hostname() {
    [ "${#1}" -le 253 ] || return 1
    [[ "$1" =~ ^([[:alnum:]]([[:alnum:]-]{0,61}[[:alnum:]])?\.)*[[:alpha:]]([[:alnum:]-]{0,61}[[:alnum:]])?\.?$ ]]
}

# True if the argument is an IPv6 address (at least two colons).
is_ipv6() {
    [[ "$1" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]] && [[ "$1" == *:*:* ]]
}

# True if the argument is a CIDR range (IPv4 or IPv6).
is_cidr() {
    [[ "$1" == */* ]] && [[ "$1" =~ ^[0-9a-fA-F.:]+/[0-9]{1,3}$ ]]
}

# Expand a CIDR range into individual host IPs, one per line, via nmap -sL.
# Honors EXCLUDE_FILE (nmap --excludefile) when set.
expand_cidr() {
    local spec="$1"
    local -a excl=()
    if [ -n "${EXCLUDE_FILE:-}" ] && [ -f "${EXCLUDE_FILE}" ]; then
        excl=(--excludefile "${EXCLUDE_FILE}")
    fi
    ${NMAPPATH:-nmap} -n -sL "${excl[@]}" "${spec}" 2>/dev/null \
        | awk '/Nmap scan report for/{print $NF}'
}

# IPv4 dotted quad -> integer (caller validates with is_ipv4).
_ip2int() {
    local IFS=.
    local -a o
    read -r -a o <<< "$1"
    printf '%d' $(( (10#${o[0]} << 24) + (10#${o[1]} << 16) + (10#${o[2]} << 8) + 10#${o[3]} ))
}

# True if IPv4 address $1 is inside IPv4 CIDR $2 (e.g. 10.0.0.0/8).
ip_in_cidr() {
    local ip="$1" net="${2%/*}" bits="${2#*/}"
    is_ipv4 "${ip}" && is_ipv4 "${net}" || return 1
    [[ "${bits}" =~ ^[0-9]+$ ]] && [ "${bits}" -le 32 ] || return 1
    [ "${bits}" -eq 0 ] && return 0
    local mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    [ $(( $(_ip2int "${ip}") & mask )) -eq $(( $(_ip2int "${net}") & mask )) ]
}

# True if target $1 matches an entry in EXCLUDE_FILE (exact IP/hostname,
# case-insensitive, or an IPv4 CIDR containing it). '#' comments allowed.
is_excluded() {
    local target="$1" entry
    [ -n "${EXCLUDE_FILE:-}" ] && [ -f "${EXCLUDE_FILE}" ] || return 1
    while IFS= read -r entry || [ -n "${entry}" ]; do
        entry="${entry%%#*}"
        entry="$(printf '%s' "${entry}" | tr -d '[:space:]')"
        [ -z "${entry}" ] && continue
        if [ "$(printf '%s' "${entry}" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "${target}" | tr '[:upper:]' '[:lower:]')" ]; then
            return 0
        fi
        if [[ "${entry}" == */* ]] && ip_in_cidr "${target}" "${entry}"; then
            return 0
        fi
    done < "${EXCLUDE_FILE}"
    return 1
}

# Test whether the host is pingable, return $nmapType and $ttl
checkPing() {
    local host="$1"
    local pingTest
    local pingCmd="ping"
    # macOS ping is IPv4-only; IPv6 needs ping6 there.
    if is_ipv6 "${host}" && ${IS_MACOS:-false} && command -v ping6 >/dev/null 2>&1; then
        pingCmd="ping6"
    fi
    if [ "${pingCmd}" = "ping6" ]; then
        # BSD ping6 has no per-reply timeout flag; bound it externally.
        pingTest="$(run_with_timeout 3 ping6 ping6 -c 1 "$host" 2>/dev/null | grep -i -E 'ttl|hlim')"
    else
        pingTest="$(ping -c 1 -${PING_TIMEOUT_FLAG} 1 "$host" 2>/dev/null | grep -i ttl)"
    fi
    if [ -z "${pingTest}" ]; then
        echo "${NMAPPATH} -Pn"
    else
        echo "${NMAPPATH}"
        local ttl
        ttl="$(echo "${pingTest}" | grep -oE '([Tt][Tt][Ll]|hlim)=[0-9]+' | head -1 | cut -d= -f2)"
        echo "${ttl}"
    fi
}

checkOS() {
    case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78])  echo "Windows" ;;
        6[34])   echo "Linux" ;;
        *)       echo "Unknown OS!" ;;
    esac
}

# Print the sorted, de-duplicated, comma-joined open port numbers found in
# the given nmap -oN files (missing files are ignored).
_ports_from_files() {
    local -a files=()
    local f
    for f in "$@"; do
        [ -f "$f" ] && files+=("$f")
    done
    [ ${#files[@]} -eq 0 ] && return 0
    awk -F/ '/^[0-9]+\/(tcp|udp)/ && $0 ~ / open/{print $1}' "${files[@]}" \
        | sort -n -u | paste -sd, -
}

# Keep found ports consistent across the script. Lists are de-duplicated:
# nmap warns about (and some NSE scripts misbehave on) repeated ports.
assignPorts() {
    local host="$1"

    if [ -f "nmap/Port_${host}.nmap" ]; then
        commonPorts="$(_ports_from_files "nmap/Port_${host}.nmap")"
    fi

    if [ -f "nmap/Full_${host}.nmap" ]; then
        allPorts="$(_ports_from_files "nmap/Port_${host}.nmap" "nmap/Full_${host}.nmap")"
    fi

    if [ -f "nmap/UDP_${host}.nmap" ]; then
        udpPorts="$(_ports_from_files "nmap/UDP_${host}.nmap")"
    fi
}

cmpPorts() {
    local -A common_set=()
    local IFS=','
    local p
    for p in ${commonPorts}; do
        common_set["$p"]=1
    done
    local result=""
    for p in ${allPorts}; do
        if [ -z "${common_set[$p]:-}" ]; then
            [ -n "$result" ] && result+=","
            result+="$p"
        fi
    done
    extraPorts="$result"
}

header() {
    echo
    printf "${BOLD}${GREEN}"
    printf "  _   _                       ____                      _____ _\n"
    printf " | \\ | |_ __ ___   __ _ _ __ |  _ \\ ___  ___ ___  _ __|  ___| | _____      __\n"
    printf " |  \\| | '_ \` _ \\ / _\` | '_ \\| |_) / _ \\/ __/ _ \\| '_ \\ |_  | |/ _ \\ \\ /\\ / /\n"
    printf " | |\\  | | | | | | (_| | |_) |  _ <  __/ (_| (_) | | | |  _| | | (_) \\ V  V /\n"
    printf " |_| \\_|_| |_| |_|\\__,_| .__/|_| \\_\\___|\\___\\___/|_| |_|_|   |_|\\___/ \\_/\\_/\n"
    printf "                       |_|                                     v${NMAPRF_VERSION}\n"
    printf "${NC}\n"

    if [[ "${TYPE}" =~ ^[Aa]ll$ ]]; then
        printf "${YELLOW}Running all scans on ${NC}${HOST}"
    else
        printf "${YELLOW}Running a ${TYPE} scan on ${NC}${HOST}"
    fi

    if ! is_ipv4 "${HOST}" && ! is_ipv6 "${HOST}" && is_hostname "${HOST}"; then
        urlIP="$(resolve_hostname "${HOST}" "${DNSSERVER}")"
        if [ -n "${urlIP}" ]; then
            printf "${YELLOW} with IP ${NC}${urlIP}\n\n"
        else
            printf ".. ${RED}Could not resolve IP of ${NC}${HOST}\n\n"
        fi
    else
        printf "\n"
    fi

    if $REMOTE; then
        printf "${YELLOW}Running in Remote mode! Some scans will be limited.\n"
    fi

    if $AUTOPILOT; then
        printf "${GREEN}Autopilot mode enabled. All scans will run unattended.\n"
    fi

    # /24 used by the Network scan and dnsrecon; from the resolved IP when
    # the target is a hostname.
    if is_ipv4 "${urlIP:-$HOST}"; then
        subnet="$(echo "${urlIP:-$HOST}" | cut -d "." -f 1,2,3).0"
    fi

    kernel="$(uname -s)"
    checkPingResult="$(checkPing "${urlIP:-$HOST}")"
    nmapType="$(echo "${checkPingResult}" | head -n 1)"

    # IPv6 targets need nmap's -6 flag
    if is_ipv6 "${urlIP:-$HOST}"; then
        nmapType="${nmapType} -6"
        printf "${GREEN}IPv6 target detected; enabling nmap -6${NC}\n"
    fi

    if [[ "${nmapType}" == *"-Pn" ]]; then
        pingable=false
        printf "${NC}\n"
        printf "${YELLOW}No ping detected.. Will not use ping scans!\n"
        printf "${NC}\n"
    else
        pingable=true
    fi

    ttl="$(echo "${checkPingResult}" | tail -n 1)"
    if [ "${ttl}" != "nmap -Pn" ] && [ "${ttl}" != "${NMAPPATH} -Pn" ]; then
        osType="$(checkOS "${ttl}")"
        printf "${NC}\n"
        printf "${GREEN}Host is likely running ${osType}\n"
    fi

    echo
    echo
}

footer() {
    printf -- "${GREEN}---------------------Finished all scans------------------------\n"
    printf "${NC}\n\n"

    local elapsedEnd
    elapsedEnd="$(date +%s)"
    local elapsedSeconds=$((elapsedEnd - elapsedStart))

    if [ ${elapsedSeconds} -gt 3600 ]; then
        local hours=$((elapsedSeconds / 3600))
        local minutes=$(((elapsedSeconds % 3600) / 60))
        local seconds=$(((elapsedSeconds % 3600) % 60))
        printf "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
    elif [ ${elapsedSeconds} -gt 60 ]; then
        local minutes=$(((elapsedSeconds % 3600) / 60))
        local seconds=$(((elapsedSeconds % 3600) % 60))
        printf "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
    else
        printf "${YELLOW}Completed in ${elapsedSeconds} seconds\n"
    fi
    printf "${NC}\n"
}
