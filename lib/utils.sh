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

# True if the argument is an IPv6 address (at least two colons).
is_ipv6() {
    [[ "$1" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]] && [[ "$1" == *:*:* ]]
}

# True if the argument is a CIDR range (IPv4 or IPv6).
is_cidr() {
    [[ "$1" == */* ]] && [[ "$1" =~ ^[0-9a-fA-F.:]+/[0-9]{1,3}$ ]]
}

# Expand a CIDR range into individual host IPs, one per line, via nmap -sL.
expand_cidr() {
    local spec="$1"
    ${NMAPPATH:-nmap} -n -sL "${spec}" 2>/dev/null \
        | awk '/Nmap scan report for/{print $NF}'
}

# Test whether the host is pingable, return $nmapType and $ttl
checkPing() {
    local host="$1"
    local pingTest
    pingTest="$(ping -c 1 -${PING_TIMEOUT_FLAG} 1 "$host" 2>/dev/null | grep -i ttl)"
    if [ -z "${pingTest}" ]; then
        echo "${NMAPPATH} -Pn"
    else
        echo "${NMAPPATH}"
        local ttl
        ttl="$(echo "${pingTest}" | grep -oE '[Tt][Tt][Ll]=[0-9]+' | head -1 | cut -d= -f2)"
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

# Keep found ports consistent across the script
assignPorts() {
    local host="$1"

    if [ -f "nmap/Port_${host}.nmap" ]; then
        commonPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_${host}.nmap" | sed 's/,$//')"
    fi

    if [ -f "nmap/Full_${host}.nmap" ]; then
        if [ -f "nmap/Port_${host}.nmap" ]; then
            allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_${host}.nmap" "nmap/Full_${host}.nmap" | sed 's/,$//')"
        else
            allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Full_${host}.nmap" | sed 's/,$//')"
        fi
    fi

    if [ -f "nmap/UDP_${host}.nmap" ]; then
        udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_${host}.nmap" | sed 's/,$//')"
        [ -z "${udpPorts}" ] && udpPorts=""
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

    if [[ "${HOST}" =~ ^(([[:alnum:]-]{1,63}\.)*[[:alpha:]]{2,6})$ ]]; then
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

    if [[ "${HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
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
    printf "${GREEN}---------------------Finished all scans------------------------\n"
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
