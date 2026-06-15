#!/usr/bin/env bash
# NmapReconFlow - Nmap scan functions

networkScan() {
    printf "${GREEN}---------------------Starting Network Scan---------------------\n"
    printf "${NC}\n"

    local origHOST="${HOST}"
    HOST="${urlIP:-$HOST}"

    if ! $REMOTE; then
        nmapProgressBar "nmap/Network_${HOST}.nmap" 1 "${TIMEOUT_NMAP_PORT}" \
            ${nmapType} -T"${NMAP_TIMING}" --max-retries "${NMAP_MAX_RETRIES}" \
            --max-scan-delay "${NMAP_MAX_SCAN_DELAY}" -n -sn \
            -oN "nmap/Network_${HOST}.nmap" "${subnet}/24"
        printf "${YELLOW}Found the following live hosts:${NC}\n\n"
        grep -v '#' "nmap/Network_${HOST}.nmap" | grep "$(echo "$subnet" | sed 's/..$//')" | awk '{print $5}'
    elif $pingable; then
        echo >"nmap/Network_${HOST}.nmap"
        local ip
        for ip in $(seq 0 254); do
            (ping -c 1 -${PING_TIMEOUT_FLAG} 1 "$(echo "$subnet" | sed 's/..$//').$ip" 2>/dev/null | grep 'stat' -A1 | xargs | grep -v ', 0.*received' | awk '{print $2}' >>"nmap/Network_${HOST}.nmap") &
        done
        wait
        sed_inplace '/^$/d' "nmap/Network_${HOST}.nmap"
        sort -t . -k 3,3n -k 4,4n -o "nmap/Network_${HOST}.nmap" "nmap/Network_${HOST}.nmap"
        cat "nmap/Network_${HOST}.nmap"
    else
        printf "${YELLOW}No ping detected.. TCP Network Scan is not implemented yet in Remote mode.\n${NC}"
    fi

    HOST="${origHOST}"

    echo
    echo
    echo
}

portScan() {
    printf "${GREEN}---------------------Starting Port Scan-----------------------\n"
    printf "${NC}\n"

    if ! $REMOTE; then
        nmapProgressBar "nmap/Port_${HOST}.nmap" 1 "${TIMEOUT_NMAP_PORT}" \
            ${nmapType} -T"${NMAP_TIMING}" --max-retries "${NMAP_MAX_RETRIES}" \
            --max-scan-delay "${NMAP_MAX_SCAN_DELAY}" --open \
            -oN "nmap/Port_${HOST}.nmap" "${HOST}" ${DNSSTRING}
        assignPorts "${HOST}"
    else
        printf "${YELLOW}Port Scan is not implemented yet in Remote mode.\n${NC}"
    fi

    echo
    echo
    echo
}

scriptScan() {
    printf "${GREEN}---------------------Starting Script Scan-----------------------\n"
    printf "${NC}\n"

    if ! $REMOTE; then
        if [ -z "${commonPorts}" ]; then
            printf "${YELLOW}No ports in port scan.. Skipping!\n"
        else
            nmapProgressBar "nmap/Script_${HOST}.nmap" 2 "${TIMEOUT_NMAP_SCRIPT}" \
                ${nmapType} -sCV -p"${commonPorts}" --open \
                -oN "nmap/Script_${HOST}.nmap" "${HOST}" ${DNSSTRING}
        fi

        if [ -f "nmap/Script_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Script_${HOST}.nmap"; then
            local serviceOS
            serviceOS="$(sed -n '/Service Info/s/.* \([^;]*\);.*/\1/p' "nmap/Script_${HOST}.nmap" | head -n 1)"
            if [ "${osType}" != "${serviceOS}" ]; then
                osType="${serviceOS}"
                printf "${NC}\n"
                printf "${NC}\n"
                printf "${GREEN}OS Detection modified to: ${osType}\n"
                printf "${NC}\n"
            fi
        fi
    else
        printf "${YELLOW}Script Scan is not supported in Remote mode.\n${NC}"
    fi

    echo
    echo
    echo
}

fullScan() {
    printf "${GREEN}---------------------Starting Full Scan------------------------\n"
    printf "${NC}\n"

    if ! $REMOTE; then
        nmapProgressBar "nmap/Full_${HOST}.nmap" 3 "${TIMEOUT_NMAP_FULL}" \
            ${nmapType} -p- --max-retries "${NMAP_MAX_RETRIES}" \
            --max-rate "${NMAP_MAX_RATE}" --max-scan-delay "${NMAP_MAX_SCAN_DELAY}" \
            -T"${NMAP_TIMING}" -v --open \
            -oN "nmap/Full_${HOST}.nmap" "${HOST}" ${DNSSTRING}
        assignPorts "${HOST}"

        if [ -z "${commonPorts}" ]; then
            echo
            echo
            printf "${YELLOW}Making a script scan on all ports\n"
            printf "${NC}\n"
            nmapProgressBar "nmap/Full_Extra_${HOST}.nmap" 2 "${TIMEOUT_NMAP_SCRIPT}" \
                ${nmapType} -sCV -p"${allPorts}" --open \
                -oN "nmap/Full_Extra_${HOST}.nmap" "${HOST}" ${DNSSTRING}
            assignPorts "${HOST}"
        else
            cmpPorts
            if [ -z "${extraPorts}" ]; then
                echo
                echo
                allPorts=""
                printf "${YELLOW}No new ports\n"
                printf "${NC}\n"
            else
                echo
                echo
                printf "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')\n"
                printf "${NC}\n"
                nmapProgressBar "nmap/Full_Extra_${HOST}.nmap" 2 "${TIMEOUT_NMAP_SCRIPT}" \
                    ${nmapType} -sCV -p"${extraPorts}" --open \
                    -oN "nmap/Full_Extra_${HOST}.nmap" "${HOST}" ${DNSSTRING}
                assignPorts "${HOST}"
            fi
        fi
    else
        printf "${YELLOW}Full Scan is not implemented yet in Remote mode.\n${NC}"
    fi

    echo
    echo
    echo
}

UDPScan() {
    printf "${GREEN}----------------------Starting UDP Scan------------------------\n"
    printf "${NC}\n"

    if ! $REMOTE; then
        if [ "${USER}" != 'root' ]; then
            echo "UDP needs to be run as root, running with sudo..."
            sudo -v
            echo
        fi

        nmapProgressBar "nmap/UDP_${HOST}.nmap" 3 "${TIMEOUT_NMAP_UDP}" \
            sudo ${nmapType} -sU --max-retries "${NMAP_MAX_RETRIES}" --open \
            -oN "nmap/UDP_${HOST}.nmap" "${HOST}" ${DNSSTRING}
        assignPorts "${HOST}"

        if [ -n "${udpPorts}" ]; then
            echo
            echo
            printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
            printf "${NC}\n"

            local nmap_scripts_dir
            nmap_scripts_dir="$(find_nmap_scripts_dir)"
            if [ -n "$nmap_scripts_dir" ] && [ -f "${nmap_scripts_dir}/vulners.nse" ]; then
                sudo -v
                nmapProgressBar "nmap/UDP_Extra_${HOST}.nmap" 2 "${TIMEOUT_NMAP_SCRIPT}" \
                    sudo ${nmapType} -sCVU --script vulners \
                    --script-args "mincvss=${NMAP_MIN_CVSS}" -p"${udpPorts}" --open \
                    -oN "nmap/UDP_Extra_${HOST}.nmap" "${HOST}" ${DNSSTRING}
            else
                sudo -v
                nmapProgressBar "nmap/UDP_Extra_${HOST}.nmap" 2 "${TIMEOUT_NMAP_SCRIPT}" \
                    sudo ${nmapType} -sCVU -p"${udpPorts}" --open \
                    -oN "nmap/UDP_Extra_${HOST}.nmap" "${HOST}" ${DNSSTRING}
            fi
        else
            echo
            echo
            printf "${YELLOW}No UDP ports are open\n"
            printf "${NC}\n"
        fi
    else
        printf "${YELLOW}UDP Scan is not implemented yet in Remote mode.\n${NC}"
    fi

    echo
    echo
    echo
}

vulnsScan() {
    printf "${GREEN}---------------------Starting Vulns Scan-----------------------\n"
    printf "${NC}\n"

    if ! $REMOTE; then
        local portType ports
        if [ -z "${allPorts}" ]; then
            portType="common"
            ports="${commonPorts}"
        else
            portType="all"
            ports="${allPorts}"
        fi

        local nmap_scripts_dir
        nmap_scripts_dir="$(find_nmap_scripts_dir)"

        if [ -z "$nmap_scripts_dir" ] || [ ! -f "${nmap_scripts_dir}/vulners.nse" ]; then
            printf "${RED}vulners.nse not found. Install from: https://github.com/vulnersCom/nmap-vulners\n"
            printf "${RED}Skipping CVE scan!\n"
            printf "${NC}\n"
        else
            printf "${YELLOW}Running CVE scan on ${portType} ports\n"
            printf "${NC}\n"
            nmapProgressBar "nmap/CVEs_${HOST}.nmap" 3 "${TIMEOUT_NMAP_VULNS}" \
                ${nmapType} -sV --script vulners \
                --script-args "mincvss=${NMAP_MIN_CVSS}" -p"${ports}" --open \
                -oN "nmap/CVEs_${HOST}.nmap" "${HOST}" ${DNSSTRING}
            echo
        fi

        echo
        printf "${YELLOW}Running Vuln scan on ${portType} ports\n"
        printf "${YELLOW}This may take a while, depending on the number of detected services..\n"
        printf "${NC}\n"
        nmapProgressBar "nmap/Vulns_${HOST}.nmap" 3 "${TIMEOUT_NMAP_VULNS}" \
            ${nmapType} -sV --script vuln -p"${ports}" --open \
            -oN "nmap/Vulns_${HOST}.nmap" "${HOST}" ${DNSSTRING}
    else
        printf "${YELLOW}Vulns Scan is not supported in Remote mode.\n${NC}"
    fi

    echo
    echo
    echo
}
