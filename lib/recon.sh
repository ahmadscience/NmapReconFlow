#!/usr/bin/env bash
# NmapReconFlow - Recon recommendation and execution

is_tool_skipped() {
    local tool="$1"
    if [ -n "${SKIP_RECON_TOOLS}" ]; then
        local IFS=','
        local skip
        for skip in ${SKIP_RECON_TOOLS}; do
            [ "$skip" = "$tool" ] && return 0
        done
    fi
    return 1
}

reconRecommend() {
    printf "${GREEN}---------------------Recon Recommendations---------------------\n"
    printf "${NC}\n"

    local IFS=$'\n'
    local ports="" file=""

    if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
        ports="${allPorts}"
        file="$(cat "nmap/Script_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
    elif [ -f "nmap/Script_${HOST}.nmap" ]; then
        ports="${commonPorts}"
        file="$(grep "open" "nmap/Script_${HOST}.nmap" | grep -v "#")"
    fi

    # SMTP recon
    if echo "${file}" | grep -q "25/tcp"; then
        local users_wordlist
        users_wordlist="$(find_wordlist "${WORDLIST_USERS}")" || users_wordlist="/usr/share/wordlists/metasploit/unix_users.txt"
        if ! is_tool_skipped "smtp-user-enum"; then
            printf "${NC}\n"
            printf "${YELLOW}SMTP Recon:\n"
            printf "${NC}\n"
            echo "smtp-user-enum -U \"${users_wordlist}\" -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""
            echo
        fi
    fi

    # DNS Recon
    if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
        printf "${NC}\n"
        printf "${YELLOW}DNS Recon:\n"
        printf "${NC}\n"
        if ! is_tool_skipped "host"; then
            echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""
        fi
        if ! is_tool_skipped "dnsrecon"; then
            echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"recon/dnsrecon_${HOST}.txt\""
            echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"recon/dnsrecon-local_${HOST}.txt\""
        fi
        if ! is_tool_skipped "dig"; then
            echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"recon/dig_${HOST}.txt\""
        fi
        echo
    fi

    # Web recon
    if echo "${file}" | grep -i -q http; then
        printf "${NC}\n"
        printf "${YELLOW}Web Servers Recon:\n"
        printf "${NC}\n"

        local dirb_wordlist
        dirb_wordlist="$(find_wordlist "${WORDLIST_DIRB}")" || dirb_wordlist="/usr/share/wordlists/dirb/common.txt"

        local line
        for line in ${file}; do
            if echo "${line}" | grep -i -q http; then
                local port urlType extensions
                port="$(echo "${line}" | cut -d "/" -f 1)"
                if echo "${line}" | grep -q ssl/http; then
                    urlType='https://'
                    if ! is_tool_skipped "sslscan"; then
                        echo "sslscan \"${HOST}\" | tee \"recon/sslscan_${HOST}_${port}.txt\""
                    fi
                    if ! is_tool_skipped "nikto"; then
                        echo "nikto -host \"${urlType}${HOST}:${port}\" -ssl -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"recon/nikto_${HOST}_${port}.txt\""
                    fi
                else
                    urlType='http://'
                    if ! is_tool_skipped "nikto"; then
                        echo "nikto -host \"${urlType}${HOST}:${port}\" -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"recon/nikto_${HOST}_${port}.txt\""
                    fi
                fi

                if command -v ffuf >/dev/null 2>&1 && ! is_tool_skipped "ffuf"; then
                    local tmpindex
                    tmpindex="$(mktemp ./index.XXXXXX)"
                    echo 'index' >"$tmpindex"
                    extensions="$(ffuf -s -w "${tmpindex}":FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/,$//')"
                    rm -f "$tmpindex"
                    local rate_flag=""
                    [ "${FFUF_RATE:-0}" -gt 0 ] 2>/dev/null && rate_flag="-rate ${FFUF_RATE}"
                    echo "ffuf -ic -w \"${dirb_wordlist}\" -e '${extensions}' ${rate_flag} -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                elif command -v gobuster >/dev/null 2>&1 && ! is_tool_skipped "gobuster"; then
                    local tmpindex
                    tmpindex="$(mktemp ./index.XXXXXX)"
                    echo 'index' >"$tmpindex"
                    extensions="$(gobuster dir -w "${tmpindex}" -t ${GOBUSTER_THREADS} -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -u "${urlType}${HOST}:${port}" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/,$//')"
                    rm -f "$tmpindex"
                    echo "gobuster dir -w \"${dirb_wordlist}\" -t ${GOBUSTER_THREADS} -ekx '${extensions}' -u \"${urlType}${HOST}:${port}\" -o \"recon/gobuster_${HOST}_${port}.txt\""
                fi
                echo
            fi
        done

        # CMS recon
        if [ -f "nmap/Script_${HOST}.nmap" ]; then
            local cms
            cms="$(grep http-generator "nmap/Script_${HOST}.nmap" | cut -d " " -f 2)"
            if [ -n "${cms}" ]; then
                local cms_line
                for cms_line in ${cms}; do
                    local port
                    port="$(sed -n 'H;x;s/\/.*'"${cms_line}"'.*//p' "nmap/Script_${HOST}.nmap")"

                    case "${cms_line}" in
                        Joomla*|WordPress|Drupal)
                            printf "${NC}\n"
                            printf "${YELLOW}CMS Recon:\n"
                            printf "${NC}\n"
                            ;;
                    esac
                    case "${cms_line}" in
                        Joomla*)
                            ! is_tool_skipped "joomscan" && echo "joomscan --url \"${HOST}:${port}\" | tee \"recon/joomscan_${HOST}_${port}.txt\""
                            ;;
                        WordPress)
                            if ! is_tool_skipped "wpscan"; then
                                local throttle_flag=""
                                [ "${WPSCAN_THROTTLE:-0}" -gt 0 ] 2>/dev/null && throttle_flag="--throttle ${WPSCAN_THROTTLE}"
                                echo "wpscan --url \"${HOST}:${port}\" --enumerate p ${throttle_flag} | tee \"recon/wpscan_${HOST}_${port}.txt\""
                            fi
                            ;;
                        Drupal)
                            ! is_tool_skipped "droopescan" && echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"recon/droopescan_${HOST}_${port}.txt\""
                            ;;
                    esac
                done
            fi
        fi
    fi

    # Non-standard web port detection
    if [ -n "${EXTRA_WEB_PORTS}" ]; then
        local IFS=','
        local extra_port
        for extra_port in ${EXTRA_WEB_PORTS}; do
            if echo "${file}" | grep -q "^${extra_port}/tcp" && \
               ! echo "${file}" | grep -i -q "^${extra_port}/tcp.*http"; then
                local urlType="http://"
                case "${extra_port}" in
                    *443*) urlType="https://" ;;
                esac
                printf "${NC}\n"
                printf "${YELLOW}Detected non-standard web port ${extra_port}:\n"
                printf "${NC}\n"
                if command -v nikto >/dev/null 2>&1 && ! is_tool_skipped "nikto"; then
                    echo "nikto -host \"${urlType}${HOST}:${extra_port}\" -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"recon/nikto_${HOST}_${extra_port}.txt\""
                fi
                if command -v gobuster >/dev/null 2>&1 && ! is_tool_skipped "gobuster"; then
                    local dirb_wordlist
                    dirb_wordlist="$(find_wordlist "${WORDLIST_DIRB}")" || dirb_wordlist="/usr/share/wordlists/dirb/common.txt"
                    echo "gobuster dir -w \"${dirb_wordlist}\" -t ${GOBUSTER_THREADS} -eku \"${urlType}${HOST}:${extra_port}\" -o \"recon/gobuster_${HOST}_${extra_port}.txt\""
                fi
                echo
            fi
        done
    fi

    # SNMP recon
    if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
        printf "${NC}\n"
        printf "${YELLOW}SNMP Recon:\n"
        printf "${NC}\n"
        ! is_tool_skipped "snmp-check" && echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
        ! is_tool_skipped "snmpwalk" && echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""
        echo
    fi

    # LDAP recon
    if echo "${file}" | grep -q "389/tcp"; then
        if ! is_tool_skipped "ldapsearch"; then
            printf "${NC}\n"
            printf "${YELLOW}LDAP Recon:\n"
            printf "${NC}\n"
            echo "ldapsearch -x -H \"ldap://${HOST}\" -s base | tee \"recon/ldapsearch_${HOST}.txt\""
            echo "ldapsearch -x -H \"ldap://${HOST}\" -b \"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"recon/ldapsearch_DC_${HOST}.txt\""
            echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d \" \" -f2)\"' \"${HOST}\" -oN \"recon/nmap_ldap_${HOST}.txt\""
            echo
        fi
    fi

    # SMB recon
    if echo "${file}" | grep -q "445/tcp"; then
        printf "${NC}\n"
        printf "${YELLOW}SMB Recon:\n"
        printf "${NC}\n"
        ! is_tool_skipped "smbmap" && echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
        ! is_tool_skipped "smbclient" && echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
        if [ "${osType}" = "Windows" ]; then
            echo "nmap -Pn -p445 --script vuln -oN \"recon/SMB_vulns_${HOST}.txt\" \"${HOST}\""
        elif [ "${osType}" = "Linux" ]; then
            ! is_tool_skipped "enum4linux" && echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
        fi
        echo
    elif echo "${file}" | grep -q "139/tcp" && [ "${osType}" = "Linux" ]; then
        printf "${NC}\n"
        printf "${YELLOW}SMB Recon:\n"
        printf "${NC}\n"
        ! is_tool_skipped "enum4linux" && echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
        echo
    fi

    # Oracle DB recon
    if echo "${file}" | grep -q "1521/tcp"; then
        if ! is_tool_skipped "odat"; then
            printf "${NC}\n"
            printf "${YELLOW}Oracle Recon:\n"
            printf "${NC}\n"
            echo "odat sidguesser -s \"${HOST}\" -p 1521"
            echo "odat passwordguesser -s \"${HOST}\" -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
            echo
        fi
    fi

    # Searchsploit against nmap XML (offline, non-intrusive). Requires XML output.
    if [ "${ENABLE_SEARCHSPLOIT}" = "true" ] && ! is_tool_skipped "searchsploit"; then
        local xml=""
        [ -f "nmap/Script_${HOST}.xml" ] && xml="nmap/Script_${HOST}.xml"
        [ -f "nmap/Full_Extra_${HOST}.xml" ] && xml="nmap/Full_Extra_${HOST}.xml"
        if [ -n "${xml}" ]; then
            printf "${NC}\n"
            printf "${YELLOW}Exploit DB Recon:\n"
            printf "${NC}\n"
            echo "searchsploit --nmap \"${xml}\" | tee \"recon/searchsploit_${HOST}.txt\""
            echo
        fi
    fi

    # Intrusive follow-ups go to a manual-commands file rather than auto-run,
    # to avoid account lockouts / noisy brute force during unattended scans.
    suggest_manual_followups "${file}"

    IFS="${origIFS}"

    echo
    echo
    echo
}

# Record intrusive, human-in-the-loop commands to recon/_manual_commands.txt.
# When RUN_BRUTE=true, emit runnable hydra commands for credential services
# (ssh/ftp/rdp) to stdout so runRecon executes them with real wordlists.
suggest_manual_followups() {
    local file="$1"
    local manual="recon/_manual_commands.txt"
    mkdir -p recon/ 2>/dev/null

    if [ "${RUN_BRUTE}" = "true" ] && command -v hydra >/dev/null 2>&1; then
        local ulist plist
        ulist="$(find_wordlist "${BRUTE_USERLIST}")" || ulist=""
        plist="$(find_wordlist "${BRUTE_PASSLIST}")" || plist=""
        if [ -n "${ulist}" ] && [ -n "${plist}" ]; then
            printf "${RED}RUN_BRUTE enabled: auto-running hydra against credential services (lockout risk!)${NC}\n" >&2
            local svc
            for svc in ssh ftp rdp; do
                case "${svc}" in
                    ssh) echo "${file}" | grep -q "22/tcp"  || continue ;;
                    ftp) echo "${file}" | grep -q "21/tcp"  || continue ;;
                    rdp) echo "${file}" | grep -q "3389/tcp" || continue ;;
                esac
                echo "hydra -L \"${ulist}\" -P \"${plist}\" -f -t 4 ${svc}://${HOST} | tee \"recon/hydra_${svc}_${HOST}.txt\""
            done
        else
            log_warning "RUN_BRUTE=true but brute wordlists not found; writing manual commands instead"
        fi
    fi

    local -a lines=()
    echo "${file}" | grep -q "22/tcp"  && lines+=("# SSH brute force (set USER/PASS lists):" "hydra -L users.txt -P passwords.txt ssh://${HOST}")
    echo "${file}" | grep -q "21/tcp"  && lines+=("# FTP brute force / anonymous check:" "hydra -L users.txt -P passwords.txt ftp://${HOST}" "ftp ${HOST}  # try anonymous:anonymous")
    echo "${file}" | grep -q "3389/tcp" && lines+=("# RDP brute force:" "hydra -L users.txt -P passwords.txt rdp://${HOST}")
    echo "${file}" | grep -i -q http    && lines+=("# Web auth brute force (adjust path/form):" "hydra -L users.txt -P passwords.txt ${HOST} http-get /")
    echo "${file}" | grep -q "445/tcp"  && lines+=("# SMB password spray (lockout risk):" "crackmapexec smb ${HOST} -u users.txt -p passwords.txt")

    [ ${#lines[@]} -eq 0 ] && return 0

    {
        echo "# ==== Manual follow-ups for ${HOST} ($(date '+%Y-%m-%d %H:%M')) ===="
        echo "# These are intrusive (brute force / spraying). Review scope & lockout policy first."
        local l
        for l in "${lines[@]}"; do echo "$l"; done
        echo
    } >> "${manual}"
    printf "${YELLOW}Manual follow-up commands written to recon/_manual_commands.txt${NC}\n" >&2
}

recon() {
    local IFS=$'\n'

    reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
    local allRecon
    allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

    local missingTools=""
    local tool
    for tool in ${allRecon}; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            missingTools="$(echo ${missingTools} ${tool} | awk '{$1=$1};1')"
        fi
    done

    local availableRecon=""
    if [ -n "${missingTools}" ]; then
        printf "${RED}Missing tools: ${NC}${missingTools}\n"
        printf "\n${RED}You can install with:\n"
        printf "${YELLOW}sudo apt install ${missingTools} -y\n"
        printf "${NC}\n\n"
        availableRecon="$(echo "${allRecon}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
    else
        availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
    fi

    if [ -n "${availableRecon}" ]; then
        if $AUTOPILOT; then
            printf "${GREEN}Autopilot: Running all recon commands automatically\n${NC}\n"
            runRecon "${HOST}" "All"
        else
            local reconCommand=""
            local secs=30
            local count=0
            while [ "${reconCommand}" != "!" ]; do
                printf "${YELLOW}\n"
                printf "Which commands would you like to run?${NC}\nAll (Default), ${availableRecon}, Skip <!>\n\n"
                while [ ${count} -lt ${secs} ]; do
                    local tlimit=$((secs - count))
                    printf "\033[2K\rRunning Default in (${tlimit})s: "
                    read -t 1 -r reconCommand || true
                    count=$((count + 1))
                    [ -n "${reconCommand}" ] && break
                done
                if [[ "${reconCommand}" =~ ^[Aa]ll$ ]] || [ -z "${reconCommand}" ]; then
                    runRecon "${HOST}" "All"
                    reconCommand="!"
                elif [[ " ${availableRecon}," == *" ${reconCommand},"* ]]; then
                    runRecon "${HOST}" "${reconCommand}"
                    reconCommand="!"
                elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                    reconCommand="!"
                    echo
                    echo
                    echo
                else
                    printf "${NC}\n"
                    printf "${RED}Incorrect choice!\n"
                    printf "${NC}\n"
                fi
            done
        fi
    else
        printf "${YELLOW}No Recon Recommendations found...\n"
        printf "${NC}\n\n\n"
    fi

    IFS="${origIFS}"
}

declare -A RECON_TOOL_STATUS=()
declare -A RECON_TOOL_DURATION=()

runRecon() {
    echo
    echo
    echo
    printf "${GREEN}---------------------Running Recon Commands--------------------\n"
    printf "${NC}\n"

    local IFS=$'\n'
    local reconCommands

    mkdir -p recon/

    if [ "$2" = "All" ]; then
        reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
    else
        reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
    fi

    local line
    for line in ${reconCommands}; do
        local currentScan
        currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
        local fileName
        fileName="$(echo "${line}" | awk -F "recon/" '{print $2}')"
        if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
            printf "${NC}\n"
            printf "${YELLOW}Starting ${currentScan} scan\n"
            printf "${NC}\n"

            if $DRY_RUN; then
                printf "${YELLOW}[DRY-RUN] Would execute: %s${NC}\n" "${line}" >&2
                continue
            fi

            local tool_start
            tool_start="$(date +%s)"

            run_with_timeout "${TIMEOUT_RECON_DEFAULT}" "${currentScan}" bash -c "${line}"
            local rc=$?

            local tool_end
            tool_end="$(date +%s)"
            local tool_duration=$((tool_end - tool_start))
            RECON_TOOL_DURATION["${currentScan}_${fileName}"]="$tool_duration"

            if [ $rc -eq 124 ]; then
                RECON_TOOL_STATUS["${currentScan}_${fileName}"]="timeout"
                printf "${RED}${currentScan} scan TIMED OUT after $(format_duration ${tool_duration})\n"
            else
                RECON_TOOL_STATUS["${currentScan}_${fileName}"]="completed"
                printf "${NC}\n"
                printf "${YELLOW}Finished ${currentScan} scan\n"
            fi
            printf "${NC}\n"
            printf "${YELLOW}=========================\n"
        fi
    done

    IFS="${origIFS}"

    echo
    echo
    echo
}
