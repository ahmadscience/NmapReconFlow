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

# Build a recon output file path for a tool/host(/port). With
# RECON_PER_PORT_DIRS=true and a port given, groups output under recon/<port>/
# (AutoRecon-style) and creates that directory as a side effect so the emitted
# command can write to it. Otherwise uses the flat legacy layout. Host-level
# tools (no port) always stay in recon/ root.
recon_outfile() {
    local tool="$1" host="$2" port="${3:-}"
    if [ "${RECON_PER_PORT_DIRS}" = "true" ] && [ -n "${port}" ]; then
        mkdir -p "recon/${port}" 2>/dev/null
        printf 'recon/%s/%s_%s.txt' "${port}" "${tool}" "${host}"
    elif [ -n "${port}" ]; then
        printf 'recon/%s_%s_%s.txt' "${tool}" "${host}" "${port}"
    else
        printf 'recon/%s_%s.txt' "${tool}" "${host}"
    fi
}

# Extract the output file (path relative to recon/) a recommended command
# writes to: the LAST "recon/<path>" on the line (earlier ones can be inputs,
# e.g. the ldapsearch DC query reads recon/ldapsearch_<host>.txt), with
# surrounding quotes stripped. Empty if the command writes no recon file.
recon_line_outfile() {
    printf '%s\n' "$1" | sed -n 's|.*recon/\([^"'"'"' ]*\).*|\1|p'
}

# Print the TCP ports in recon-recommend input ($1: nmap "open" lines) whose
# service column (minus any "ssl/" prefix) matches the extended regex $2.
ports_for_service() {
    printf '%s\n' "$1" | awk -v re="$2" '
        $1 ~ /^[0-9]+\/tcp$/ && $2 ~ /^open/ {
            svc = $3; sub(/^ssl\//, "", svc)          # ssl/imap -> imap
            if (svc ~ re) { split($1, a, "/"); print a[1] }
        }' \
        | sort -n -u
}

# Host as it must appear inside a URL (IPv6 literals need brackets).
url_host() {
    if is_ipv6 "$1"; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
}

# Emit a targeted, non-intrusive nmap NSE command for one service port.
emit_nse_recon() {
    local name="$1" port="$2" scripts="$3"
    local v6=""
    is_ipv6 "${HOST}" && v6="-6 "
    echo "nmap ${v6}-Pn -sV -p${port} --script \"${scripts}\" \"${HOST}\" -oN \"$(recon_outfile "nmap_${name}" "${HOST}" "${port}")\""
}

reconRecommend() {
    printf -- "${GREEN}---------------------Recon Recommendations---------------------\n"
    printf "${NC}\n"

    local IFS=$'\n'
    local ports="" file=""
    # Web URLs found below; consumed by nuclei/gowitness and exports.
    local webUrlsFile="recon/_web_urls_${HOST}.txt"

    if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
        ports="${allPorts}"
        file="$(cat "nmap/Script_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | grep -v "^#" | sort | uniq)"
    elif [ -f "nmap/Script_${HOST}.nmap" ]; then
        ports="${commonPorts}"
        file="$(grep "open" "nmap/Script_${HOST}.nmap" | grep -v "^#")"
    fi

    # Port checks below are anchored ("^389/tcp"): an unanchored "389/tcp"
    # would also match 3389/tcp (RDP), "21/tcp" would match 1521/tcp, etc.

    # SMTP recon
    if echo "${file}" | grep -q "^25/tcp"; then
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
    if echo "${file}" | grep -q "^53/tcp" && [ -n "${DNSSERVER}" ]; then
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

        local webHost
        webHost="$(url_host "${HOST}")"
        mkdir -p recon/ 2>/dev/null
        : > "${webUrlsFile}"

        local line
        for line in ${file}; do
            # Only real port lines ("80/tcp open http ..."), not NSE output
            # such as "|_http-open-proxy: ...".
            [[ "${line}" =~ ^[0-9]+/tcp ]] || continue
            if echo "${line}" | grep -i -q http; then
                local port urlType extensions
                port="$(echo "${line}" | cut -d "/" -f 1)"
                if echo "${line}" | grep -q ssl/http; then
                    urlType='https://'
                    if ! is_tool_skipped "sslscan"; then
                        echo "sslscan \"${HOST}:${port}\" | tee \"$(recon_outfile sslscan "${HOST}" "${port}")\""
                    fi
                    if ! is_tool_skipped "nikto"; then
                        echo "nikto -host \"${urlType}${webHost}:${port}\" -ssl -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"$(recon_outfile nikto "${HOST}" "${port}")\""
                    fi
                else
                    urlType='http://'
                    if ! is_tool_skipped "nikto"; then
                        echo "nikto -host \"${urlType}${webHost}:${port}\" -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"$(recon_outfile nikto "${HOST}" "${port}")\""
                    fi
                fi
                echo "${urlType}${webHost}:${port}" >> "${webUrlsFile}"

                # Fingerprint (CMS, frameworks, headers) - one request per URL.
                if [ "${ENABLE_WHATWEB}" = "true" ] && ! is_tool_skipped "whatweb"; then
                    echo "whatweb --color=never -a 1 \"${urlType}${webHost}:${port}\" | tee \"$(recon_outfile whatweb "${HOST}" "${port}")\""
                fi

                # Probe which index.<ext> the server answers so directory
                # brute force only tries relevant extensions. Bounded by a
                # timeout; skipped in dry-run (it would hit the target).
                if command -v ffuf >/dev/null 2>&1 && ! is_tool_skipped "ffuf"; then
                    extensions=""
                    if ! $DRY_RUN; then
                        local tmpindex
                        tmpindex="$(mktemp ./index.XXXXXX)"
                        echo 'index' >"$tmpindex"
                        extensions="$(run_with_timeout 60 "ffuf probe" ffuf -s -w "${tmpindex}":FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${webHost}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/,$//')"
                        rm -f "$tmpindex"
                    fi
                    local rate_flag="" ext_flag=""
                    [ "${FFUF_RATE:-0}" -gt 0 ] 2>/dev/null && rate_flag="-rate ${FFUF_RATE}"
                    [ -n "${extensions}" ] && ext_flag="-e '${extensions}'"
                    echo "ffuf -ic -w \"${dirb_wordlist}\" ${ext_flag} ${rate_flag} -u \"${urlType}${webHost}:${port}/FUZZ\" | tee \"$(recon_outfile ffuf "${HOST}" "${port}")\""
                elif command -v gobuster >/dev/null 2>&1 && ! is_tool_skipped "gobuster"; then
                    extensions=""
                    if ! $DRY_RUN; then
                        local tmpindex
                        tmpindex="$(mktemp ./index.XXXXXX)"
                        echo 'index' >"$tmpindex"
                        extensions="$(run_with_timeout 60 "gobuster probe" gobuster dir -w "${tmpindex}" -t ${GOBUSTER_THREADS} -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -b '' -u "${urlType}${webHost}:${port}" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/,$//')"
                        rm -f "$tmpindex"
                    fi
                    local ext_flag=""
                    [ -n "${extensions}" ] && ext_flag="-x '${extensions}'"
                    echo "gobuster dir -w \"${dirb_wordlist}\" -t ${GOBUSTER_THREADS} -ek ${ext_flag} -u \"${urlType}${webHost}:${port}\" -o \"$(recon_outfile gobuster "${HOST}" "${port}")\""
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
                            ! is_tool_skipped "joomscan" && echo "joomscan --url \"${HOST}:${port}\" | tee \"$(recon_outfile joomscan "${HOST}" "${port}")\""
                            ;;
                        WordPress)
                            if ! is_tool_skipped "wpscan"; then
                                local throttle_flag=""
                                [ "${WPSCAN_THROTTLE:-0}" -gt 0 ] 2>/dev/null && throttle_flag="--throttle ${WPSCAN_THROTTLE}"
                                echo "wpscan --url \"${HOST}:${port}\" --enumerate p ${throttle_flag} | tee \"$(recon_outfile wpscan "${HOST}" "${port}")\""
                            fi
                            ;;
                        Drupal)
                            ! is_tool_skipped "droopescan" && echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"$(recon_outfile droopescan "${HOST}" "${port}")\""
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
                local xHost
                xHost="$(url_host "${HOST}")"
                printf "${NC}\n"
                printf "${YELLOW}Detected non-standard web port ${extra_port}:\n"
                printf "${NC}\n"
                mkdir -p recon/ 2>/dev/null
                echo "${urlType}${xHost}:${extra_port}" >> "${webUrlsFile}"
                if command -v nikto >/dev/null 2>&1 && ! is_tool_skipped "nikto"; then
                    echo "nikto -host \"${urlType}${xHost}:${extra_port}\" -maxtime ${TIMEOUT_RECON_DEFAULT}s | tee \"$(recon_outfile nikto "${HOST}" "${extra_port}")\""
                fi
                if command -v gobuster >/dev/null 2>&1 && ! is_tool_skipped "gobuster"; then
                    local dirb_wordlist
                    dirb_wordlist="$(find_wordlist "${WORDLIST_DIRB}")" || dirb_wordlist="/usr/share/wordlists/dirb/common.txt"
                    echo "gobuster dir -w \"${dirb_wordlist}\" -t ${GOBUSTER_THREADS} -ek -u \"${urlType}${xHost}:${extra_port}\" -o \"$(recon_outfile gobuster "${HOST}" "${extra_port}")\""
                fi
                echo
            fi
        done
    fi

    # Web vulnerability templates + screenshots over every discovered URL
    # (opt-in: nuclei sends active checks; gowitness drives a browser).
    IFS="${origIFS}"
    if [ -s "${webUrlsFile}" ]; then
        local _sorted
        _sorted="$(sort -u "${webUrlsFile}")"
        printf '%s\n' "${_sorted}" > "${webUrlsFile}"
        if [ "${RUN_NUCLEI}" = "true" ] && ! is_tool_skipped "nuclei"; then
            printf "${NC}\n"
            printf "${YELLOW}Nuclei:\n"
            printf "${NC}\n"
            echo "nuclei -l \"${webUrlsFile}\" -severity \"${NUCLEI_SEVERITY}\" -no-color -silent | tee \"recon/nuclei_${HOST}.txt\""
            echo
        fi
        if [ "${RUN_SCREENSHOTS}" = "true" ] && ! is_tool_skipped "gowitness"; then
            printf "${NC}\n"
            printf "${YELLOW}Screenshots:\n"
            printf "${NC}\n"
            mkdir -p "recon/screenshots_${HOST}" 2>/dev/null
            if command -v gowitness >/dev/null 2>&1 && ! gowitness scan --help >/dev/null 2>&1; then
                # gowitness v2 syntax
                echo "gowitness file -f \"${webUrlsFile}\" -P \"recon/screenshots_${HOST}\" 2>&1 | tee \"recon/gowitness_${HOST}.txt\""
            else
                # gowitness v3 syntax
                echo "gowitness scan file -f \"${webUrlsFile}\" -s \"recon/screenshots_${HOST}\" 2>&1 | tee \"recon/gowitness_${HOST}.txt\""
            fi
            echo
        fi
    else
        rm -f "${webUrlsFile}" 2>/dev/null
    fi
    IFS=$'\n'

    # Targeted service enumeration with safe NSE scripts (non-intrusive).
    if [ "${ENABLE_SERVICE_NSE}" = "true" ] && ! is_tool_skipped "nmap-nse"; then
        local _svc _port _hdr=false
        # name;service-column regex;NSE scripts (";" because regexes use "|")
        local -a _nse_map=(
            "nfs;^(nfs|rpcbind|mountd);nfs-showmount,nfs-ls,nfs-statfs,rpcinfo"
            "mysql;^mysql;mysql-info"
            "mssql;^ms-sql;ms-sql-info,ms-sql-ntlm-info"
            "rdp;^ms-wbt-server;rdp-enum-encryption,rdp-ntlm-info"
            "redis;^redis;redis-info"
            "mongodb;^mongod;mongodb-info,mongodb-databases"
            "vnc;^vnc;vnc-info"
            "smtp;^smtp;smtp-commands,smtp-ntlm-info"
            "imap;^imap;imap-capabilities,imap-ntlm-info"
            "pop3;^pop3;pop3-capabilities,pop3-ntlm-info"
            "memcached;^memcache;memcached-info"
            "rsync;^rsync;rsync-list-modules"
            "telnet;^telnet;telnet-encryption,telnet-ntlm-info"
            "ftp;^ftp;ftp-anon,ftp-syst"
        )
        local _entry _name _re _scripts
        for _entry in "${_nse_map[@]}"; do
            IFS=';' read -r _name _re _scripts <<< "${_entry}"
            IFS=$'\n'
            for _port in $(ports_for_service "${file}" "${_re}"); do
                if ! ${_hdr}; then
                    printf "${NC}\n"
                    printf "${YELLOW}Service Enumeration (safe NSE):\n"
                    printf "${NC}\n"
                    _hdr=true
                fi
                emit_nse_recon "${_name}" "${_port}" "${_scripts}"
            done
        done
        ${_hdr} && echo
    fi

    # NFS exports (showmount) when rpcbind/NFS is exposed
    if [ -n "$(ports_for_service "${file}" '^(nfs|rpcbind|mountd)')" ] && ! is_tool_skipped "showmount"; then
        printf "${NC}\n"
        printf "${YELLOW}NFS Recon:\n"
        printf "${NC}\n"
        echo "showmount -e \"${HOST}\" | tee \"recon/showmount_${HOST}.txt\""
        echo
    fi

    # SSH configuration audit (algorithms, CVEs) - only when installed
    if [ "${ENABLE_SSH_AUDIT}" = "true" ] && command -v ssh-audit >/dev/null 2>&1 && ! is_tool_skipped "ssh-audit"; then
        local _sshport _sshhdr=false
        for _sshport in $(ports_for_service "${file}" '^ssh'); do
            if ! ${_sshhdr}; then
                printf "${NC}\n"
                printf "${YELLOW}SSH Audit:\n"
                printf "${NC}\n"
                _sshhdr=true
            fi
            echo "ssh-audit -n -p ${_sshport} \"${HOST}\" | tee \"$(recon_outfile ssh-audit "${HOST}" "${_sshport}")\""
        done
        ${_sshhdr} && echo
    fi

    # SNMP recon
    if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "^161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
        printf "${NC}\n"
        printf "${YELLOW}SNMP Recon:\n"
        printf "${NC}\n"
        ! is_tool_skipped "snmp-check" && echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
        ! is_tool_skipped "snmpwalk" && echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""
        echo
    fi

    # LDAP recon
    if echo "${file}" | grep -q "^389/tcp"; then
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
    if echo "${file}" | grep -q "^445/tcp"; then
        printf "${NC}\n"
        printf "${YELLOW}SMB Recon:\n"
        printf "${NC}\n"
        ! is_tool_skipped "smbmap" && echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
        ! is_tool_skipped "smbclient" && echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
        if [ "${osType}" = "Windows" ]; then
            echo "nmap -Pn -p445 --script vuln \"${HOST}\" -oN \"recon/SMB_vulns_${HOST}.txt\""
        elif [ "${osType}" = "Linux" ]; then
            emit_enum4linux
        fi
        echo
    elif echo "${file}" | grep -q "^139/tcp" && [ "${osType}" = "Linux" ]; then
        printf "${NC}\n"
        printf "${YELLOW}SMB Recon:\n"
        printf "${NC}\n"
        emit_enum4linux
        echo
    fi

    # Oracle DB recon
    if echo "${file}" | grep -q "^1521/tcp"; then
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

# enum4linux-ng (maintained rewrite, default on current Kali) when present,
# else classic enum4linux.
emit_enum4linux() {
    if command -v enum4linux-ng >/dev/null 2>&1 && ! is_tool_skipped "enum4linux-ng"; then
        echo "enum4linux-ng -A \"${HOST}\" | tee \"recon/enum4linux-ng_${HOST}.txt\""
    elif ! is_tool_skipped "enum4linux"; then
        echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
    fi
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
                    ssh) echo "${file}" | grep -q "^22/tcp"  || continue ;;
                    ftp) echo "${file}" | grep -q "^21/tcp"  || continue ;;
                    rdp) echo "${file}" | grep -q "^3389/tcp" || continue ;;
                esac
                echo "hydra -L \"${ulist}\" -P \"${plist}\" -f -t 4 ${svc}://${HOST} | tee \"recon/hydra_${svc}_${HOST}.txt\""
            done
        else
            log_warning "RUN_BRUTE=true but brute wordlists not found; writing manual commands instead"
        fi
    fi

    local -a lines=()
    echo "${file}" | grep -q "^22/tcp"  && lines+=("# SSH brute force (set USER/PASS lists):" "hydra -L users.txt -P passwords.txt ssh://${HOST}")
    echo "${file}" | grep -q "^21/tcp"  && lines+=("# FTP brute force / anonymous check:" "hydra -L users.txt -P passwords.txt ftp://${HOST}" "ftp ${HOST}  # try anonymous:anonymous")
    echo "${file}" | grep -q "^3389/tcp" && lines+=("# RDP brute force:" "hydra -L users.txt -P passwords.txt rdp://${HOST}")
    echo "${file}" | grep -i -q http    && lines+=("# Web auth brute force (adjust path/form):" "hydra -L users.txt -P passwords.txt ${HOST} http-get /")
    local spray="crackmapexec"
    command -v nxc >/dev/null 2>&1 && spray="nxc"   # NetExec, CME's successor
    echo "${file}" | grep -q "^445/tcp"  && lines+=("# SMB password spray (lockout risk):" "${spray} smb ${HOST} -u users.txt -p passwords.txt")
    echo "${file}" | grep -q -E "^(5985|5986)/tcp" && lines+=("# WinRM login check (with valid creds):" "${spray} winrm ${HOST} -u USER -p PASS" "evil-winrm -i ${HOST} -u USER -p PASS")
    echo "${file}" | grep -q "^88/tcp"  && lines+=("# Kerberos user enumeration / AS-REP roast (set DOMAIN):" "kerbrute userenum -d DOMAIN --dc ${HOST} users.txt" "impacket-GetNPUsers DOMAIN/ -dc-ip ${HOST} -usersfile users.txt -no-pass")

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
        printf "${RED}Missing tools (will be skipped): ${NC}${missingTools}\n"
        printf "\n${RED}You can install with:\n"
        printf "${YELLOW}%s\n" "$(IFS="${origIFS}"; install_hint "${missingTools}")"
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
                    if $IS_TTY; then
                        printf "\033[2K\rRunning Default in (${tlimit})s: "
                    elif [ "${count}" -eq 0 ]; then
                        printf "Running Default in ${secs}s unless you choose: "
                    fi
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
        if [ -n "${allRecon}" ]; then
            printf "${YELLOW}No runnable recon commands: every recommended tool is missing (see above).\n"
        else
            printf "${YELLOW}No Recon Recommendations found...\n"
        fi
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
    printf -- "${GREEN}---------------------Running Recon Commands--------------------\n"
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
        fileName="$(recon_line_outfile "${line}")"
        # Already-present output = finished on a previous (resumed) run.
        if [ -n "${fileName}" ] && [ ! -f "recon/${fileName}" ]; then
            # Not installed: record and move on instead of "running" it.
            if ! command -v "${currentScan}" >/dev/null 2>&1; then
                RECON_TOOL_STATUS["${currentScan}_${fileName}"]="missing"
                RECON_TOOL_DURATION["${currentScan}_${fileName}"]=0
                printf "${YELLOW}Skipping ${currentScan}: not installed${NC}\n"
                continue
            fi

            printf "${NC}\n"
            printf "${YELLOW}Starting ${currentScan} scan\n"
            printf "${NC}\n"

            # Ensure any per-port subdirectory exists before the command runs.
            mkdir -p "$(dirname "recon/${fileName}")" 2>/dev/null

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
