#!/usr/bin/env bash
# NmapReconFlow - Summary report generation

parse_nmap_ports() {
    local file="$1"
    [ -f "$file" ] || return 0
    awk '/^[0-9]+\//{
        split($1, a, "/"); port=a[1]; proto=a[2];
        state=$2; service=$3;
        ver=""; for(i=4;i<=NF;i++) ver=ver" "$i;
        gsub(/^[ \t]+|[ \t]+$/,"",ver);
        print port"|"proto"|"state"|"service"|"ver
    }' "$file"
}

# Extract unique CVE IDs from an nmap output file as "CVE-ID|confidence".
# Matches the ID token itself (vulners lines also carry the ID inside a URL,
# which must not produce a second, mangled entry).
parse_vulns_from_file() {
    local file="$1"
    local confidence="$2"
    [ -f "$file" ] || return 0
    grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$file" 2>/dev/null | LC_ALL=C sort -u \
        | awk -v conf="$confidence" '{print $0 "|" conf}'
}

json_escape() {
    local val="$1"
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    val="${val//\//\\/}"
    val="${val//$'\n'/\\n}"
    val="${val//$'\t'/\\t}"
    val="${val//$'\r'/\\r}"
    printf '%s' "$val"
}

yaml_escape() {
    local val="$1"
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    val="${val//$'\n'/\\n}"
    val="${val//$'\t'/\\t}"
    val="${val//$'\r'/\\r}"
    printf '"%s"' "$val"
}

generate_json_report() {
    local host="$1"
    local scan_date="$2"
    local duration="$3"
    local json_file="summary.json"

    # Use nameref arrays passed via global scope
    local first=true
    local comma=""

    {
        printf '{\n'
        printf '  "target": "%s",\n' "$(json_escape "${host}")"
        printf '  "hostname": "%s",\n' "$(json_escape "${urlIP:-${host}}")"
        printf '  "os_detected": "%s",\n' "$(json_escape "${osType:-unknown}")"
        printf '  "scan_date": "%s",\n' "$(json_escape "${scan_date}")"
        printf '  "scan_duration_seconds": %d,\n' "${duration}"
        printf '  "scan_type": "%s",\n' "$(json_escape "${TYPE}")"
        printf '  "scan_profile": "%s",\n' "$(json_escape "${SCAN_PROFILE:-normal}")"

        # Ports array
        printf '  "ports": [\n'
        first=true
        for line in "${all_port_lines[@]}"; do
            IFS='|' read -r port proto state service ver source <<< "$line"
            $first && first=false || printf ',\n'
            printf '    {\n'
            printf '      "port": %s,\n' "${port}"
            printf '      "proto": "%s",\n' "$(json_escape "${proto}")"
            printf '      "state": "%s",\n' "$(json_escape "${state}")"
            printf '      "service": "%s",\n' "$(json_escape "${service}")"
            printf '      "version": "%s",\n' "$(json_escape "${ver}")"
            printf '      "discovered_in": "%s"\n' "$(json_escape "${source}")"
            printf '    }'
        done
        printf '\n  ],\n'

        # Vulnerabilities array
        printf '  "vulnerabilities": [\n'
        first=true
        for v in "${vuln_lines[@]}"; do
            IFS='|' read -r vid conf <<< "$v"
            $first && first=false || printf ',\n'
            printf '    {\n'
            printf '      "id": "%s",\n' "$(json_escape "${vid}")"
            printf '      "confidence": "%s"\n' "$(json_escape "${conf}")"
            printf '    }'
        done
        printf '\n  ],\n'

        # Recon tools array
        printf '  "recon_tools": [\n'
        first=true
        for key in "${!RECON_TOOL_STATUS[@]}"; do
            local tool_name="${key%%_*}"
            local status="${RECON_TOOL_STATUS[$key]}"
            local dur="${RECON_TOOL_DURATION[$key]:-0}"
            $first && first=false || printf ',\n'
            printf '    {\n'
            printf '      "tool": "%s",\n' "$(json_escape "${tool_name}")"
            printf '      "status": "%s",\n' "$(json_escape "${status}")"
            printf '      "duration_seconds": %d\n' "${dur}"
            printf '    }'
        done
        printf '\n  ],\n'

        # Phases array
        printf '  "phases": [\n'
        first=true
        for phase in "${SCAN_PHASES[@]}"; do
            local pstatus="${PHASE_STATUS[$phase]:-pending}"
            local pdur=0
            if [ -n "${PHASE_START[$phase]:-}" ] && [ -n "${PHASE_END[$phase]:-}" ]; then
                pdur=$((PHASE_END[$phase] - PHASE_START[$phase]))
            fi
            $first && first=false || printf ',\n'
            printf '    {\n'
            printf '      "name": "%s",\n' "$(json_escape "${phase}")"
            printf '      "status": "%s",\n' "$(json_escape "${pstatus}")"
            printf '      "duration_seconds": %d\n' "${pdur}"
            printf '    }'
        done
        printf '\n  ]\n'

        printf '}\n'
    } > "${json_file}"

    printf "${GREEN}JSON report saved to: ${OUTPUTDIR}/${json_file}${NC}\n"
}

# Parse a target's nmap/*.nmap results (run from inside the target's output
# directory) into two arrays in the CALLER's scope (dynamic scoping; declare
# them first): all_port_lines ("port|proto|state|service|version|source")
# and vuln_lines ("CVE-ID|confidence"). Shared by the report, exports,
# explore and diff so every view agrees.
collect_scan_data() {
    local host="$1"
    local -A port_source=()
    all_port_lines=()
    local port proto state service ver cve conf

    if [ -f "nmap/Port_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            port_source["${port}/${proto}"]="port_scan"
            all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|port_scan")
        done < <(parse_nmap_ports "nmap/Port_${host}.nmap")
    fi

    if [ -f "nmap/Script_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            if [ -z "${port_source[${port}/${proto}]:-}" ]; then
                port_source["${port}/${proto}"]="script_scan"
                all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|script_scan")
            else
                # Update version info from script scan (more detailed)
                local idx
                for idx in "${!all_port_lines[@]}"; do
                    if [[ "${all_port_lines[$idx]}" == "${port}|${proto}|"* ]]; then
                        all_port_lines[$idx]="${port}|${proto}|${state}|${service}|${ver}|${port_source[${port}/${proto}]}"
                        break
                    fi
                done
            fi
        done < <(parse_nmap_ports "nmap/Script_${host}.nmap")
    fi

    if [ -f "nmap/Full_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            if [ -z "${port_source[${port}/${proto}]:-}" ]; then
                port_source["${port}/${proto}"]="full_scan"
                all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|full_scan")
            fi
        done < <(parse_nmap_ports "nmap/Full_${host}.nmap")
    fi

    if [ -f "nmap/Full_Extra_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            if [ -z "${port_source[${port}/${proto}]:-}" ]; then
                port_source["${port}/${proto}"]="full_scan"
                all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|full_scan")
            else
                local idx
                for idx in "${!all_port_lines[@]}"; do
                    if [[ "${all_port_lines[$idx]}" == "${port}|${proto}|"* ]]; then
                        all_port_lines[$idx]="${port}|${proto}|${state}|${service}|${ver}|${port_source[${port}/${proto}]}"
                        break
                    fi
                done
            fi
        done < <(parse_nmap_ports "nmap/Full_Extra_${host}.nmap")
    fi

    if [ -f "nmap/UDP_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            if [ -z "${port_source[${port}/${proto}]:-}" ]; then
                port_source["${port}/${proto}"]="udp_scan"
                all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|udp_scan")
            fi
        done < <(parse_nmap_ports "nmap/UDP_${host}.nmap")
    fi

    # UDP script/version scan refines UDP service info.
    if [ -f "nmap/UDP_Extra_${host}.nmap" ]; then
        while IFS='|' read -r port proto state service ver; do
            [ -z "$port" ] && continue
            if [ -z "${port_source[${port}/${proto}]:-}" ]; then
                port_source["${port}/${proto}"]="udp_scan"
                all_port_lines+=("${port}|${proto}|${state}|${service}|${ver}|udp_scan")
            else
                local idx
                for idx in "${!all_port_lines[@]}"; do
                    if [[ "${all_port_lines[$idx]}" == "${port}|${proto}|"* ]]; then
                        all_port_lines[$idx]="${port}|${proto}|${state}|${service}|${ver}|${port_source[${port}/${proto}]}"
                        break
                    fi
                done
            fi
        done < <(parse_nmap_ports "nmap/UDP_Extra_${host}.nmap")
    fi

    # Collect vulnerabilities
    vuln_lines=()
    if [ -f "nmap/CVEs_${host}.nmap" ]; then
        while IFS='|' read -r cve conf; do
            [ -z "$cve" ] && continue
            vuln_lines+=("${cve}|confirmed")
        done < <(parse_vulns_from_file "nmap/CVEs_${host}.nmap" "confirmed")
    fi
    if [ -f "nmap/Vulns_${host}.nmap" ]; then
        while IFS='|' read -r cve conf; do
            [ -z "$cve" ] && continue
            local already=false
            local v
            for v in "${vuln_lines[@]}"; do
                [[ "$v" == "${cve}|"* ]] && already=true && break
            done
            $already || vuln_lines+=("${cve}|probable")
        done < <(parse_vulns_from_file "nmap/Vulns_${host}.nmap" "probable")
    fi

}

generate_report() {
    local host="$1"
    local report_file="summary.md"

    $GENERATE_REPORT || return 0

    printf "${GREEN}Generating summary report...${NC}\n"

    local scan_date
    scan_date="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"

    local elapsedEnd
    elapsedEnd="$(date +%s)"
    local duration=$((elapsedEnd - elapsedStart))

    declare -a all_port_lines=()
    declare -a vuln_lines=()
    collect_scan_data "${host}"

    # --- Write the report ---
    {
        # YAML front matter
        echo "---"
        echo "target: $(yaml_escape "${host}")"
        echo "hostname: $(yaml_escape "${urlIP:-${host}}")"
        echo "os_detected: $(yaml_escape "${osType:-unknown}")"
        echo "scan_date: \"${scan_date}\""
        echo "scan_duration_seconds: ${duration}"
        echo "scan_type: $(yaml_escape "${TYPE}")"
        echo "scan_profile: $(yaml_escape "${SCAN_PROFILE:-normal}")"
        echo "ports:"
        for line in "${all_port_lines[@]}"; do
            IFS='|' read -r port proto state service ver source <<< "$line"
            echo "  - port: ${port}"
            echo "    proto: $(yaml_escape "${proto}")"
            echo "    service: $(yaml_escape "${service}")"
            echo "    version: $(yaml_escape "${ver}")"
            echo "    discovered_in: ${source}"
        done
        if [ ${#vuln_lines[@]} -gt 0 ]; then
            echo "vulnerabilities:"
            for v in "${vuln_lines[@]}"; do
                IFS='|' read -r vid conf <<< "$v"
                echo "  - id: ${vid}"
                echo "    confidence: ${conf}"
            done
        else
            echo "vulnerabilities: []"
        fi
        echo "recon_tools:"
        for key in "${!RECON_TOOL_STATUS[@]}"; do
            local tool_name="${key%%_*}"
            local status="${RECON_TOOL_STATUS[$key]}"
            local dur="${RECON_TOOL_DURATION[$key]:-0}"
            echo "  - tool: ${tool_name}"
            echo "    status: ${status}"
            echo "    duration_seconds: ${dur}"
        done
        echo "phases:"
        for phase in "${SCAN_PHASES[@]}"; do
            local pstatus="${PHASE_STATUS[$phase]:-pending}"
            local pdur=0
            if [ -n "${PHASE_START[$phase]:-}" ] && [ -n "${PHASE_END[$phase]:-}" ]; then
                pdur=$((PHASE_END[$phase] - PHASE_START[$phase]))
            fi
            echo "  - name: ${phase}"
            echo "    status: ${pstatus}"
            echo "    duration_seconds: ${pdur}"
        done
        echo "---"
        echo ""

        # Markdown body
        echo "# Reconnaissance Report: ${host}"
        echo ""
        echo "**Date:** $(date '+%Y-%m-%d %H:%M')  "
        echo "**Duration:** $(format_duration ${duration})  "
        echo "**OS Detection:** ${osType:-unknown}  "
        echo "**Scan Type:** ${TYPE}  "
        echo "**Scan Profile:** ${SCAN_PROFILE:-normal}  "
        echo ""

        # Open Ports table
        if [ ${#all_port_lines[@]} -gt 0 ]; then
            echo "## Open Ports"
            echo ""
            echo "| Port | Proto | State | Service | Version | Discovered In |"
            echo "|------|-------|-------|---------|---------|---------------|"
            for line in "${all_port_lines[@]}"; do
                IFS='|' read -r port proto state service ver source <<< "$line"
                echo "| ${port} | ${proto} | ${state} | ${service} | ${ver} | ${source} |"
            done
            echo ""
        fi

        # Port Discovery Timeline
        echo "## Port Discovery Timeline"
        echo ""
        local scan_names=("port_scan:Port Scan" "script_scan:Script Scan" "full_scan:Full Scan" "udp_scan:UDP Scan")
        for sn in "${scan_names[@]}"; do
            local skey="${sn%%:*}"
            local slabel="${sn#*:}"
            local found_ports=""
            for line in "${all_port_lines[@]}"; do
                IFS='|' read -r port proto state service ver source <<< "$line"
                if [ "$source" = "$skey" ]; then
                    [ -n "$found_ports" ] && found_ports+=", "
                    found_ports+="${port}/${proto}"
                fi
            done
            [ -n "$found_ports" ] && echo "- **${slabel}**: ${found_ports}"
        done
        echo ""

        # Vulnerability Findings
        if [ ${#vuln_lines[@]} -gt 0 ]; then
            echo "## Vulnerability Findings"
            echo ""
            echo "| ID | Confidence |"
            echo "|----|------------|"
            for v in "${vuln_lines[@]}"; do
                IFS='|' read -r vid conf <<< "$v"
                echo "| ${vid} | ${conf} |"
            done
            echo ""
        fi

        # Recon Findings
        if [ -d "recon" ] && [ -n "$(ls -A recon/ 2>/dev/null)" ]; then
            echo "## Recon Findings"
            echo ""
            local rfile
            while IFS= read -r rfile; do
                [ -f "$rfile" ] || continue
                local rname
                # Path relative to recon/ so per-port files stay unique
                # (e.g. 80/nikto_host.txt vs 443/nikto_host.txt).
                rname="${rfile#recon/}"
                local rstatus="completed"
                local rdur=""
                for key in "${!RECON_TOOL_STATUS[@]}"; do
                    if [[ "$key" == *"${rname}"* ]] || [[ "$key" == *"${rname%.txt}"* ]]; then
                        rstatus="${RECON_TOOL_STATUS[$key]}"
                        rdur="${RECON_TOOL_DURATION[$key]:-}"
                        break
                    fi
                done
                local dur_str=""
                [ -n "$rdur" ] && dur_str=" ($(format_duration "$rdur"))"
                local status_str=""
                [ "$rstatus" = "timeout" ] && status_str=" **TIMEOUT**"

                echo "### ${rname}${dur_str}${status_str}"
                echo ""
                echo '```'
                head -n "${REPORT_MAX_TOOL_OUTPUT}" "$rfile" 2>/dev/null
                local total_lines
                total_lines="$(wc -l < "$rfile" 2>/dev/null)"
                if [ "${total_lines:-0}" -gt "${REPORT_MAX_TOOL_OUTPUT}" ]; then
                    echo "... (truncated, ${total_lines} total lines)"
                fi
                echo '```'
                echo ""
            done < <(find recon -type f 2>/dev/null | LC_ALL=C sort)
        fi

        # Scan Phase Summary
        echo "## Scan Phase Summary"
        echo ""
        echo "| Phase | Status | Duration |"
        echo "|-------|--------|----------|"
        for phase in "${SCAN_PHASES[@]}"; do
            local pstatus="${PHASE_STATUS[$phase]:-pending}"
            local pdur="--"
            if [ -n "${PHASE_START[$phase]:-}" ] && [ -n "${PHASE_END[$phase]:-}" ]; then
                pdur="$(format_duration $((PHASE_END[$phase] - PHASE_START[$phase])))"
            fi
            echo "| ${phase} | ${pstatus} | ${pdur} |"
        done
        echo ""

    } > "${report_file}"

    printf "${GREEN}Report saved to: ${OUTPUTDIR}/${report_file}${NC}\n"

    if [ "${REPORT_FORMAT}" = "json" ] || [ "${REPORT_FORMAT}" = "both" ]; then
        generate_json_report "${host}" "${scan_date}" "${duration}"
    fi

    if [ "${REPORT_HTML}" = "true" ]; then
        generate_html_report "${host}"
    fi
}

# Render an HTML report from nmap XML via xsltproc (nmap ships nmap.xsl).
# Uses all of this target's scans merged into one XML. The stylesheet is
# passed explicitly when nmap's data dir is found, because the path embedded
# in the XML points at the scanning machine's install (e.g. Homebrew vs
# /usr/share) and may not exist where the report is rendered.
generate_html_report() {
    local host="$1"
    local html_file="summary.html"

    if ! command -v xsltproc >/dev/null 2>&1; then
        log_warning "REPORT_HTML=true but xsltproc not found; skipping HTML report ($(install_hint xsltproc))"
        return 0
    fi

    local merged
    merged="$(mktemp "${TMPDIR:-/tmp}/nmaprf_merged.XXXXXX")"
    if ! merge_nmap_xml "${host}" > "${merged}" || [ ! -s "${merged}" ]; then
        rm -f "${merged}"
        log_warning "No complete nmap XML files found (set NMAP_XML=true); skipping HTML report"
        return 0
    fi

    local xsl rc
    if xsl="$(find_nmap_xsl)"; then
        xsltproc -o "${html_file}" "${xsl}" "${merged}" 2>/dev/null
        rc=$?
    else
        xsltproc -o "${html_file}" "${merged}" 2>/dev/null
        rc=$?
    fi
    rm -f "${merged}"

    if [ ${rc} -eq 0 ] && [ -s "${html_file}" ]; then
        printf "${GREEN}HTML report saved to: ${OUTPUTDIR}/${html_file}${NC}\n"
    else
        rm -f "${html_file}"
        log_warning "xsltproc failed to render HTML report (nmap.xsl not found?)"
    fi
}
