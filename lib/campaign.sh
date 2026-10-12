#!/usr/bin/env bash
# NmapReconFlow - Multi-target campaign orchestration

run_single_target() {
    local target="$1"
    local target_dir="$2"

    mkdir -p "${target_dir}" || return 1
    cd "${target_dir}" || return 1
    mkdir -p nmap/ || return 1

    HOST="$target"
    OUTPUTDIR="$target_dir"
    elapsedStart="$(date +%s)"
    commonPorts=""
    allPorts=""
    udpPorts=""
    extraPorts=""
    urlIP=""
    subnet=""
    osType=""
    nmapType=""
    pingable=true
    RECON_TOOL_STATUS=()
    RECON_TOOL_DURATION=()
    DNSSERVER=""
    DNSSTRING=""
    SCAN_PHASES=()
    PHASE_STATUS=()
    PHASE_START=()
    PHASE_END=()
    PHASE_NOTE=()
    detect_dns_server

    main
}

run_campaign() {
    local targets_file="$1"
    local parallelism="${CAMPAIGN_PARALLEL:-1}"
    local campaign_dir="campaign_$(date +%Y%m%d_%H%M%S)"

    if [ ! -f "$targets_file" ]; then
        log_error "Targets file not found: ${targets_file}"
        exit 1
    fi

    mkdir -p "${campaign_dir}"

    declare -a targets=()
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(echo "$line" | sed 's/#.*//' | awk '{$1=$1};1')"
        [ -z "$line" ] && continue
        if ! validate_host_safe "$line"; then
            log_warning "Skipping invalid target: ${line}"
            continue
        fi
        targets+=("$line")
    done < "$targets_file" || { log_error "Failed to read ${targets_file}"; exit 1; }

    local total=${#targets[@]}
    if [ "$total" -eq 0 ]; then
        log_error "No valid targets found in ${targets_file}"
        exit 1
    fi

    printf "${GREEN}${BOLD}=== NmapReconFlow Campaign ===${NC}\n"
    printf "${YELLOW}Targets: ${total} | Type: ${TYPE} | Parallelism: ${parallelism}${NC}\n"
    printf "${YELLOW}Output: ${campaign_dir}/${NC}\n\n"

    declare -A campaign_status=()
    declare -A campaign_start=()
    declare -A campaign_end=()
    local completed=0

    if [ "$parallelism" -le 1 ]; then
        local idx=0
        for target in "${targets[@]}"; do
            ((idx++))
            printf "\n${GREEN}=== Campaign: Target ${idx}/${total}: ${target} ===${NC}\n\n"

            campaign_status["$target"]="running"
            campaign_start["$target"]="$(date +%s)"

            (run_single_target "$target" "${campaign_dir}/${target}")
            local rc=$?

            campaign_end["$target"]="$(date +%s)"
            if [ $rc -eq 0 ]; then
                campaign_status["$target"]="done"
            else
                campaign_status["$target"]="error"
            fi
            ((completed++))
            printf "${GREEN}=== Campaign: ${completed}/${total} targets complete ===${NC}\n"
        done
    else
        declare -A pid_to_target=()

        # Reap finished jobs with a per-PID wait so each target gets its real
        # exit code. Portable to bash 4.3 (wait -n -p needs bash 5.1).
        _campaign_reap() {
            local pid rc ft
            for pid in "${!pid_to_target[@]}"; do
                kill -0 "$pid" 2>/dev/null && continue
                wait "$pid" 2>/dev/null
                rc=$?
                ft="${pid_to_target[$pid]}"
                campaign_end["$ft"]="$(date +%s)"
                if [ $rc -eq 0 ]; then
                    campaign_status["$ft"]="done"
                else
                    campaign_status["$ft"]="error"
                fi
                unset 'pid_to_target[$pid]'
                ((completed++))
                printf "${GREEN}=== Campaign: ${ft} finished (${completed}/${total}) ===${NC}\n"
            done
        }

        local idx=0
        for target in "${targets[@]}"; do
            ((idx++))

            while [ "${#pid_to_target[@]}" -ge "$parallelism" ]; do
                _campaign_reap
                [ "${#pid_to_target[@]}" -ge "$parallelism" ] && sleep 1
            done

            printf "${GREEN}=== Campaign: Starting ${target} (${idx}/${total}) ===${NC}\n"

            campaign_status["$target"]="running"
            campaign_start["$target"]="$(date +%s)"

            (run_single_target "$target" "${campaign_dir}/${target}" > "${campaign_dir}/${target}.log" 2>&1) &
            pid_to_target[$!]="$target"
        done

        while [ "${#pid_to_target[@]}" -gt 0 ]; do
            _campaign_reap
            [ "${#pid_to_target[@]}" -gt 0 ] && sleep 1
        done
    fi

    _campaign_generate_summary "${campaign_dir}" "${targets[*]}" campaign_status campaign_start campaign_end

    printf "\n${GREEN}${BOLD}=== Campaign Complete ===${NC}\n"
    printf "${YELLOW}Results in: ${campaign_dir}/${NC}\n"
    printf "${YELLOW}Summary: ${campaign_dir}/campaign_summary.md${NC}\n"

    send_notification "NmapReconFlow campaign complete: ${total} target(s), type ${TYPE}. Results in ${campaign_dir}/"
}

_campaign_generate_summary() {
    local campaign_dir="$1"
    local targets_str="$2"
    local -n _status=$3
    local -n _start=$4
    local -n _end=$5

    read -ra _targets <<< "$targets_str"
    local summary_file="${campaign_dir}/campaign_summary.md"

    {
        echo "---"
        echo "campaign_date: \"$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')\""
        echo "scan_type: \"${TYPE}\""
        echo "total_targets: ${#_targets[@]}"
        echo "targets:"
        for target in "${_targets[@]}"; do
            local status="${_status[$target]:-unknown}"
            local dur=0
            if [ -n "${_start[$target]:-}" ] && [ -n "${_end[$target]:-}" ]; then
                dur=$((_end[$target] - _start[$target]))
            fi
            echo "  - host: \"${target}\""
            echo "    status: ${status}"
            echo "    duration_seconds: ${dur}"

            local port_count=0
            local vuln_count=0
            local target_summary="${campaign_dir}/${target}/summary.md"
            if [ -f "$target_summary" ]; then
                port_count="$(grep -c '^ *- port:' "$target_summary" 2>/dev/null || echo 0)"
                vuln_count="$(grep -c '^ *- id:' "$target_summary" 2>/dev/null || echo 0)"
            fi
            echo "    open_ports: ${port_count}"
            echo "    vulnerabilities: ${vuln_count}"
        done
        echo "---"
        echo ""

        echo "# Campaign Summary"
        echo ""
        echo "**Date:** $(date '+%Y-%m-%d %H:%M')  "
        echo "**Scan Type:** ${TYPE}  "
        echo "**Targets:** ${#_targets[@]}  "
        echo ""

        echo "## Results"
        echo ""
        echo "| Target | Status | Duration | Open Ports | Vulns |"
        echo "|--------|--------|----------|------------|-------|"

        for target in "${_targets[@]}"; do
            local status="${_status[$target]:-unknown}"
            local dur="--"
            if [ -n "${_start[$target]:-}" ] && [ -n "${_end[$target]:-}" ]; then
                dur="$(format_duration $((_end[$target] - _start[$target])))"
            fi
            local port_count=0
            local vuln_count=0
            local target_summary="${campaign_dir}/${target}/summary.md"
            if [ -f "$target_summary" ]; then
                port_count="$(grep -c '^ *- port:' "$target_summary" 2>/dev/null || echo 0)"
                vuln_count="$(grep -c '^ *- id:' "$target_summary" 2>/dev/null || echo 0)"
            fi
            echo "| ${target} | ${status} | ${dur} | ${port_count} | ${vuln_count} |"
        done
        echo ""
    } > "$summary_file"
}
