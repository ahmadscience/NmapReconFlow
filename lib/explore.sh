#!/usr/bin/env bash
# NmapReconFlow - Explore and diff existing results (no scanning, no nmap)
#
#   --explore <dir> [view]   browse a target or campaign result directory
#   --diff <old> <new>       compare two runs (new/closed/changed services)

# Print a row table from "host|port|proto|state|service|version|source"
# lines on stdin.
_print_service_table() {
    awk -F'|' '
        BEGIN { printf "%-28s %-7s %-5s %-14s %-20s %s\n", "HOST", "PORT", "PROTO", "STATE", "SERVICE", "VERSION"
                printf "%-28s %-7s %-5s %-14s %-20s %s\n", "----", "----", "-----", "-----", "-------", "-------" }
        $2 != "" { printf "%-28s %-7s %-5s %-14s %-20s %s\n", $1, $2, $3, $4, $5, $6; n++ }
        END { if (n == 0) print "(no services)" }'
}

# Resolve a file argument for `show`: as given, relative to the results dir,
# or relative to any target directory inside it.
_explore_resolve_file() {
    local root="$1" name="$2" d
    [ -f "${name}" ] && { printf '%s' "${name}"; return 0; }
    [ -f "${root}/${name}" ] && { printf '%s' "${root}/${name}"; return 0; }
    while IFS= read -r d; do
        [ -f "${d}/${name}" ] && { printf '%s' "${d}/${name}"; return 0; }
        [ -f "${d}/recon/${name}" ] && { printf '%s' "${d}/recon/${name}"; return 0; }
        [ -f "${d}/nmap/${name}" ] && { printf '%s' "${d}/nmap/${name}"; return 0; }
    done < <(find_target_dirs "${root}")
    return 1
}

_explore_page() {
    if [ -t 1 ] && command -v less >/dev/null 2>&1; then
        less -R "$1"
    else
        cat "$1"
    fi
}

# Run one explore view. Returns 1 for an unknown view.
explore_view() {
    local root="$1" view="${2:-summary}"
    shift 2 2>/dev/null || shift $#
    local rows d host
    case "${view}" in
        summary)
            local nt=0 total_tcp=0 total_udp=0 total_web=0 total_cve=0
            printf "${BOLD}Results: %s${NC}\n\n" "${root}"
            printf "%-28s %-6s %-6s %-6s %-6s %-8s %s\n" "HOST" "TCP" "UDP" "WEB" "CVEs" "RECON" "OS"
            printf "%-28s %-6s %-6s %-6s %-6s %-8s %s\n" "----" "---" "---" "---" "----" "-----" "--"
            while IFS= read -r d; do
                host="$(detect_result_host "$d")" || continue
                rows="$(result_rows "$d")"
                local tcp udp web cve recon os
                tcp="$(printf '%s\n' "${rows}" | awk -F'|' '$3=="tcp"' | grep -c . )"
                udp="$(printf '%s\n' "${rows}" | awk -F'|' '$3=="udp"' | grep -c . )"
                web=0
                local h port proto state service ver src
                while IFS='|' read -r h port proto state service ver src; do
                    [ "${proto}" = "tcp" ] && web_scheme "${service}" "${port}" >/dev/null && web=$((web + 1))
                done <<< "${rows}"
                cve="$(result_vuln_rows "$d" | grep -c .)"
                recon="$(find "${d}/recon" -type f 2>/dev/null | grep -c .)"
                os="$(sed -n 's/^os_detected: "\(.*\)"$/\1/p' "${d}/summary.md" 2>/dev/null | head -n 1)"
                printf "%-28s %-6s %-6s %-6s %-6s %-8s %s\n" "${host}" "${tcp}" "${udp}" "${web}" "${cve}" "${recon}" "${os:-?}"
                nt=$((nt + 1)); total_tcp=$((total_tcp + tcp)); total_udp=$((total_udp + udp))
                total_web=$((total_web + web)); total_cve=$((total_cve + cve))
            done < <(find_target_dirs "${root}")
            printf "\n%d target(s): %d TCP, %d UDP services, %d web, %d CVE findings\n" \
                "${nt}" "${total_tcp}" "${total_udp}" "${total_web}" "${total_cve}"
            ;;
        hosts)
            result_rows "${root}" | awk -F'|' '
                { n[$1]++; if ($3=="tcp") t[$1]++; else u[$1]++ ; if (!($1 in seen)) { seen[$1]=1; order[++k]=$1 } }
                END { printf "%-28s %-6s %-6s\n", "HOST", "TCP", "UDP"
                      for (i=1;i<=k;i++) printf "%-28s %-6d %-6d\n", order[i], t[order[i]], u[order[i]] }'
            # Targets scanned but with nothing open
            while IFS= read -r d; do
                host="$(detect_result_host "$d")" || continue
                result_rows "$d" | grep -q . || printf "%-28s %-6s %-6s\n" "${host}" "0" "0"
            done < <(find_target_dirs "${root}")
            ;;
        ports|services-list)
            local filter="${1:-}"
            if [ -n "${filter}" ]; then
                result_rows "${root}" | grep -i -E -- "${filter}" | _print_service_table
            else
                result_rows "${root}" | _print_service_table
            fi
            ;;
        services)
            result_rows "${root}" | awk -F'|' '
                $5 != "" { key=$5"/"$3; c[key]++; if (!((key, $1) in hh)) { hh[key,$1]=1; h[key]++ } }
                END { printf "%-26s %-8s %s\n", "SERVICE", "COUNT", "HOSTS"
                      for (k in c) printf "%-26s %-8d %d\n", k, c[k], h[k] }' \
                | { IFS= read -r hdr; echo "${hdr}"; sort -k2,2nr -k1,1; }
            ;;
        urls)
            local h port proto state service ver src scheme
            result_rows "${root}" | while IFS='|' read -r h port proto state service ver src; do
                [ "${proto}" = "tcp" ] || continue
                scheme="$(web_scheme "${service}" "${port}")" || continue
                printf '%s://%s\n' "${scheme}" "$(host_port "$h" "$port")"
            done | awk '!seen[$0]++'
            ;;
        vulns|cves)
            result_vuln_rows "${root}" | awk -F'|' '
                BEGIN { printf "%-28s %-18s %s\n", "HOST", "CVE", "CONFIDENCE" }
                { printf "%-28s %-18s %s\n", $1, $2, $3; n++ }
                END { if (n == 0) print "(no CVE findings)" }'
            ;;
        recon)
            while IFS= read -r d; do
                host="$(detect_result_host "$d")" || continue
                printf "${BOLD}%s${NC}\n" "${host}"
                if [ -d "${d}/recon" ]; then
                    find "${d}/recon" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do
                        printf "  %-60s %6s lines\n" "${f#"${d}"/}" "$(($(wc -l < "$f")))"
                    done
                else
                    echo "  (no recon output)"
                fi
            done < <(find_target_dirs "${root}")
            ;;
        commands)
            while IFS= read -r d; do
                host="$(detect_result_host "$d")" || continue
                printf "${BOLD}%s - recommended recon commands${NC}\n" "${host}"
                if [ -f "${d}/nmap/Recon_${host}.nmap" ]; then
                    grep -F "${host}" "${d}/nmap/Recon_${host}.nmap" | sed 's/^/  /'
                else
                    echo "  (none - run with -t Recon or -t All)"
                fi
                if [ -f "${d}/recon/_manual_commands.txt" ]; then
                    printf "${BOLD}%s - manual follow-ups${NC}\n" "${host}"
                    sed 's/^/  /' "${d}/recon/_manual_commands.txt"
                fi
            done < <(find_target_dirs "${root}")
            ;;
        show)
            local f
            if [ -z "${1:-}" ]; then
                echo "Usage: show <file>   (path, or name of a file under recon/ or nmap/)"
                return 0
            fi
            if f="$(_explore_resolve_file "${root}" "$1")"; then
                _explore_page "$f"
            else
                log_error "File not found: $1"
            fi
            ;;
        search|grep)
            if [ -z "${1:-}" ]; then
                echo "Usage: search <regex>"
                return 0
            fi
            while IFS= read -r d; do
                grep -r -n -i -E -- "$1" "${d}/nmap" "${d}/recon" 2>/dev/null \
                    | grep -v -E '\.(xml|tmp):' | sed "s|^${d}/||; s|^|${d##*/}: |"
            done < <(find_target_dirs "${root}")
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

_explore_menu() {
    local root="$1" choice arg
    while true; do
        printf "\n${BOLD}${GREEN}NmapReconFlow explorer${NC} - %s\n" "${root}"
        printf "  1) summary     2) hosts      3) ports       4) services\n"
        printf "  5) urls        6) vulns      7) recon files 8) recommended commands\n"
        printf "  9) show file  10) search    11) filter ports  e) rebuild exports   q) quit\n"
        printf "> "
        IFS= read -r choice || return 0
        case "${choice}" in
            1|summary)  explore_view "${root}" summary ;;
            2|hosts)    explore_view "${root}" hosts ;;
            3|ports)    explore_view "${root}" ports ;;
            4|services) explore_view "${root}" services ;;
            5|urls)     explore_view "${root}" urls ;;
            6|vulns)    explore_view "${root}" vulns ;;
            7|recon)    explore_view "${root}" recon ;;
            8|commands) explore_view "${root}" commands ;;
            9|show)
                printf "file> "; IFS= read -r arg || return 0
                explore_view "${root}" show "${arg}" ;;
            10|search)
                printf "regex> "; IFS= read -r arg || return 0
                explore_view "${root}" search "${arg}" ;;
            11|filter)
                printf "filter (e.g. http, 445, ssh|ftp)> "; IFS= read -r arg || return 0
                explore_view "${root}" ports "${arg}" ;;
            e|export)   export_results_dir "${root}" ;;
            q|Q|quit|exit) return 0 ;;
            "") ;;
            *) echo "Unknown choice: ${choice}" ;;
        esac
    done
}

# --explore <dir> [view [args]]
explore_results() {
    local root="${1%/}"
    shift
    if [ ! -d "${root}" ]; then
        log_error "Not a directory: ${root}"
        return 1
    fi
    if ! find_target_dirs "${root}" | grep -q .; then
        log_error "No NmapReconFlow results (nmap/ folder) found in ${root}"
        return 1
    fi
    if [ $# -eq 0 ]; then
        if [ -t 0 ] && [ -t 1 ]; then
            explore_view "${root}" summary
            _explore_menu "${root}"
            return 0
        fi
        explore_view "${root}" summary
        return 0
    fi
    if ! explore_view "${root}" "$@"; then
        log_error "Unknown view: $1 (summary, hosts, ports [FILTER], services, urls, vulns, recon, commands, show FILE, search REGEX)"
        return 1
    fi
}

# --diff <old> <new>: like diff(1), exit 0 = no changes, 1 = changes, 2 = error.
diff_results() {
    local old="${1%/}" new="${2%/}"
    local d
    for d in "${old}" "${new}"; do
        if [ ! -d "$d" ] || ! find_target_dirs "$d" | grep -q .; then
            log_error "No NmapReconFlow results found in: $d"
            return 2
        fi
    done

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/nmaprf_diff.XXXXXX")" || return 2
    result_rows "${old}" > "${tmp}/old"
    result_rows "${new}" > "${tmp}/new"
    result_vuln_rows "${old}" | cut -d'|' -f1,2 | sort -u > "${tmp}/oldv"
    result_vuln_rows "${new}" | cut -d'|' -f1,2 | sort -u > "${tmp}/newv"

    printf "${BOLD}Diff: %s -> %s${NC}\n\n" "${old}" "${new}"
    awk -F'|' '
        FNR == NR { k = $1 "|" $2 "|" $3; o[k] = $5 "|" $6; next }
        { k = $1 "|" $2 "|" $3; n[k] = $5 "|" $6 }
        END {
            for (k in n) if (!(k in o)) { split(k, a, "|"); split(n[k], s, "|")
                printf "+ NEW     %s %s/%s  %s %s\n", a[1], a[2], a[3], s[1], s[2]; c++ }
            for (k in o) if (!(k in n)) { split(k, a, "|"); split(o[k], s, "|")
                printf "- CLOSED  %s %s/%s  %s %s\n", a[1], a[2], a[3], s[1], s[2]; c++ }
            for (k in n) if ((k in o) && o[k] != n[k]) { split(k, a, "|"); split(o[k], s, "|"); split(n[k], t, "|")
                printf "~ CHANGED %s %s/%s  %s %s  ->  %s %s\n", a[1], a[2], a[3], s[1], s[2], t[1], t[2]; c++ }
        }' "${tmp}/old" "${tmp}/new" | LC_ALL=C sort -k3,3 -k4,4n > "${tmp}/svc"

    comm -13 "${tmp}/oldv" "${tmp}/newv" | awk -F'|' '{printf "+ NEW CVE %s %s\n", $1, $2}' > "${tmp}/vulns"
    comm -23 "${tmp}/oldv" "${tmp}/newv" | awk -F'|' '{printf "- GONE CVE %s %s\n", $1, $2}' >> "${tmp}/vulns"

    local rc=0
    if [ -s "${tmp}/svc" ]; then
        printf "${BOLD}Services${NC}\n"
        cat "${tmp}/svc"
        echo
        rc=1
    fi
    if [ -s "${tmp}/vulns" ]; then
        printf "${BOLD}Vulnerabilities${NC}\n"
        cat "${tmp}/vulns"
        echo
        rc=1
    fi
    if [ ${rc} -eq 0 ]; then
        echo "No changes in open services or CVE findings."
    else
        printf "Summary: %d new, %d closed, %d changed service(s); %d CVE change(s)\n" \
            "$(grep -c '^+ NEW ' "${tmp}/svc")" "$(grep -c '^- CLOSED' "${tmp}/svc")" \
            "$(grep -c '^~ CHANGED' "${tmp}/svc")" "$(grep -c . "${tmp}/vulns")"
    fi
    rm -rf "${tmp}"
    return ${rc}
}
