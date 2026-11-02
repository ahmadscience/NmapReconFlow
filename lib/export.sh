#!/usr/bin/env bash
# NmapReconFlow - Exports: turn scan results into files other tools consume
#
# exports/ (per target, and aggregated per campaign):
#   hosts.txt            targets with open ports      -> nmap -iL, masscan -iL
#   tcp_ports.txt        22,80,443                    -> nmap -p "$(cat ...)"
#   udp_ports.txt        53,161                       -> nmap -sU -p ...
#   host_port.txt        10.0.0.1:443                 -> httpx -l, nuclei -l, testssl --file
#   urls.txt             https://10.0.0.1:443         -> nuclei -l, ffuf, gowitness, eyewitness
#   services.csv         host,port,proto,...          -> spreadsheets, pandas, SIEM
#   services.jsonl       one JSON object per service  -> jq, Elastic, Splunk
#   cves.csv             host,cve,confidence
#   by_service/<svc>.txt host:port per service        -> hydra -M, brutespray, nxc
#   nmap_merged.xml      all scans in one nmap XML    -> Metasploit db_import, xsltproc,
#                                                        nmap-parse-output, Faraday, Dradis
#   nmap_merged.gnmap    grepable nmap output         -> brutespray, grep/awk

# Order in which per-scan files are merged (richest service info last wins
# in tools that de-duplicate by host/port).
NMAPRF_SCAN_ORDER=(Port Script Full Full_Extra UDP UDP_Extra CVEs Vulns)

# CSV field quoting (RFC 4180): wrap in quotes, double embedded quotes.
csv_field() {
    local v="${1//\"/\"\"}"
    printf '"%s"' "${v}"
}

# host:port with IPv6 brackets.
host_port() {
    if is_ipv6 "$1"; then printf '[%s]:%s' "$1" "$2"; else printf '%s:%s' "$1" "$2"; fi
}

# URL scheme for an nmap service name, or empty if not a web service.
web_scheme() {
    local service="$1" port="$2"
    case "${service}" in
        ncacn_http*|*msrpc*|http-rpc-epmap*) return 1 ;;
        ssl/http*|https*|*https) printf 'https' ;;
        http*|*/http|*http-proxy*|*http-alt*)
            case "${port}" in
                443|4443|8443|9443) printf 'https' ;;
                *) printf 'http' ;;
            esac ;;
        *) return 1 ;;
    esac
}

# Merge complete nmap XML files (those ending in </nmaprun>) into one valid
# nmaprun document on stdout: prologue of the first file, every <host> block
# from all files, runstats of the last. Returns 1 if there is nothing to merge.
merge_xml_files() {
    local -a files=()
    local f
    for f in "$@"; do
        [ -f "$f" ] && grep -q '</nmaprun>' "$f" 2>/dev/null && files+=("$f")
    done
    [ ${#files[@]} -eq 0 ] && return 1

    # Prologue: everything before the first <host>/<hosthint>/<runstats>.
    awk '/^<(host|hosthint|runstats)[ >]/ {exit} {print}' "${files[0]}"
    for f in "${files[@]}"; do
        awk '/^<host[ >]/ {inhost=1} inhost {print} /^<\/host>/ {inhost=0}' "$f"
    done
    awk '/^<runstats>/ {p=1} p {print}' "${files[${#files[@]}-1]}"
}

# Merged XML of one target's scans (run from inside the target directory).
merge_nmap_xml() {
    local host="$1" scan
    local -a files=()
    for scan in "${NMAPRF_SCAN_ORDER[@]}"; do
        files+=("nmap/${scan}_${host}.xml")
    done
    merge_xml_files "${files[@]}"
}

# Merged grepable output of one target's scans (run from the target dir).
merge_nmap_gnmap() {
    local host="$1" scan found=false
    for scan in "${NMAPRF_SCAN_ORDER[@]}"; do
        if [ -f "nmap/${scan}_${host}.gnmap" ]; then
            if ! ${found}; then
                echo "# NmapReconFlow merged grepable output for ${host}"
                found=true
            fi
            grep -v '^#' "nmap/${scan}_${host}.gnmap"
        fi
    done
    ${found}
}

# Infer the target name of a result directory from its nmap/ file names.
detect_result_host() {
    local dir="$1" f base scan
    for scan in "${NMAPRF_SCAN_ORDER[@]}" Network Recon; do
        for f in "${dir}/nmap/${scan}_"*.nmap; do
            [ -f "$f" ] || continue
            base="$(basename "$f" .nmap)"
            printf '%s' "${base#"${scan}"_}"
            return 0
        done
    done
    return 1
}

# Print every target result directory under $1: $1 itself if it holds nmap/,
# otherwise each immediate subdirectory that does (campaign layout).
find_target_dirs() {
    local dir="${1%/}" d
    if [ -d "${dir}/nmap" ]; then
        printf '%s\n' "${dir}"
        return 0
    fi
    for d in "${dir}"/*/; do
        d="${d%/}"
        [ -d "${d}/nmap" ] && printf '%s\n' "${d}"
    done
    return 0
}

# Rows "host|port|proto|state|service|version|source" for every service in a
# result or campaign directory. Uses the same parser as the report.
result_rows() {
    local root="$1" d host
    while IFS= read -r d; do
        host="$(detect_result_host "$d")" || continue
        (
            cd "$d" || exit 0
            declare -a all_port_lines=() vuln_lines=()
            collect_scan_data "${host}"
            local l
            for l in "${all_port_lines[@]}"; do
                printf '%s|%s\n' "${host}" "${l}"
            done
        )
    done < <(find_target_dirs "${root}")
}

# Rows "host|CVE|confidence" for a result or campaign directory.
result_vuln_rows() {
    local root="$1" d host
    while IFS= read -r d; do
        host="$(detect_result_host "$d")" || continue
        (
            cd "$d" || exit 0
            declare -a all_port_lines=() vuln_lines=()
            collect_scan_data "${host}"
            local v
            for v in "${vuln_lines[@]}"; do
                printf '%s|%s\n' "${host}" "${v}"
            done
        )
    done < <(find_target_dirs "${root}")
}

# Write the derived export files into $out from service rows ($2, a file of
# result_rows lines) and vuln rows ($3, a file of result_vuln_rows lines).
_write_exports() {
    local out="$1" rows="$2" vrows="$3"
    mkdir -p "${out}/by_service" || return 1
    rm -f "${out}"/by_service/*.txt 2>/dev/null

    local h port proto state service ver src scheme svcfile
    {
        echo "host,port,proto,state,service,version,discovered_in"
    } > "${out}/services.csv"
    : > "${out}/services.jsonl"
    : > "${out}/host_port.txt"
    : > "${out}/urls.txt"

    while IFS='|' read -r h port proto state service ver src; do
        [ -z "${port}" ] && continue
        printf '%s,%s,%s,%s,%s,%s,%s\n' \
            "$(csv_field "$h")" "${port}" "$(csv_field "$proto")" "$(csv_field "$state")" \
            "$(csv_field "$service")" "$(csv_field "$ver")" "$(csv_field "$src")" >> "${out}/services.csv"
        printf '{"host":"%s","port":%s,"proto":"%s","state":"%s","service":"%s","version":"%s","discovered_in":"%s"}\n' \
            "$(json_escape "$h")" "${port}" "$(json_escape "$proto")" "$(json_escape "$state")" \
            "$(json_escape "$service")" "$(json_escape "$ver")" "$(json_escape "$src")" >> "${out}/services.jsonl"
        if [ "${proto}" = "tcp" ]; then
            host_port "$h" "$port" >> "${out}/host_port.txt"; echo >> "${out}/host_port.txt"
            if scheme="$(web_scheme "${service}" "${port}")"; then
                printf '%s://%s\n' "${scheme}" "$(host_port "$h" "$port")" >> "${out}/urls.txt"
            fi
        fi
        svcfile="${service:-unknown}"
        svcfile="${svcfile//\//_}"
        svcfile="${svcfile//[^A-Za-z0-9._-]/_}"
        { host_port "$h" "$port"; echo; } >> "${out}/by_service/${svcfile}_${proto}.txt"
    done < "${rows}"

    awk -F'|' '$1!="" {print $1}' "${rows}" | awk '!seen[$0]++' > "${out}/hosts.txt"
    awk -F'|' '$3=="tcp" {print $2}' "${rows}" | sort -n -u | paste -sd, - > "${out}/tcp_ports.txt"
    awk -F'|' '$3=="udp" {print $2}' "${rows}" | sort -n -u | paste -sd, - > "${out}/udp_ports.txt"
    local f
    for f in host_port.txt urls.txt; do
        awk '!seen[$0]++' "${out}/${f}" > "${out}/${f}.tmp" && mv "${out}/${f}.tmp" "${out}/${f}"
    done
    for f in "${out}"/by_service/*.txt; do
        [ -f "$f" ] || continue
        awk '!seen[$0]++' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    done

    {
        echo "host,cve,confidence"
        while IFS='|' read -r h vid conf; do
            [ -z "${vid}" ] && continue
            printf '%s,%s,%s\n' "$(csv_field "$h")" "$(csv_field "$vid")" "$(csv_field "$conf")"
        done < "${vrows}"
    } > "${out}/cves.csv"

    _write_exports_readme "${out}"
}

_write_exports_readme() {
    cat > "$1/README.txt" <<'EOF'
NmapReconFlow exports - ready-to-use inputs for other tools
===========================================================
hosts.txt          Targets with open ports       nmap -iL hosts.txt ...
tcp_ports.txt      Open TCP ports, comma list    nmap -p "$(cat tcp_ports.txt)" -iL hosts.txt
udp_ports.txt      Open UDP ports, comma list    sudo nmap -sU -p "$(cat udp_ports.txt)" ...
host_port.txt      host:port (TCP)               httpx -l host_port.txt / nuclei -l host_port.txt
urls.txt           Web URLs                      nuclei -l urls.txt / gowitness scan file -f urls.txt
services.csv       All services (CSV)            open in a spreadsheet, pandas.read_csv(...)
services.jsonl     All services (JSON Lines)     jq -r 'select(.service=="ssh") | .host' services.jsonl
cves.csv           CVEs found by vulners/vuln    host,cve,confidence
by_service/        host:port per service         hydra -M <(cut -d: -f1 by_service/ssh_tcp.txt) ...
nmap_merged.xml    All scans as one nmap XML     msfconsole: db_import nmap_merged.xml
                                                 xsltproc nmap_merged.xml -o report.html
nmap_merged.gnmap  All scans, grepable format    brutespray -f nmap_merged.gnmap
Rebuild at any time with: nmapReconFlow.sh --export <results-dir>
EOF
}

# Build exports/ for the current target directory (called after a scan).
generate_exports() {
    local host="$1"
    local out="exports"
    mkdir -p "${out}" || return 1

    local rows vrows
    rows="$(mktemp "${TMPDIR:-/tmp}/nmaprf_rows.XXXXXX")"
    vrows="$(mktemp "${TMPDIR:-/tmp}/nmaprf_vrows.XXXXXX")"
    (
        declare -a all_port_lines=() vuln_lines=()
        collect_scan_data "${host}"
        local l
        for l in "${all_port_lines[@]}"; do printf '%s|%s\n' "${host}" "${l}"; done > "${rows}"
        for l in "${vuln_lines[@]}"; do printf '%s|%s\n' "${host}" "${l}"; done > "${vrows}"
    )
    _write_exports "${out}" "${rows}" "${vrows}"
    rm -f "${rows}" "${vrows}"

    if merge_nmap_xml "${host}" > "${out}/nmap_merged.xml.tmp"; then
        mv "${out}/nmap_merged.xml.tmp" "${out}/nmap_merged.xml"
    else
        rm -f "${out}/nmap_merged.xml.tmp" "${out}/nmap_merged.xml"
    fi
    if merge_nmap_gnmap "${host}" > "${out}/nmap_merged.gnmap.tmp"; then
        mv "${out}/nmap_merged.gnmap.tmp" "${out}/nmap_merged.gnmap"
    else
        rm -f "${out}/nmap_merged.gnmap.tmp" "${out}/nmap_merged.gnmap"
    fi

    printf "${GREEN}Exports saved to: ${OUTPUTDIR:-.}/${out}/ (CSV, JSONL, URLs, host:port, port lists, merged XML/gnmap)${NC}\n"
}

# Aggregate every target of a campaign directory into <campaign>/exports/.
export_campaign() {
    local cdir="${1%/}"
    local out="${cdir}/exports"
    mkdir -p "${out}" || return 1

    local rows vrows
    rows="$(mktemp "${TMPDIR:-/tmp}/nmaprf_rows.XXXXXX")"
    vrows="$(mktemp "${TMPDIR:-/tmp}/nmaprf_vrows.XXXXXX")"
    result_rows "${cdir}" > "${rows}"
    result_vuln_rows "${cdir}" > "${vrows}"
    _write_exports "${out}" "${rows}" "${vrows}"
    rm -f "${rows}" "${vrows}"

    # Merged XML/gnmap across all targets.
    local d host scan
    local -a xmls=()
    while IFS= read -r d; do
        host="$(detect_result_host "$d")" || continue
        for scan in "${NMAPRF_SCAN_ORDER[@]}"; do
            xmls+=("${d}/nmap/${scan}_${host}.xml")
        done
    done < <(find_target_dirs "${cdir}")
    if [ ${#xmls[@]} -gt 0 ] && merge_xml_files "${xmls[@]}" > "${out}/nmap_merged.xml.tmp"; then
        mv "${out}/nmap_merged.xml.tmp" "${out}/nmap_merged.xml"
    else
        rm -f "${out}/nmap_merged.xml.tmp" "${out}/nmap_merged.xml"
    fi
    {
        echo "# NmapReconFlow merged grepable output for campaign ${cdir##*/}"
        while IFS= read -r d; do
            host="$(detect_result_host "$d")" || continue
            for scan in "${NMAPRF_SCAN_ORDER[@]}"; do
                [ -f "${d}/nmap/${scan}_${host}.gnmap" ] && grep -v '^#' "${d}/nmap/${scan}_${host}.gnmap"
            done
        done < <(find_target_dirs "${cdir}")
    } > "${out}/nmap_merged.gnmap"

    printf "${GREEN}Campaign exports saved to: ${out}/${NC}\n"
}

# --export <dir>: (re)build exports for a target dir or a campaign dir.
export_results_dir() {
    local dir="${1%/}"
    if [ ! -d "${dir}" ]; then
        log_error "Not a directory: ${dir}"
        return 1
    fi
    local -a tdirs=()
    local d
    while IFS= read -r d; do tdirs+=("$d"); done < <(find_target_dirs "${dir}")
    if [ ${#tdirs[@]} -eq 0 ]; then
        log_error "No NmapReconFlow results (nmap/ folder) found in ${dir}"
        return 1
    fi

    local host
    for d in "${tdirs[@]}"; do
        host="$(detect_result_host "$d")" || continue
        ( cd "$d" && OUTPUTDIR="$d" generate_exports "${host}" )
    done
    if [ ! -d "${dir}/nmap" ]; then
        export_campaign "${dir}"
    fi
    return 0
}
