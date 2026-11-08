#!/usr/bin/env bash
# Tests for lib/export.sh and lib/explore.sh (exports, explore, diff)

# --- csv_field / host_port / web_scheme ---
assert_eq '"plain"' "$(csv_field 'plain')" "csv_field: quoted"
assert_eq '"say ""hi"""' "$(csv_field 'say "hi"')" "csv_field: embedded quotes doubled"
assert_eq "10.0.0.1:80" "$(host_port 10.0.0.1 80)" "host_port: IPv4"
assert_eq "[::1]:443" "$(host_port ::1 443)" "host_port: IPv6 bracketed"
assert_eq "http"  "$(web_scheme http 80)"           "web_scheme: http"
assert_eq "https" "$(web_scheme ssl/http 8443)"     "web_scheme: ssl/http"
assert_eq "https" "$(web_scheme https 443)"         "web_scheme: https"
assert_eq "https" "$(web_scheme http 443)"          "web_scheme: http on 443"
assert_eq "http"  "$(web_scheme http-proxy 8080)"   "web_scheme: http-proxy"
assert_exit 1 web_scheme ssh 22
assert_exit 1 web_scheme ncacn_http 593
assert_exit 1 web_scheme http-rpc-epmap 593

# --- fixture results: <root>/<host>/nmap/*.nmap|*.xml ---
_mk_result() {
    local dir="$1" host="$2" scriptPorts="$3" cves="${4:-}"
    mkdir -p "${dir}/${host}/nmap"
    {
        echo "# Nmap 7.94SVN scan initiated as: nmap -sCV ${host}"
        echo "Nmap scan report for ${host}"
        echo "PORT     STATE SERVICE  VERSION"
        printf '%s\n' "${scriptPorts}"
        echo "# Nmap done at Mon Jun 15 10:00:15 2026 -- 1 IP address (1 host up)"
    } > "${dir}/${host}/nmap/Script_${host}.nmap"
    cp "${dir}/${host}/nmap/Script_${host}.nmap" "${dir}/${host}/nmap/Port_${host}.nmap"
    if [ -n "${cves}" ]; then
        {
            echo "PORT   STATE SERVICE VERSION"
            echo "22/tcp open  ssh     OpenSSH 7.2"
            echo "| vulners:"
            printf '|       %s  7.8  https://vulners.com/cve/%s\n' "${cves}" "${cves}"
        } > "${dir}/${host}/nmap/CVEs_${host}.nmap"
    fi
}

_mk_xml() {
    local file="$1" addr="$2" port="$3" svc="$4"
    cat > "${file}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -oX x" start="1" version="7.94" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="${port}"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="${addr}" addrtype="ipv4"/>
</hosthint>
<host starttime="1" endtime="2"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="${addr}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="${port}"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="${svc}" method="table" conf="3"/></port>
</ports>
</host>
<runstats><finished time="2" timestr="x" summary="x" elapsed="1" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
EOF
}

_exp_root="$(mktemp -d)"
_mk_result "${_exp_root}/old" "10.0.0.1" \
    $'22/tcp   open  ssh      OpenSSH 7.2\n80/tcp   open  http     Apache 2.4.18' "CVE-2016-6210"
_mk_result "${_exp_root}/old" "10.0.0.2" $'21/tcp   open  ftp      vsftpd 3.0.3'
_mk_result "${_exp_root}/new" "10.0.0.1" \
    $'22/tcp   open  ssh      OpenSSH 8.9\n443/tcp  open  ssl/http nginx 1.18'
_mk_result "${_exp_root}/new" "10.0.0.2" $'21/tcp   open  ftp      vsftpd 3.0.3'
_mk_xml "${_exp_root}/old/10.0.0.1/nmap/Port_10.0.0.1.xml" 10.0.0.1 22 ssh
_mk_xml "${_exp_root}/old/10.0.0.1/nmap/Script_10.0.0.1.xml" 10.0.0.1 80 http
# Incomplete XML (interrupted scan) must be ignored by the merge
printf '<?xml version="1.0"?>\n<nmaprun>\n<host>\n' > "${_exp_root}/old/10.0.0.1/nmap/Vulns_10.0.0.1.xml"

# --- find_target_dirs / detect_result_host ---
assert_eq "2" "$(find_target_dirs "${_exp_root}/old" | grep -c .)" "find_target_dirs: campaign layout"
assert_eq "${_exp_root}/old/10.0.0.1" "$(find_target_dirs "${_exp_root}/old/10.0.0.1")" "find_target_dirs: single target"
assert_eq "10.0.0.1" "$(detect_result_host "${_exp_root}/old/10.0.0.1")" "detect_result_host: from nmap file names"

# --- collect_scan_data (via result_rows) ---
assert_eq "10.0.0.1|22|tcp|open|ssh|OpenSSH 7.2|port_scan" "$(result_rows "${_exp_root}/old/10.0.0.1" | head -n 1)" \
    "result_rows: host|port|proto|state|service|version|source"
assert_eq "10.0.0.1|CVE-2016-6210|confirmed" "$(result_vuln_rows "${_exp_root}/old")" "result_vuln_rows: CVE with confidence"

# --- merge_xml_files: complete files only, one nmaprun, all hosts, no hosthints ---
_merged="$(cd "${_exp_root}/old/10.0.0.1" && merge_nmap_xml 10.0.0.1)"
assert_eq "1" "$(printf '%s\n' "${_merged}" | grep -c '<nmaprun ')" "merge_nmap_xml: single nmaprun root"
assert_eq "2" "$(printf '%s\n' "${_merged}" | grep -c '^<host ')" "merge_nmap_xml: host blocks from both complete scans"
assert_eq "0" "$(printf '%s\n' "${_merged}" | grep -c '<hosthint>')" "merge_nmap_xml: hosthints dropped"
assert_eq "1" "$(printf '%s\n' "${_merged}" | grep -c '</nmaprun>')" "merge_nmap_xml: closed document"
if command -v python3 >/dev/null 2>&1; then
    assert_eq "ok" "$(printf '%s\n' "${_merged}" | python3 -I -c 'import sys, xml.dom.minidom as m; m.parseString(sys.stdin.read().encode()); print("ok")' 2>&1)" \
        "merge_nmap_xml: well-formed XML"
fi
assert_exit 1 merge_xml_files /nonexistent.xml

# --- generate_exports (single target) ---
(cd "${_exp_root}/old/10.0.0.1" && OUTPUTDIR=. generate_exports 10.0.0.1 >/dev/null)
_ex="${_exp_root}/old/10.0.0.1/exports"
assert_eq "22,80" "$(cat "${_ex}/tcp_ports.txt")" "exports: tcp_ports.txt"
assert_eq "10.0.0.1" "$(cat "${_ex}/hosts.txt")" "exports: hosts.txt"
assert_eq $'10.0.0.1:22\n10.0.0.1:80' "$(cat "${_ex}/host_port.txt")" "exports: host_port.txt"
assert_eq "http://10.0.0.1:80" "$(cat "${_ex}/urls.txt")" "exports: urls.txt (web only)"
assert_eq '"10.0.0.1",80,"tcp","open","http","Apache 2.4.18","port_scan"' "$(sed -n 3p "${_ex}/services.csv")" "exports: services.csv row"
assert_eq "host,port,proto,state,service,version,discovered_in" "$(head -n 1 "${_ex}/services.csv")" "exports: services.csv header"
assert_eq "10.0.0.1:22" "$(cat "${_ex}/by_service/ssh_tcp.txt")" "exports: by_service/ssh_tcp.txt"
assert_eq '"10.0.0.1","CVE-2016-6210","confirmed"' "$(sed -n 2p "${_ex}/cves.csv")" "exports: cves.csv"
assert_eq "2" "$(grep -c '"port":' "${_ex}/services.jsonl")" "exports: services.jsonl lines"
assert_eq "true" "$([ -s "${_ex}/nmap_merged.xml" ] && echo true || echo false)" "exports: nmap_merged.xml written"

# --- export_campaign (aggregate) ---
export_campaign "${_exp_root}/new" >/dev/null
assert_eq $'10.0.0.1\n10.0.0.2' "$(cat "${_exp_root}/new/exports/hosts.txt")" "export_campaign: hosts.txt across targets"
assert_eq "21,22,443" "$(cat "${_exp_root}/new/exports/tcp_ports.txt")" "export_campaign: union of ports"
assert_eq "https://10.0.0.1:443" "$(cat "${_exp_root}/new/exports/urls.txt")" "export_campaign: ssl/http -> https URL"

# --- diff_results ---
_diff_out="$(diff_results "${_exp_root}/old" "${_exp_root}/new")"
_diff_rc=$?
assert_eq "1" "${_diff_rc}" "diff_results: exit 1 when results differ"
assert_match '\+ NEW +10\.0\.0\.1 443/tcp' "${_diff_out}" "diff_results: new port"
assert_match '- CLOSED +10\.0\.0\.1 80/tcp' "${_diff_out}" "diff_results: closed port"
assert_match '~ CHANGED 10\.0\.0\.1 22/tcp +ssh OpenSSH 7\.2 +-> +ssh OpenSSH 8\.9' "${_diff_out}" "diff_results: changed version"
assert_match '- GONE CVE 10\.0\.0\.1 CVE-2016-6210' "${_diff_out}" "diff_results: CVE no longer present"
assert_exit 0 diff_results "${_exp_root}/old" "${_exp_root}/old"
assert_exit 2 diff_results "${_exp_root}/old" "${_exp_root}/missing"

# --- explore_results ---
assert_exit 0 explore_results "${_exp_root}/old" summary
assert_match '10\.0\.0\.2 +1 +0 +0 +0' "$(explore_view "${_exp_root}/old" summary)" "explore summary: per-host counts"
assert_match '21 +tcp +open +ftp' "$(explore_view "${_exp_root}/old" ports ftp)" "explore ports: filter"
assert_eq "0" "$(explore_view "${_exp_root}/old" ports ftp | grep -c ' ssh ')" "explore ports: filter excludes others"
assert_eq "http://10.0.0.1:80" "$(explore_view "${_exp_root}/old" urls)" "explore urls"
assert_match 'CVE-2016-6210' "$(explore_view "${_exp_root}/old" vulns)" "explore vulns"
assert_match 'Script_10\.0\.0\.2\.nmap:[0-9]+:21/tcp' "$(explore_view "${_exp_root}/old" search vsftpd)" "explore search"
assert_exit 1 explore_results "${_exp_root}/old" no-such-view
assert_exit 1 explore_results "${_exp_root}/missing"

# --- export_results_dir rebuilds per-target + campaign exports ---
rm -rf "${_exp_root}/new/exports" "${_exp_root}/new/10.0.0.1/exports"
assert_exit 0 export_results_dir "${_exp_root}/new"
assert_eq "true" "$([ -f "${_exp_root}/new/10.0.0.1/exports/services.csv" ] && [ -f "${_exp_root}/new/exports/services.csv" ] && echo true || echo false)" \
    "export_results_dir: per-target and campaign exports"
assert_exit 1 export_results_dir "${_exp_root}/missing"

# --- _explore_menu: numbered choices drive the matching view, q quits ---
# The CLI opens the menu only on a TTY, so test the function directly with
# piped choices. 3 = ports, 5 = urls, then quit.
_menu_out="$(printf '3\n5\nq\n' | _explore_menu "${_exp_root}/old" 2>&1)"
assert_match '22/tcp|22 +tcp' "${_menu_out}" "explore menu: choice 3 shows the ports table"
assert_match 'http://10\.0\.0\.1:80' "${_menu_out}" "explore menu: choice 5 shows URLs"
# Word aliases work too, and an unknown choice is reported, not fatal.
_menu_out2="$(printf 'services\nbogus\nquit\n' | _explore_menu "${_exp_root}/old" 2>&1)"
assert_match 'ssh/tcp' "${_menu_out2}" "explore menu: word alias 'services'"
assert_match 'Unknown choice: bogus' "${_menu_out2}" "explore menu: unknown choice reported"
# EOF on input (read fails) exits the loop cleanly.
_explore_menu "${_exp_root}/old" </dev/null >/dev/null 2>&1
assert_eq "0" "$?" "explore menu: EOF on input exits cleanly"

rm -rf "${_exp_root}"
