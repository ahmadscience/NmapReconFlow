#!/usr/bin/env bash
# Tests for lib/recon.sh

# --- recon_outfile: flat (legacy) layout ---
RECON_PER_PORT_DIRS=false
assert_eq "recon/nikto_10.0.0.1_80.txt" "$(recon_outfile nikto 10.0.0.1 80)" \
    "recon_outfile: flat layout with port"
assert_eq "recon/smbmap_10.0.0.1.txt" "$(recon_outfile smbmap 10.0.0.1)" \
    "recon_outfile: host-level (no port)"

# --- recon_outfile: per-port layout (runs in a temp dir; creates recon/<port>/) ---
assert_eq "recon/80/nikto_10.0.0.1.txt" "$(
    _d="$(mktemp -d)"; cd "$_d" || exit 1
    RECON_PER_PORT_DIRS=true recon_outfile nikto 10.0.0.1 80
    cd / && rm -rf "$_d"
)" "recon_outfile: per-port layout groups under recon/<port>/"

# --- recon_outfile: per-port on but host-level tool stays in recon/ root ---
assert_eq "recon/smbmap_10.0.0.1.txt" "$(RECON_PER_PORT_DIRS=true recon_outfile smbmap 10.0.0.1)" \
    "recon_outfile: per-port on but no port stays flat"

RECON_PER_PORT_DIRS=false

# --- recon_line_outfile: last recon/ path, quotes stripped ---
assert_eq "nikto_h_80.txt" "$(recon_line_outfile 'nikto -host "http://h:80" | tee "recon/nikto_h_80.txt"')" \
    "recon_line_outfile: tee target without trailing quote"
assert_eq "80/nikto_h.txt" "$(recon_line_outfile 'nikto -host "http://h:80" | tee "recon/80/nikto_h.txt"')" \
    "recon_line_outfile: per-port path"
assert_eq "ldapsearch_DC_h.txt" "$(recon_line_outfile 'ldapsearch -x -b "$(grep x "recon/ldapsearch_h.txt" | cut -f2)" | tee "recon/ldapsearch_DC_h.txt"')" \
    "recon_line_outfile: last occurrence wins (input file earlier on the line)"
assert_eq "SMB_vulns_h.txt" "$(recon_line_outfile 'nmap -Pn -p445 --script vuln "h" -oN "recon/SMB_vulns_h.txt"')" \
    "recon_line_outfile: nmap -oN"
assert_eq "" "$(recon_line_outfile 'odat sidguesser -s "h" -p 1521')" "recon_line_outfile: no output file"

# --- ports_for_service ---
_svc_lines=$'22/tcp   open  ssh     OpenSSH 8.2\n3306/tcp open  mysql   MySQL 5.7\n993/tcp  open  ssl/imap Dovecot\n111/tcp  open  rpcbind 2-4\n2049/tcp open  nfs     3-4\n80/tcp   open  http    nginx'
assert_eq "3306" "$(ports_for_service "${_svc_lines}" '^mysql')" "ports_for_service: mysql"
assert_eq "993" "$(ports_for_service "${_svc_lines}" '^imap')" "ports_for_service: strips ssl/ prefix"
assert_eq $'111\n2049' "$(ports_for_service "${_svc_lines}" '^(nfs|rpcbind|mountd)')" "ports_for_service: regex alternation"
assert_eq "" "$(ports_for_service "${_svc_lines}" '^redis')" "ports_for_service: no match"

# --- url_host ---
assert_eq "10.0.0.1" "$(url_host 10.0.0.1)" "url_host: IPv4 unchanged"
assert_eq "[2001:db8::1]" "$(url_host 2001:db8::1)" "url_host: IPv6 bracketed"

# --- emit_nse_recon ---
RECON_PER_PORT_DIRS=false
assert_eq 'nmap -Pn -sV -p3306 --script "mysql-info" "10.0.0.1" -oN "recon/nmap_mysql_10.0.0.1_3306.txt"' \
    "$(HOST=10.0.0.1 emit_nse_recon mysql 3306 mysql-info)" "emit_nse_recon: command line"
assert_eq 'nmap -6 -Pn -sV -p6379 --script "redis-info" "2001:db8::1" -oN "recon/nmap_redis_2001:db8::1_6379.txt"' \
    "$(HOST=2001:db8::1 emit_nse_recon redis 6379 redis-info)" "emit_nse_recon: IPv6 adds -6"

# --- reconRecommend regressions: anchored port matching, '#' in versions,
#     NSE output lines are not ports ---
_rr_out="$(
    _d="$(mktemp -d)"; cd "$_d" || exit 1
    mkdir -p nmap
    printf '%s\n' \
        "# Nmap 7.94 scan initiated as: nmap -sCV 10.0.0.9" \
        "PORT     STATE SERVICE       VERSION" \
        "111/tcp  open  rpcbind       2-4 (RPC #100000)" \
        "3389/tcp open  ms-wbt-server Microsoft Terminal Services" \
        "8080/tcp open  http          Jetty 9.4" \
        "|_http-open-proxy: Proxy might be redirecting requests" \
        "# Nmap done at Mon Jun 15 10:00:15 2026" > nmap/Script_10.0.0.9.nmap
    HOST=10.0.0.9 DRY_RUN=true osType=Windows DNSSERVER="" RECON_PER_PORT_DIRS=false commonPorts="111,3389,8080" allPorts="" subnet="" \
        reconRecommend 2>/dev/null
    cd / && rm -rf "$_d"
)"
assert_eq "0" "$(printf '%s\n' "${_rr_out}" | grep -c ldapsearch)" "reconRecommend: 3389/tcp does not trigger LDAP (389) recon"
assert_match 'nfs-showmount' "${_rr_out}" "reconRecommend: rpcbind line with '#' in version is kept"
assert_match 'rdp-ntlm-info' "${_rr_out}" "reconRecommend: RDP safe NSE emitted"
assert_eq "0" "$(printf '%s\n' "${_rr_out}" | grep -c 'http-open-proxy:')" "reconRecommend: NSE output line not treated as a port"
assert_match 'nikto -host "http://10.0.0.9:8080"' "${_rr_out}" "reconRecommend: real web port recommended"
