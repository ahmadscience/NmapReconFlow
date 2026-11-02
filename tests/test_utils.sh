#!/usr/bin/env bash
# Tests for lib/utils.sh

# --- checkOS ---
assert_eq "Linux" "$(checkOS 64)" "checkOS: TTL 64 returns Linux"
assert_eq "Linux" "$(checkOS 63)" "checkOS: TTL 63 returns Linux"
assert_eq "Windows" "$(checkOS 128)" "checkOS: TTL 128 returns Windows"
assert_eq "Windows" "$(checkOS 127)" "checkOS: TTL 127 returns Windows"
assert_eq "OpenBSD/Cisco/Oracle" "$(checkOS 254)" "checkOS: TTL 254 returns OpenBSD/Cisco/Oracle"
assert_eq "OpenBSD/Cisco/Oracle" "$(checkOS 255)" "checkOS: TTL 255 returns OpenBSD/Cisco/Oracle"
assert_eq "Unknown OS!" "$(checkOS 200)" "checkOS: TTL 200 returns Unknown OS!"

# --- is_valid_scan_type: valid types ---
assert_exit 0 is_valid_scan_type "Port"
assert_exit 0 is_valid_scan_type "port"
assert_exit 0 is_valid_scan_type "All"
assert_exit 0 is_valid_scan_type "all"
assert_exit 0 is_valid_scan_type "UDP"
assert_exit 0 is_valid_scan_type "udp"
assert_exit 0 is_valid_scan_type "Network"
assert_exit 0 is_valid_scan_type "Script"
assert_exit 0 is_valid_scan_type "Full"
assert_exit 0 is_valid_scan_type "Vulns"
assert_exit 0 is_valid_scan_type "Recon"

# --- is_valid_scan_type: invalid types ---
assert_exit 1 is_valid_scan_type "Invalid"
assert_exit 1 is_valid_scan_type ""
assert_exit 1 is_valid_scan_type "port_scan"
assert_exit 1 is_valid_scan_type "everything"

# --- validate_host_safe: valid hosts ---
assert_exit 0 validate_host_safe "10.0.0.1"
assert_exit 0 validate_host_safe "example.com"
assert_exit 0 validate_host_safe "test-host.local"
assert_exit 0 validate_host_safe "::1"
assert_exit 0 validate_host_safe "2001:db8::1"

# --- validate_host_safe: dangerous inputs ---
assert_exit 1 validate_host_safe '$(id)'
assert_exit 1 validate_host_safe '`whoami`'
assert_exit 1 validate_host_safe "test;ls"
assert_exit 1 validate_host_safe "test|cat"
assert_exit 1 validate_host_safe "test&bg"

# --- cmpPorts ---
commonPorts="22,80"
allPorts="22,80,443,8080"
extraPorts=""
cmpPorts
assert_eq "443,8080" "$extraPorts" "cmpPorts: finds extra ports 443,8080"

commonPorts="22,80"
allPorts="22,80"
extraPorts=""
cmpPorts
assert_eq "" "$extraPorts" "cmpPorts: no extra ports when sets match"

# --- is_ipv6 ---
assert_exit 0 is_ipv6 "::1"
assert_exit 0 is_ipv6 "2001:db8::1"
assert_exit 0 is_ipv6 "fe80::1"
assert_exit 1 is_ipv6 "10.0.0.1"
assert_exit 1 is_ipv6 "example.com"

# --- is_cidr ---
assert_exit 0 is_cidr "10.0.0.0/24"
assert_exit 0 is_cidr "192.168.1.0/16"
assert_exit 0 is_cidr "2001:db8::/64"
assert_exit 1 is_cidr "10.0.0.1"
assert_exit 1 is_cidr "example.com"

# --- nmap_output_flags (from config.sh) ---
NMAP_XML=true; NMAP_GNMAP=true
assert_eq "-oN nmap/Port_h.nmap -oX nmap/Port_h.xml -oG nmap/Port_h.gnmap" "$(nmap_output_flags nmap/Port_h)" "nmap_output_flags: XML + gnmap"
NMAP_XML=false
assert_eq "-oN nmap/Port_h.nmap -oG nmap/Port_h.gnmap" "$(nmap_output_flags nmap/Port_h)" "nmap_output_flags: XML off"
NMAP_GNMAP=false
assert_eq "-oN nmap/Port_h.nmap" "$(nmap_output_flags nmap/Port_h)" "nmap_output_flags: normal only"
NMAP_XML=true; NMAP_GNMAP=true

# --- is_ipv4 ---
assert_exit 0 is_ipv4 "10.0.0.1"
assert_exit 0 is_ipv4 "255.255.255.255"
assert_exit 0 is_ipv4 "010.008.000.009"
assert_exit 1 is_ipv4 "10.0.0.256"
assert_exit 1 is_ipv4 "10.0.0.999"
assert_exit 1 is_ipv4 "10.0.0"
assert_exit 1 is_ipv4 "a.b.c.d"

# --- is_hostname ---
assert_exit 0 is_hostname "example.com"
assert_exit 0 is_hostname "localhost"
assert_exit 0 is_hostname "dc01"
assert_exit 0 is_hostname "academy.htb"
assert_exit 0 is_hostname "intranet.corp.internal"
assert_exit 0 is_hostname "my-host.local"
assert_exit 1 is_hostname "10.0.0.999"
assert_exit 1 is_hostname "-bad.com"
assert_exit 1 is_hostname "bad_host.com"
assert_exit 1 is_hostname "a..b"

# --- ip_in_cidr ---
assert_exit 0 ip_in_cidr "10.1.2.3" "10.0.0.0/8"
assert_exit 0 ip_in_cidr "192.168.1.77" "192.168.1.0/24"
assert_exit 0 ip_in_cidr "1.2.3.4" "0.0.0.0/0"
assert_exit 0 ip_in_cidr "127.0.0.2" "127.0.0.2/32"
assert_exit 1 ip_in_cidr "192.168.2.1" "192.168.1.0/24"
assert_exit 1 ip_in_cidr "example.com" "10.0.0.0/8"
assert_exit 1 ip_in_cidr "10.0.0.1" "10.0.0.0/33"

# --- is_excluded ---
_excl_file="$(mktemp)"
printf '# scope exclusions
10.0.0.5
192.168.50.0/24  # lab
Printer.Corp.local
' > "${_excl_file}"
EXCLUDE_FILE="${_excl_file}"
assert_exit 0 is_excluded "10.0.0.5"
assert_exit 0 is_excluded "192.168.50.9"
assert_exit 0 is_excluded "printer.corp.local"
assert_exit 1 is_excluded "10.0.0.6"
assert_exit 1 is_excluded "192.168.51.9"
EXCLUDE_FILE=""
assert_exit 1 is_excluded "10.0.0.5"
rm -f "${_excl_file}"

# --- _ports_from_files: sorted, de-duplicated (Port + Full overlap) ---
assert_eq "22,80,443,8080,9090" "$(_ports_from_files "${TEST_DIR}/fixtures/Port_testhost.nmap" "${TEST_DIR}/fixtures/Full_testhost.nmap")" \
    "_ports_from_files: merges and de-duplicates ports"
assert_eq "" "$(_ports_from_files "${TEST_DIR}/fixtures/UDP_empty.nmap")" "_ports_from_files: no open ports"
assert_eq "" "$(_ports_from_files /nonexistent/file.nmap)" "_ports_from_files: missing file"

# --- assignPorts: no duplicates in allPorts (fed to -p for Vulns) ---
assignPorts_dir="$(mktemp -d)"
mkdir -p "${assignPorts_dir}/nmap"
cp "${TEST_DIR}/fixtures/Port_testhost.nmap" "${TEST_DIR}/fixtures/Full_testhost.nmap" "${assignPorts_dir}/nmap/"
assert_eq "22,80,443|22,80,443,8080,9090" "$(cd "${assignPorts_dir}" && commonPorts="" allPorts="" && assignPorts testhost && printf '%s|%s' "${commonPorts}" "${allPorts}")" \
    "assignPorts: commonPorts and de-duplicated allPorts"
rm -rf "${assignPorts_dir}"
