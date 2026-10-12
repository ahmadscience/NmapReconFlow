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
NMAP_XML=true
assert_eq "-oN nmap/Port_h.nmap -oX nmap/Port_h.xml" "$(nmap_output_flags nmap/Port_h)" "nmap_output_flags: XML on"
NMAP_XML=false
assert_eq "-oN nmap/Port_h.nmap" "$(nmap_output_flags nmap/Port_h)" "nmap_output_flags: XML off"
NMAP_XML=true
