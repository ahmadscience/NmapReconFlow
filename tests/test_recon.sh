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
