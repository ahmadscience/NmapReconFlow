# NmapReconFlow — CLAUDE.md

## Project Overview
Bash-based automated reconnaissance tool. Wraps nmap + 25 recon tools into a modular pipeline with timeout protection, autopilot mode, multi-target campaigns, and summary reporting.

## Tech Stack
- **Language:** Bash 4.3+ (required for associative arrays, nameref, `wait -n`)
- **Shebang:** `#!/usr/bin/env bash`
- **Platforms:** macOS (Darwin), Kali Linux, Ubuntu

## Repository Structure
```
nmapReconFlow.sh              # Entry point: arg parsing, validation, dispatch
lib/
  config.sh                   # Platform detection, config loading, path helpers
  timeout.sh                  # run_with_timeout(), signal traps, PID tracking
  ui.sh                       # Colors, progress bar, dashboard, logging
  utils.sh                    # checkPing, assignPorts, header, footer
  scans.sh                    # All nmap scan functions
  recon.sh                    # Recon recommendation + execution
  report.sh                   # summary.md generation (YAML + markdown), collect_scan_data()
  export.sh                   # exports/ (CSV, JSONL, URLs, merged nmap XML/gnmap)
  explore.sh                  # --explore views and --diff of result directories
  campaign.sh                 # Multi-target campaign orchestration
nmapReconFlow.conf.example    # Documented example config
nmapAutomator.sh              # Legacy script (original upstream)
tests/run_tests.sh            # Unit tests (TAP)
tests/e2e.sh                  # End-to-end: real nmap scans of a local web server
```

## Coding Conventions
- Variable names: camelCase (e.g., `commonPorts`, `nmapType`)
- Function names: camelCase (e.g., `portScan`, `assignPorts`)
- All variables enclosed in `${}` and quoted: `"${myVar}"`
- Output files use underscores and include `${HOST}`: `Port_${HOST}.nmap`
- ANSI colors via `\033[...m` (not `\e[...]` — macOS compat)
- Use `command -v` instead of `type` for tool detection

## Build / Test / Lint Commands
```bash
# Unit + end-to-end tests (e2e needs nmap and python3)
bash tests/run_tests.sh
bash tests/e2e.sh

# Syntax check all files
bash -n nmapReconFlow.sh
for f in lib/*.sh; do bash -n "$f"; done

# Shellcheck (if available)
shellcheck -x nmapReconFlow.sh lib/*.sh

# Test help output
./nmapReconFlow.sh --help
./nmapReconFlow.sh --version

# Test validation (no nmap required)
./nmapReconFlow.sh -H invalid!!! -t Port    # Should reject
./nmapReconFlow.sh -H 127.0.0.1 -t BadType  # Should reject
```

## Cross-Platform Rules
- Never use `sed -i` directly — use `sed_inplace()` from lib/config.sh
- Never hardcode paths like `/usr/share/wordlists/` — use `find_wordlist()`
- Never hardcode nmap script paths — use `find_nmap_scripts_dir()`
- Use `$PING_TIMEOUT_FLAG` for ping timeout flag (Linux=W, macOS=t)
- Use `date +%s` for epoch timestamps (not `date '+%H:%M:%S'` with awk arithmetic)
- No `setsid` on macOS — start process groups with `_spawn_group()` (perl setpgrp)
- No `readlink -f`/`realpath` on older macOS — use `_resolve_path()`
- `printf` formats must not start with `-` once colors are empty: use `printf -- "..."`
- Anchor port matches against nmap lines: `grep "^389/tcp"` (plain "389/tcp" matches 3389)
- Bare `--max-scan-delay N` means seconds to nmap — use `nmap_delay_arg()` (adds ms)

## Critical Design Rules
- Every external tool invocation MUST go through `run_with_timeout()`
- Every function that can fail MUST propagate its exit code
- Signal handlers MUST clean up the entire process tree (kill process groups, not just PIDs)
- Every shell that tracks CHILD_PIDS (incl. campaign workers) MUST call install_signal_handlers (traps reset in subshells)
- Campaign subshells MUST have all required globals available
- YAML output MUST properly escape special characters
