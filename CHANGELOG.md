# Changelog

## Unreleased

### Added
- **Guided setup for beginners**: run `nmapReconFlow` with no options on a terminal (or `--wizard`) and answer seven plain questions (target, scan type, speed, unattended, HTML report, folder, permission). It refuses to scan unless you confirm permission, re-asks invalid input, and prints the equivalent command before running it.
- **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)**: a step-by-step guide for new users (install per OS, first safe scan, reading results, choosing a scan type, copy-paste recipes, troubleshooting, glossary). Linked from the top of the README and from `--help`.

### Tests / CI
- e2e now covers a real UDP scan (in the root Debian/Kali CI containers), a real recon tool (nikto, installed in the Kali job) against the local web server, and the `--explore` no-view summary fallback on a non-terminal.
- The interactive `--explore` menu is unit-tested by driving `_explore_menu` with piped choices (numbered and word aliases, unknown choice, EOF).
- New `docker-build` CI job: builds the `Dockerfile` and smoke-tests the entrypoint (`--version`, `--help`) and that nmap/nikto/ffuf are present in the image.
- e2e checks that the signal and UDP tests leave unrelated processes alive (a web server the tool doesn't own must still answer), and the real-nikto check runs against its own fresh server.
- Process-group tests: the pgid check waits for perl's `setpgrp` to take effect (slower on macOS), and a new check confirms a group kill also stops the spawned command's children.
- macOS now runs the full e2e suite in CI for the first time (44/44). The interactive-run time limit is relative to the plain run on the same machine, and the log prints per-phase timings.

## 2.1.0

### Fixed
- **Campaign (`-f`) and CIDR modes never scanned anything.** `main()` was defined after the campaign dispatch.
- **All recon tools failed on macOS.** `setsid` doesn't exist there; process groups now use perl `setpgrp`.
- `--max-scan-delay` was sent without a unit. nmap reads a bare number as seconds, so the default meant 20 s and the stealth profile made nmap quit. The value is now sent in ms.
- Port matching was unanchored: `389/tcp` matched 3389 (bogus LDAP recon on RDP hosts), and likewise 21/1521, 22/222, 25/125, 53/1053.
- Service lines containing `#` (e.g. `rpcbind 2-4 (RPC #100000)`) were dropped from recon.
- Every vulners CVE was also recorded as a mangled ID built from its URL.
- Duplicate ports were passed to the Vulns scan.
- Ctrl+C/TERM did not reach running tools. Campaign workers had no traps, and watchdog `sleep`s were orphaned, keeping the run log open for up to 10 minutes.
- UDP: no longer relies on `$USER` (unset in containers), works as root without sudo, and skips instead of hanging on a password prompt in autopilot.
- Installed symlink (`/usr/local/bin/nmapReconFlow`) couldn't find `lib/`.
- `--resume` hung on partial scan files and never detected finished recon output.
- Campaign summary counts showed `0\n0`. nmap failures were reported as phase "done".
- An NSE output line like `|_http-open-proxy` was treated as a web port.

### Added
- `exports/` for every target and campaign: `services.csv`, `services.jsonl`, `urls.txt`, `host_port.txt`, `hosts.txt`, `tcp_ports.txt`, `udp_ports.txt`, `cves.csv`, `by_service/`, `nmap_merged.xml`, `nmap_merged.gnmap`. See [docs/EXPORTS.md](docs/EXPORTS.md).
- `--explore <dir> [view]`, `--export <dir>`, `--diff <old> <new>`. See [docs/RESULTS.md](docs/RESULTS.md).
- `-x/--exclude <file>` scope exclusions (IPs, IPv4 CIDRs, hostnames).
- `-f -` reads targets from stdin. Target files may contain CIDR ranges.
- Grepable nmap output (`-oG`, `NMAP_GNMAP`).
- Recon: whatweb, safe per-service NSE (NFS, MySQL, MSSQL, RDP, Redis, MongoDB, VNC, SMTP, IMAP, POP3, memcached, rsync, telnet, FTP), showmount, ssh-audit, enum4linux-ng and NetExec when present, Kerberos/WinRM manual follow-ups.
- Opt-in `--nuclei` and `--screenshots` (gowitness v2/v3).
- `--no-color`, `NO_COLOR`, `FORCE_COLOR`. Colors are off automatically when output is not a terminal.
- `install.sh --with-recon`. The installer detects derivatives via `ID_LIKE`.
- Missing-tool install hints for apt, brew, dnf and pacman.
- `tests/e2e.sh` and a CI matrix running real scans on Ubuntu, Debian, Kali and macOS.

### Changed
- The script re-launches itself with bash when started via `sh`/`zsh`, and with Homebrew bash on macOS.
- Hostname validation accepts single labels (`dc01`) and long TLDs (`.internal`). IPv4 octets must be 0–255.
- IPv6 targets get bracketed URLs and `-6` on recon nmap commands.
- `-o` now sets where campaign directories are created.
- `--parallel` must be a positive integer, and flags that take a value reject a missing one.

## 2.0.x
- Scan profiles (`--profile stealth|normal|aggressive`) and per-port recon directories (`--per-port-dirs`).
- HTML report, completion webhooks, opt-in brute force (`--brute`).
- Fast discovery (rustscan/naabu/masscan), CIDR & IPv6 targets, JSON report, nmap XML, searchsploit, manual-commands file, dry-run & resume, Docker image, installer.
- Modular rewrite of nmapAutomator: timeouts, autopilot, campaigns, dashboard, summary report.
