# Contributing Guidelines

NmapReconFlow is a **bash 4.3+** tool (not POSIX `sh`) that must keep working on
**macOS, Kali, Debian and Ubuntu**. Pull requests are welcome; CI must be green on
all four platforms before merge.

## Project layout

```
nmapReconFlow.sh        Entry point: bash re-exec guard, arg parsing, dispatch, main()
lib/config.sh           Platform/distro detection, config + defaults, profiles, path helpers
lib/timeout.sh          run_with_timeout(), _spawn_group(), signal handling
lib/ui.sh               Colors, dashboard, nmap progress bar, logging, notifications
lib/utils.sh            Target validation (IPv4/IPv6/hostname/CIDR), exclusions, ports
lib/scans.sh            nmap scan phases
lib/recon.sh            Recon recommendations + execution
lib/report.sh           collect_scan_data(), summary.md / summary.json / summary.html
lib/export.sh           exports/ (CSV, JSONL, URLs, host:port, merged XML/gnmap)
lib/explore.sh          --explore views and --diff
lib/wizard.sh           --wizard guided setup (also runs with no args on a terminal)
lib/campaign.sh         Multi-target campaigns
tests/run_tests.sh      Unit tests (TAP), sources tests/test_*.sh
tests/e2e.sh            End-to-end: real nmap scans of a local web server
docs/                   User documentation
```

## Running the tests

```bash
bash tests/run_tests.sh        # unit tests, no nmap needed
bash tests/e2e.sh              # needs nmap + python3; scans 127.0.0.1:8000
shellcheck -x -S error nmapReconFlow.sh lib/*.sh install.sh tests/e2e.sh
```

On macOS run them with Homebrew bash: `"$(brew --prefix)/bin/bash" tests/run_tests.sh`.

CI (`.github/workflows/ci.yml`) runs lint, then unit + e2e tests on Ubuntu,
Debian (container), Kali (container) and macOS, plus a `docker-build` job that
builds the image and smoke-tests it. Some e2e sections only run where they can:
the UDP scan needs root (Debian/Kali containers), and the real-nikto check needs
nikto (installed in the Kali job); elsewhere they print a skip note. The Kali job
also checks that every package in the `Dockerfile` exists. The e2e log prints
per-phase timings (`# timing:` lines) for diagnosing slow platforms.

Add a unit test for every new function, and an e2e check for every new flag.
Unit tests run under `set -u`, so initialise any global a function reads.

## Coding standards

- camelCase for variables and functions (`newVariable`, `portScan`).
- `${var}` braces and quoting everywhere (`"${myVar}"`) unless word splitting is intended.
- Output files use underscores and include `${HOST}`: `Port_${HOST}.nmap`.
- Comment the purpose of every function and of any non-obvious line.
- Colors via the `${RED}`/`${GREEN}`/... variables (they are empty when output is not a terminal).
- Every external tool runs through `run_with_timeout()`.
- Functions that can fail return their exit code; scan phases propagate nmap's.

## Cross-platform rules (each one was a real bug)

| Don't | Do | Why |
|-------|----|-----|
| `sed -i` | `sed_inplace` | BSD sed needs `-i ''` |
| `setsid cmd &` | `_spawn_group cmd` | macOS has no setsid |
| `readlink -f`, `realpath` | `_resolve_path` | missing on older macOS |
| `echo -e`, `\e[` | `printf`, `\033[` | BSD/bash 3.2 differences |
| `printf "${GREEN}---"` | `printf -- "${GREEN}---"` | with colors off the format starts with `-` |
| `grep "389/tcp"` | `grep "^389/tcp"` | matches 3389 otherwise |
| `grep -v "#"` | `grep -v "^#"` | versions contain `#` (`RPC #100000`) |
| `--max-scan-delay 20` | `--max-scan-delay "$(nmap_delay_arg)"` | nmap reads a bare number as seconds |
| `grep -c x \|\| echo 0` | `n="$(grep -c x)"; echo "${n:-0}"` | prints `0` twice |
| `wc -l < f` in output | `$(($(wc -l < f)))` | macOS pads with spaces |
| hardcoded `/usr/share/...` | `find_wordlist`, `find_nmap_datadir` | Homebrew/Kali paths differ |
| `$USER` for root checks | `id -u` | `$USER` is unset in containers |
| `wait -n -p`, `${var@Q}` | per-PID `wait`, explicit quoting | bash 4.3 compatibility |

## Adding a recon tool

1. Emit the command from `reconRecommend()` in `lib/recon.sh`, writing to a path
   from `recon_outfile <tool> "${HOST}" [port]` (or `recon/<tool>_${HOST}.txt`).
   The **last** `recon/...` path on the line is treated as its output file.
2. Gate it with `! is_tool_skipped "<tool>"`; anchor port checks (`^PORT/tcp`) or
   use `ports_for_service "${file}" '<service regex>'`.
3. Map its package in `tool_package()` (`lib/config.sh`) if the package name differs.
4. Intrusive actions (brute force, spraying) go to `recon/_manual_commands.txt`
   via `suggest_manual_followups()`, or behind an opt-in flag.
5. Document it in the README and `nmapReconFlow.conf.example`; add a test.

## Commits and PRs

Keep changes focused, describe what you verified, and update `CHANGELOG.md`.
Do not add a "Generated with Claude Code" line to PR descriptions or commits.
