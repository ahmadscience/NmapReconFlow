# NmapReconFlow — Known Errors & Bugs

## Critical

### ~~E001: Campaign parallel mode never updates target status~~ FIXED
PID-to-target mapping with individual `wait $pid` for status collection.

### ~~E002: Campaign subshells lack required globals~~ FIXED
`run_single_target()` explicitly initializes all globals before calling `main()`.

### ~~E003: `wait -n` requires bash 4.3+, nameref requires bash 4.3+~~ FIXED
Bash 4.3+ version check added at startup with clear error message.

## High

### ~~E004: `nmapProgressBar()` always returns exit code 0~~ FIXED
Now tracks `nmap_rc` and `timed_out` flag, returns 124 on timeout or nmap's actual exit code.

### ~~E005: Timeout kills only parent process, not process tree~~ FIXED
`run_with_timeout()` now uses `setsid` + `_kill_tree()` (process group kill). `nmapProgressBar` timeout also uses `_kill_tree()`. `cleanup_and_exit` uses process group kills.

### ~~E006: Date arithmetic uses awk with octal-unsafe values~~ FIXED
All `date '+%H:%M:%S'` arithmetic replaced with `date +%s` (epoch seconds).

### E007: Linux ping timeout — verified not a bug
Linux `ping -W 1` = 1 second timeout. macOS `ping -t 1` = 1 second. Both correct.

## Medium

### ~~E008: YAML escaping only handles double quotes~~ FIXED
`yaml_escape()` now escapes backslashes first, then double quotes, then newlines. All string fields quoted.

### ~~E009: `hostname` field empty when target is an IP~~ FIXED
Falls back to `${HOST}` when `urlIP` is empty.

### ~~E010: Recon tool arrays not reset between campaign targets~~ FIXED
`run_single_target()` resets `RECON_TOOL_STATUS` and `RECON_TOOL_DURATION` per target.

### ~~E011: Network scan sort output not saved to file~~ FIXED
Uses `sort -o` to write back to the same file, then `cat` to display.

### ~~E012: Signal handler vulnerable to double-invocation~~ FIXED
`_CLEANUP_RUNNING` guard prevents re-entrant execution.

## Found by end-to-end testing (real nmap runs)

### ~~E013: Campaign and CIDR modes never ran a scan~~ FIXED
`main()` was defined after the campaign dispatch, so every target failed with
`main: command not found`. `main` is now defined before dispatch.

### ~~E014: All recon tools failed on macOS~~ FIXED
`run_with_timeout` called `setsid`, which macOS doesn't have. `_spawn_group()`
uses perl `setpgrp` (keeps the tty so sudo tickets work), then setsid.

### ~~E015: `--max-scan-delay` in seconds, stealth profile rejected~~ FIXED
nmap reads a bare number as seconds: the default "20" meant 20 s and the stealth
profile's "200" made nmap quit. `nmap_delay_arg()` appends `ms`.

### ~~E016: Unanchored port matching~~ FIXED
`grep "389/tcp"` matched 3389 (RDP -> bogus LDAP recon); likewise 21/1521, 22/222, 25/125, 53/1053.

### ~~E017: Service lines containing '#' dropped~~ FIXED
`grep -v "#"` removed lines like `rpcbind 2-4 (RPC #100000)`; now `grep -v "^#"`.

### ~~E018: Duplicate CVEs from vulners URLs~~ FIXED
Every CVE was also recorded as `httpsvulnerscomcveCVE-...`. IDs are now extracted with `grep -o`.

### ~~E019: Duplicate ports passed to Vulns scan~~ FIXED
`allPorts` repeated ports found by both Port and Full scans; lists are now `sort -u`.

### ~~E020: Signals did not reach running tools~~ FIXED
`main | tee` ran main in a subshell (traps reset, CHILD_PIDS invisible to the
handler). main now runs in the parent shell with `> >(tee ...)`; campaign workers
re-arm traps; sequential campaign workers are waited on interruptibly.

### ~~E021: UDP scan when root / without sudo / in autopilot~~ FIXED
Used `$USER` (unset in containers) and always prefixed `sudo`, which hung in
autopilot or failed where sudo is absent. `resolve_privilege()` handles all cases.

### ~~E022: Installed symlink could not find lib/~~ FIXED
`install.sh` links `/usr/local/bin/nmapReconFlow`; SCRIPT_DIR is now resolved through symlinks.

### ~~E023: Resume could hang on a partial scan file~~ FIXED
An interrupted `.nmap` without "Nmap done" was waited on until the timeout; it is now discarded and re-scanned.

### ~~E024: Recon outputs never detected on resume~~ FIXED
The output filename parser kept a trailing quote, and took the FIRST `recon/` path
(an input for the ldapsearch DC query). `recon_line_outfile()` takes the last path.

### ~~E025: `grep -c ... || echo 0` produced "0\n0" in campaign YAML~~ FIXED

### Known upstream: Ubuntu/Debian `ndiff` crashes on ports with 2+ script results
Python 3 `TypeError` in ndiff itself (also on unmodified nmap XML). Use `--diff`.
