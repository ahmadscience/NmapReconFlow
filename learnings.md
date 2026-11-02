# NmapReconFlow — Learnings

## Architecture Decisions

### L001: Bash modularization via `source`
Splitting a monolithic shell script into `lib/*.sh` modules sourced at startup works well for organization but creates a flat namespace. All functions and globals share scope. This is acceptable for a tool of this size (~2000 lines) but means variable naming discipline is critical.

### L002: `eval` is still needed for constructed nmap commands
The `nmapProgressBar()` function receives nmap commands as strings because it needs to parse `-oN <file>` to find the output filename. This forces `eval` usage. Alternative: pass the output file as a separate argument and construct the command inside the function.

### L003: Subshell isolation vs global state
Campaign mode runs each target in a subshell for isolation, but `main()` was designed for single-target mode where globals are set progressively (header sets nmapType, portScan sets commonPorts, etc.). The subshell approach requires either: (a) exporting all globals, (b) re-initializing inside the subshell, or (c) restructuring main() to be self-contained.

### L004: Process tree management in bash
`kill -TERM $pid` only kills the immediate process. For tools that spawn children (nmap NSE scripts, ffuf threads), you need process group kills: `kill -TERM -$pid` (note the negative PID). This requires starting the child in its own process group with `set -m` or `setsid`.

### L005: Date arithmetic pitfall
`date '+%H:%M:%S'` produces zero-padded hours like `08` which awk interprets as octal (and `08` is invalid octal). Always use `date +%s` (epoch seconds) for arithmetic. The original nmapAutomator had this same bug.

## Cross-Platform Pitfalls

### L006: macOS ships bash 3.2
Apple licenses bash under GPLv2 and refuses to ship GPLv3 (bash 4+). Associative arrays, nameref (`local -n`), and `wait -n` all require bash 4+. Either: document the requirement, check at startup, or avoid these features.

### L007: `sed -i` is the #1 cross-platform trap
GNU sed: `sed -i 's/foo/bar/' file`
BSD sed: `sed -i '' 's/foo/bar/' file`
Always use the `sed_inplace()` wrapper.

### L008: Ping timeout flag
Linux `ping -W 1` = 1 second timeout. macOS `ping -t 1` = 1 second timeout. Both use seconds with the value `1`, so the current implementation is correct despite confusing flag names.

## Testing Observations

### L009: No nmap available in CI/container environments
The tool can't be functionally tested without nmap installed. Unit tests should mock nmap output files and test parsing/reporting functions independently.

### L010: Progress bar requires a TTY
The progress dashboard uses ANSI escape sequences that break in piped/redirected output. The `IS_TTY` check handles this but makes automated testing of UI functions difficult.

## Lessons from end-to-end testing (v2.1.0)

### L010: Unit tests passed while whole features were broken
Campaign mode called a function defined later in the script, and every recon tool
failed on macOS (`setsid` missing). Neither showed up in unit tests, which never run
the entry script. `tests/e2e.sh` now runs real nmap scans in CI on all four
platforms. Keep adding an e2e check for every user-facing flag.

### L011: Function definitions are statements
In bash a function exists only after its definition has executed. Anything a
dispatch path calls (`main` for campaigns) must be defined before that path runs.

### L012: Process groups without setsid
macOS has no `setsid`. `perl -e 'setpgrp(0,0); exec @ARGV'` creates a new process
group while keeping the controlling terminal. That matters for sudo: tty-bound
sudo tickets stop working after `setsid` detaches the tty.

### L013: Traps don't survive into subshells
Caught traps are reset in `( ... )`, pipelines and `&` jobs. `main | tee log` put
the CHILD_PIDS table in a subshell with no handler. Run main in the parent with
`main > >(tee log)`, and re-arm traps in every worker. A foreground subshell also
delays the parent's trap until the child exits; background it and `wait` (the
`wait` builtin is interruptible). Then give it `<&0` so it keeps the terminal.

### L014: Background helpers hold pipes open
A killed watchdog subshell left its `sleep N` child running. That sleep inherited
stdout (the `tee` pipe), so the run log stayed open for N seconds. Kill helper
children explicitly and detach helpers' stdout.

### L015: nmap units
`--max-scan-delay 20` means 20 *seconds*, and values ≥ ~100 make nmap quit. The
original nmapAutomator had this too. Always pass units (`20ms`).

### L016: Substring matching on nmap output
`grep "389/tcp"` matches `3389/tcp`, and `grep -v "#"` drops `RPC #100000`
service lines. Anchor patterns on the port column. Extract IDs with `grep -o`
rather than stripping characters (vulners URLs contain the CVE ID).

### L017: Empty color variables change printf semantics
When colors are disabled, `printf "${GREEN}----"` becomes `printf "----"`, which
printf parses as an option. Use `printf --` for formats that may start with `-`.

### L018: `grep -c` already prints 0
`grep -c x f || echo 0` prints `0` twice, because grep prints 0 *and* exits 1.
