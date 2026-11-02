# Exploring and Comparing Results

These modes read existing output only. They don't scan and don't need nmap, so
you can copy a results folder to another machine (e.g. from a Kali VM to your
Mac) and explore it there. They accept a single target directory (contains
`nmap/`) or a campaign directory (contains target subdirectories).

## `--explore <dir> [view] [args]`

With no view and a terminal, it prints the summary and opens a menu:

```
NmapReconFlow explorer - 10.10.10.5
  1) summary     2) hosts      3) ports       4) services
  5) urls        6) vulns      7) recon files 8) recommended commands
  9) show file  10) search    11) filter ports  e) rebuild exports   q) quit
```

Without a terminal (pipes, scripts) it prints the summary and exits.

| View | Shows |
|------|-------|
| `summary` | per target: open TCP/UDP, web services, CVEs, recon files, detected OS |
| `hosts` | targets with TCP/UDP service counts |
| `ports [FILTER]` | host/port/proto/state/service/version table. FILTER is a case-insensitive regex over the whole row (`http`, `445`, `ssh\|ftp`, `Apache/2\.4`) |
| `services` | each service with how often and on how many hosts it appears |
| `urls` | web URLs (same rules as `exports/urls.txt`) |
| `vulns` | CVE findings with confidence |
| `recon` | recon output files with line counts |
| `commands` | recommended recon commands and the manual follow-ups (brute force etc.) |
| `show FILE` | a file by path, or by name under `recon/` or `nmap/` (opens in `less` on a terminal) |
| `search REGEX` | case-insensitive grep across nmap and recon output, with file:line |

Examples:

```bash
nmapReconFlow.sh --explore 10.10.10.5
nmapReconFlow.sh --explore campaign_20260101_120000 ports 'smb|microsoft-ds'
nmapReconFlow.sh --explore campaign_20260101_120000 services
nmapReconFlow.sh --explore 10.10.10.5 search 'anonymous|guest'
nmapReconFlow.sh --explore 10.10.10.5 show nikto_10.10.10.5_80.txt
```

## `--diff <old> <new>`

Compares two runs, by `host + port + proto`:

```
Diff: results/monday -> results/friday

Services
+ NEW     10.0.0.1 443/tcp  ssl/http nginx 1.18
- CLOSED  10.0.0.1 80/tcp  http Apache 2.4.18
~ CHANGED 10.0.0.1 22/tcp  ssh OpenSSH 7.2  ->  ssh OpenSSH 8.9

Vulnerabilities
- GONE CVE 10.0.0.1 CVE-2016-6210

Summary: 1 new, 1 closed, 1 changed service(s); 1 CVE change(s)
```

Exit codes follow `diff(1)`: **0** no changes, **1** changes, **2** error.
That makes it usable for monitoring:

```bash
# nightly: rescan, alert only when the attack surface changed
today="scans/$(date +%F)"
nmapReconFlow.sh -f scope.txt -t Full -a -o "$today" --no-color >/dev/null
new="$(ls -d "$today"/campaign_* | tail -1)"
if ! nmapReconFlow.sh --diff "$(cat scans/last)" "$new" > diff.txt; then
    mail -s "Attack surface changed" you@example.com < diff.txt
fi
echo "$new" > scans/last
```

nmap's own `ndiff` also works on the per-scan XML or `exports/nmap_merged.xml`.
Note: the `ndiff` packaged in current Ubuntu/Debian crashes (Python `TypeError`)
on ports that have two or more script results. That is an upstream bug and also
happens on unmodified nmap XML. `--diff` has no such limitation.

## `--export <dir>`

Rebuilds `exports/` for every target in `<dir>`, plus the aggregated campaign
exports when `<dir>` is a campaign. See [EXPORTS.md](EXPORTS.md).
