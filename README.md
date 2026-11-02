# NmapReconFlow

Automated reconnaissance workflow. Fire and forget.

*Based on [nmapAutomator](https://github.com/21y4d/nmapAutomator) by @21y4d*

## What's New

NmapReconFlow is a major overhaul of nmapAutomator with these improvements:

- **Timeout protection** — every scan and recon tool has a configurable wall-clock timeout. No more hanging nikto/gobuster sessions. Stuck scans are killed and the pipeline moves on.
- **Autopilot mode** (`-a`) — run the entire pipeline unattended, zero prompts.
- **Multi-target campaigns** (`-f targets.txt`) — give it a file of IPs and forget. Sequential by default, parallel with `-P N`.
- **Progress dashboard** — real-time status of each scan phase with elapsed time.
- **Summary report** — generates `summary.md` with YAML front matter (AI/tool readable) and markdown body (human readable). Includes port discovery timeline and finding confidence levels.
- **Signal handling** — Ctrl+C cleans up all background processes. No more orphaned nmap jobs.
- **Cross-platform** — tested in CI on macOS, Kali, Debian and Ubuntu with real nmap scans.
- **Configurable** — rate limits, timeouts, wordlist paths, tool preferences via config file.
- **Fast port discovery** — optionally feed the Full scan with rustscan/naabu/masscan so nmap only scans open ports (minutes → seconds).
- **CIDR & IPv6 targets** — `-H 10.0.0.0/24` auto-expands into a campaign; IPv6 targets scanned with `nmap -6`.
- **JSON output** — `--format json` (or `both`) writes `summary.json` for tooling.
- **Nmap XML** — `-oX` written alongside `-oN`, enabling `searchsploit --nmap` and HTML reports.
- **searchsploit** — offline Exploit-DB lookup against the scan's XML.
- **Manual-commands file** — intrusive follow-ups (brute force, spraying) are written to `recon/_manual_commands.txt` instead of auto-running.
- **Dry-run & resume** — `--dry-run` previews commands; `--resume` skips already-completed phases.
- **HTML report** — `--html` renders `summary.html` from the nmap XML (via `xsltproc`).
- **Notifications** — set `NOTIFY_WEBHOOK` to ping Slack/Discord/a generic webhook when a scan or campaign finishes.
- **Opt-in brute force** — `--brute` auto-runs hydra against ssh/ftp/rdp (off by default; lockout risk).
- **Scan profiles** — `--profile stealth|normal|aggressive` presets nmap timing, rate, retries, and scan-delay in one flag.
- **Per-port output dirs** — `--per-port-dirs` groups recon output under `recon/<port>/` (AutoRecon-style) instead of a flat folder.
- **Docker & installer** — `Dockerfile` (Kali + tools) and `install.sh` (`--with-deps`, `--with-recon`).
- **Exports for other tools** — every run writes `exports/`: `services.csv`/`.jsonl`, `urls.txt`, `host_port.txt`, port lists, per-service target lists, and one merged nmap XML/gnmap (Metasploit `db_import`, nuclei, httpx, brutespray, spreadsheets).
- **Explore results** — `--explore <dir>` browses a target or campaign (interactive menu, or views like `ports http`, `urls`, `vulns`, `search <regex>`).
- **Diff runs** — `--diff <old> <new>` shows new/closed ports, changed versions and CVE changes (exit 1 when something changed: cron-friendly).
- **Scope control** — `-x/--exclude <file>` never scans listed IPs/CIDRs/hosts (single, campaign and CIDR modes).
- **Pipe targets in** — `echo 10.0.0.1 | nmapReconFlow.sh -f - -t Port`.
- **More service recon** — whatweb, safe NSE per service (NFS, MySQL, MSSQL, RDP, Redis, MongoDB, VNC, SMTP, IMAP, POP3, rsync, ...), showmount, ssh-audit, enum4linux-ng; opt-in `--nuclei` and `--screenshots` (gowitness).

## Features

### Scan Types
| Type | Description | Time |
|------|-------------|------|
| Network | Discover live hosts on the network | ~15 seconds |
| Port | Find all open ports | ~15 seconds |
| Script | Version detection + NSE scripts on found ports | ~5 minutes |
| Full | All 65535 ports + script scan on new ports | ~5-10 minutes |
| UDP | UDP port scan (requires sudo) | ~5 minutes |
| Vulns | CVE detection + vulnerability scripts | ~5-15 minutes |
| Recon | Auto-recommend and run service-specific recon tools | varies |
| All | Run everything | ~20-30 minutes |

### Autopilot Mode
```bash
./nmapReconFlow.sh -H 10.10.10.10 -t All -a
```
Runs all scans unattended. Stuck tools are killed after their timeout (default 10 minutes for recon tools). The pipeline continues automatically.

### Multi-Target Campaigns
```bash
# targets.txt: one IP or hostname per line, # for comments
./nmapReconFlow.sh -f targets.txt -t All -a

# Parallel (2 targets at a time)
./nmapReconFlow.sh -f targets.txt -t All -a -P 2
```
Each target gets its own output directory. A campaign summary is generated at the end.

### Summary Report
After scanning, `summary.md` is generated with:
- **YAML front matter**: structured data for AI tools and scripts (ports, services, vulns, timing)
- **Open ports table** with service versions and discovery source
- **Port discovery timeline**: which scan found which ports
- **Vulnerability findings** with confidence levels (confirmed/probable/potential)
- **Recon tool output** (truncated, with timeout status)
- **Scan phase summary** with durations

### Configuration
Copy `nmapReconFlow.conf.example` to `./nmapReconFlow.conf` or `~/.nmapReconFlow.conf`:
```bash
cp nmapReconFlow.conf.example nmapReconFlow.conf
```
Configurable: timeouts, nmap rate limits, wordlist paths, tool skip lists, parallelism, report options.

## Requirements

- **bash** 4.3+ (macOS: `brew install bash`; the script re-launches itself with
  Homebrew bash automatically, and also works when started as `sh nmapReconFlow.sh`)
- **nmap**
- **perl** (process-group handling; preinstalled on macOS, Debian, Ubuntu, Kali)
- **Recommended**: [ffuf](https://github.com/ffuf/ffuf) or [gobuster](https://github.com/OJ/gobuster), `xsltproc` for `--html`

Other recon tools (installed automatically on Kali, install as needed on other distros):

| Tool | Tool | Tool | Tool | Tool |
|:----:|:----:|:----:|:----:|:----:|
| [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) | [sslscan](https://github.com/rbsec/sslscan) | [nikto](https://github.com/sullo/nikto) | [joomscan](https://github.com/rezasp/joomscan) | [wpscan](https://github.com/wpscanteam/wpscan) |
| [droopescan](https://github.com/droope/droopescan) | [smbmap](https://github.com/ShawnDEvans/smbmap) | [enum4linux](https://github.com/portcullislabs/enum4linux) | [dnsrecon](https://github.com/darkoperator/dnsrecon) | [odat](https://github.com/quentinhardy/odat) |
| [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) | snmp-check | snmpwalk | ldapsearch | [whatweb](https://github.com/urbanadventurer/WhatWeb) |
| [ssh-audit](https://github.com/jtesta/ssh-audit) | [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | showmount | [nuclei](https://github.com/projectdiscovery/nuclei) | [gowitness](https://github.com/sensepost/gowitness) |

Missing tools are detected and skipped, with an install command for your
platform (`apt`, `brew`, `dnf` or `pacman`).

### Platform support

| Platform | Status | Notes |
|----------|--------|-------|
| Kali Linux | CI-tested | Everything packaged; `install.sh --with-deps --with-recon` |
| Debian 12+ | CI-tested | Core + most recon tools via apt |
| Ubuntu 22.04+ | CI-tested | Core via apt; some recon tools need manual install |
| macOS 13+ (Intel/Apple Silicon) | CI-tested | `brew install bash nmap`; no `setsid` needed (uses perl) |

UDP scans need root. When not root, NmapReconFlow uses `sudo` if it can; in
autopilot (or with no terminal) it never blocks on a password prompt and skips
UDP instead (run `sudo -v` first to include it).

## Installation

```bash
git clone https://github.com/whatsdd/NmapReconFlow.git
cd NmapReconFlow
chmod +x nmapReconFlow.sh
sudo ln -s "$(pwd)/nmapReconFlow.sh" /usr/local/bin/nmapReconFlow
```

### macOS
```bash
brew install nmap
# Install recon tools as needed
```

### Kali / Debian / Ubuntu
```bash
sudo ./install.sh --with-deps               # nmap, bash, ping, dig, xsltproc
sudo ./install.sh --with-deps --with-recon  # + ffuf, gobuster, nikto, whatweb, ...
```

### Docker
```bash
docker build -t nmapreconflow .
docker run --rm -it --net=host -v "$PWD:/output" nmapreconflow -H 10.10.10.10 -t All -a
```

## Usage

```
./nmapReconFlow.sh -h

Usage: nmapReconFlow.sh -H/--host <TARGET-IP> -t/--type <TYPE>
       nmapReconFlow.sh -f/--file <TARGETS-FILE> -t/--type <TYPE>

Required:
  -H, --host <TARGET>       Target IP or hostname
  -f, --file <FILE>         File with targets (one per line)
  -t, --type <TYPE>         Scan type

Optional:
  -a, --autopilot           Run unattended, no prompts
  -d, --dns <DNS>           Custom DNS server
  -o, --output <DIR>        Output directory
  -s, --static-nmap <PATH>  Path to static nmap binary
  -r, --remote              Remote mode (limited scans)
  -c, --config <FILE>       Config file path
  -P, --parallel <N>        Campaign parallelism (default: 1)
  -x, --exclude <FILE>      Never scan IPs/CIDRs/hosts listed in FILE
  --resume                  Resume a previously interrupted scan
  --no-report               Skip summary.md generation
  --no-exports              Skip exports/
  --format <FORMAT>         Report format: markdown, json, or both
  --dry-run                 Show what would run without executing
  --html                    Also generate summary.html from nmap XML
  --brute                   Auto-run hydra against ssh/ftp/rdp (lockout risk!)
  --nuclei                  Run nuclei templates against discovered web URLs
  --screenshots             Screenshot discovered web URLs with gowitness
  --profile <NAME>          Timing profile: stealth, normal, aggressive (default: normal)
  --per-port-dirs           Group recon output under recon/<port>/ (AutoRecon-style)
  --no-color                Plain output (also NO_COLOR=1; automatic when piped)
  -v, --version             Print version

Results tools (no scanning, no nmap needed):
  --explore <DIR> [VIEW]    Browse results; VIEW: summary, hosts, ports [FILTER],
                            services, urls, vulns, recon, commands,
                            show <FILE>, search <REGEX>
  --export <DIR>            (Re)build exports/ for a result or campaign directory
  --diff <OLD> <NEW>        Compare two runs
```

`-f -` reads targets from stdin. Target files may contain IPs, hostnames,
IPv6 addresses and CIDR ranges, with `#` comments.

`-H` also accepts a CIDR range (e.g. `10.0.0.0/24`), which is expanded and run
as a campaign, and IPv6 addresses (scanned with `nmap -6`).

### Examples
```bash
# Single target, all scans, autopilot
./nmapReconFlow.sh -H 10.10.10.10 -t All -a

# Quick port scan
./nmapReconFlow.sh -H 10.10.10.10 -t Port

# Recon with custom DNS
./nmapReconFlow.sh -H academy.htb -t Recon -d 1.1.1.1

# Multi-target campaign
./nmapReconFlow.sh -f targets.txt -t All -a

# Custom config and output dir
./nmapReconFlow.sh -H 10.10.10.10 -t All -a -c custom.conf -o results/

# Quiet/slow scan with per-port recon folders
./nmapReconFlow.sh -H 10.10.10.10 -t All -a --profile stealth --per-port-dirs

# Fast and loud (labs/CTFs)
./nmapReconFlow.sh -H 10.10.10.10 -t Full -a --profile aggressive

# Targets from a pipe, with a scope exclusion list
cat scope.txt | ./nmapReconFlow.sh -f - -t All -a -x out-of-scope.txt

# Web-heavy target: nuclei + screenshots
./nmapReconFlow.sh -H 10.10.10.10 -t All -a --nuclei --screenshots
```

### Exploring Results
```bash
./nmapReconFlow.sh --explore 10.10.10.10              # interactive menu
./nmapReconFlow.sh --explore campaign_20260101_120000 ports 'http|ssl'
./nmapReconFlow.sh --explore 10.10.10.10 search 'Apache/2\.4\.49'
./nmapReconFlow.sh --diff results/monday results/friday  # what changed?
```

### Using the Exports with Other Tools
Every run writes `exports/` (campaigns also get an aggregated
`campaign_*/exports/`). Rebuild any time with `--export <dir>`.

| File | Use it with |
|------|-------------|
| `hosts.txt` | `nmap -iL hosts.txt`, `masscan -iL` |
| `tcp_ports.txt` / `udp_ports.txt` | `nmap -p "$(cat tcp_ports.txt)" -iL hosts.txt` |
| `host_port.txt` | `httpx -l`, `nuclei -l`, `testssl.sh --file` |
| `urls.txt` | `nuclei -l`, `ffuf`, `gowitness scan file -f`, `eyewitness -f` |
| `services.csv` | spreadsheets, `pandas.read_csv`, SIEM import |
| `services.jsonl` | `jq 'select(.service=="ssh")'`, Elastic, Splunk |
| `cves.csv` | tracking / reporting |
| `by_service/<svc>_tcp.txt` | `hydra -M`, `nxc`, per-service tooling |
| `nmap_merged.xml` | Metasploit `db_import`, `xsltproc`, nmap-parse-output, Faraday, Dradis |
| `nmap_merged.gnmap` | `brutespray -f`, grep/awk |

### Scan Profiles
`--profile` sets nmap timing knobs in one flag. Any explicit `NMAP_*` value in
your config overrides the profile.

| Profile | Timing | Max rate | Retries | Max scan-delay |
|---------|:------:|:--------:|:-------:|:--------------:|
| stealth | `-T2` | 100/s | 2 | 200 |
| normal (default) | `-T4` | 500/s | 1 | 20 |
| aggressive | `-T5` | 5000/s | 1 | 5 |

### Legacy Compatibility
The old `nmapAutomator.sh` flags still work. `Quick` maps to `Port`, `Basic` maps to `Script`.

## Output Structure
```
target_ip/
  nmap/
    Port_target.nmap
    Script_target.nmap
    Full_target.nmap
    UDP_target.nmap
    CVEs_target.nmap
    Vulns_target.nmap
    Recon_target.nmap
    Port_target.xml             # Nmap XML (when NMAP_XML=true)
    Port_target.gnmap           # Grepable (when NMAP_GNMAP=true)
  recon/
    nikto_target_80.txt
    ffuf_target_80.txt
    searchsploit_target.txt
    _manual_commands.txt        # Intrusive follow-ups to run by hand
    ...
    # With --per-port-dirs, port-specific output is grouped instead:
    #   recon/80/nikto_target.txt
    #   recon/80/ffuf_target.txt
    #   recon/443/sslscan_target.txt
  exports/                      # CSV, JSONL, URLs, host:port, merged XML (see above)
  summary.md                    # Human + AI readable report
  summary.json                  # Machine-readable (when --format json/both)
  nmapReconFlow_target_All.txt  # Full console output
```

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
