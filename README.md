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
- **Cross-platform** — works on macOS, Kali Linux, and Ubuntu.
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
- **Docker & installer** — `Dockerfile` (Kali + tools) and `install.sh`.

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

- **bash** 4.3+ (for associative arrays and `wait -n`)
- **nmap**
- **Recommended**: [ffuf](https://github.com/ffuf/ffuf) or [gobuster](https://github.com/OJ/gobuster)

Other recon tools (installed automatically on Kali, install as needed on other distros):

| Tool | Tool | Tool | Tool | Tool |
|:----:|:----:|:----:|:----:|:----:|
| [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) | [sslscan](https://github.com/rbsec/sslscan) | [nikto](https://github.com/sullo/nikto) | [joomscan](https://github.com/rezasp/joomscan) | [wpscan](https://github.com/wpscanteam/wpscan) |
| [droopescan](https://github.com/droope/droopescan) | [smbmap](https://github.com/ShawnDEvans/smbmap) | [enum4linux](https://github.com/portcullislabs/enum4linux) | [dnsrecon](https://github.com/darkoperator/dnsrecon) | [odat](https://github.com/quentinhardy/odat) |
| [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) | snmp-check | snmpwalk | ldapsearch | |

Missing tools are automatically detected and skipped with a warning.

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

### Kali / Ubuntu
```bash
sudo apt update && sudo apt install nmap ffuf -y
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
  --resume                  Resume a previously interrupted scan
  --no-report               Skip summary.md generation
  --format <FORMAT>         Report format: markdown, json, or both
  --dry-run                 Show what would run without executing
  --html                    Also generate summary.html from nmap XML
  --brute                   Auto-run hydra against ssh/ftp/rdp (lockout risk!)
  --profile <NAME>          Timing profile: stealth, normal, aggressive (default: normal)
  --per-port-dirs           Group recon output under recon/<port>/ (AutoRecon-style)
  -v, --version             Print version
```

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
```

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
  summary.md                    # Human + AI readable report
  summary.json                  # Machine-readable (when --format json/both)
  nmapReconFlow_target_All.txt  # Full console output
```

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
