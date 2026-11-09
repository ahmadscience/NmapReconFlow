# Platform Guide

| Platform | Status | Install |
|----------|--------|---------|
| Kali Linux (rolling) | CI-tested | `sudo ./install.sh --with-deps --with-recon` |
| Debian 12+ | CI-tested | `sudo ./install.sh --with-deps --with-recon` |
| Ubuntu 22.04+ | CI-tested | `sudo ./install.sh --with-deps --with-recon` |
| macOS 13+ (Intel & Apple Silicon) | CI-tested | `brew install bash nmap`, then `./install.sh` |
| Fedora/RHEL, Arch | best effort | `install.sh` knows dnf/pacman; not in CI |
| Docker (Kali image) | — | see below |

CI (`.github/workflows/ci.yml`) runs the unit tests and `tests/e2e.sh` (real
nmap scans of a local web server, a campaign, explore/export/diff, signal
handling) on Ubuntu, Debian, Kali and macOS for every push. Debian and Kali run
as root, so they also cover UDP scans; Kali also runs a real nikto scan. A
`docker-build` job builds the Docker image and checks that it starts and
contains nmap, nikto and ffuf.

## Requirements

- **bash 4.3+.** The script fixes common cases itself:
  - `sh nmapReconFlow.sh` (dash on Debian/Ubuntu) and `zsh nmapReconFlow.sh` re-launch under bash.
  - macOS `/bin/bash` is 3.2. The script re-launches with Homebrew bash
    (`/opt/homebrew/bin/bash` or `/usr/local/bin/bash`) when installed.
- **nmap.**
- **perl.** Used to put each tool in its own process group so timeouts and
  Ctrl+C kill the whole tree. It ships with macOS and is always present on
  Debian/Ubuntu/Kali (`perl-base` is essential). Without perl, `setsid` is used.
- Optional: `xsltproc` (`--html`), `ping`, `host`/`dig`, and the recon tools.
  When recommended tools are missing, the run lists them with an install
  command for your platform (`apt`, `brew`, `dnf`, `pacman`).

## `install.sh`

```
sudo ./install.sh [--with-deps] [--with-recon] [--prefix DIR]
```

- Copies the tool to `/usr/local/share/nmapReconFlow` (or `--prefix`) and links
  `/usr/local/bin/nmapReconFlow`.
- `--with-deps`: bash, nmap, curl, DNS tools, ping, xsltproc, perl.
- `--with-recon`: ffuf, gobuster, nikto, whatweb, sslscan, smbclient, smbmap,
  ldap-utils, snmp, dnsrecon, nfs-common, hydra, ssh-audit, enum4linux-ng,
  exploitdb, nuclei, gowitness, wordlists/seclists (Debian family). Each
  package is tried separately. Packages your distro lacks (Ubuntu/Debian don't
  ship several Kali tools) are listed at the end instead of aborting.
- macOS: Homebrew refuses to run as root, so under `sudo` the installer runs
  `brew` as your user.
- Derivatives (Parrot, Mint, Pop!_OS, Rocky, Alma, Manjaro) are recognised via `ID_LIKE`.

## UDP scans and root

UDP scanning needs raw sockets:

| Situation | Behaviour |
|-----------|-----------|
| running as root (incl. Docker) | scans directly, no sudo |
| sudo works without a password, or the ticket is cached | `sudo -n nmap ...` |
| interactive terminal, sudo needs a password | asks once, then scans |
| autopilot / no terminal / piped targets, and sudo needs a password | **skips UDP** (phase shows `skipped`, note "needs root") instead of hanging |
| no sudo installed | skips UDP |

To include UDP in an unattended run, run `sudo -v` first or run as root.

## macOS notes

- `brew install bash nmap`. Homebrew nmap's data dir (`share/nmap`) is found
  from the binary's location, on both Intel and Apple Silicon.
- `ping` there is IPv4-only, so IPv6 targets use `ping6` with an external timeout.
- No `setsid`, `timeout`, `realpath` or GNU sed is needed.

## Docker

```bash
docker build -t nmapreconflow .
docker run --rm -it --net=host -v "$PWD:/output" nmapreconflow -H 10.10.10.10 -t All -a
docker run --rm -it -v "$PWD:/output" nmapreconflow --explore /output/10.10.10.10
```

The image is Kali with nmap and the recon tools preinstalled. It runs as root
(UDP works). `--net=host` gives scans the host's network view. Docker's
default capabilities include `NET_RAW`, which nmap's SYN/UDP scans need.

## Output and terminals

- Colors and the live progress bar appear only on a terminal. Piped output,
  cron and CI get plain text (`NO_COLOR=1` / `--no-color` force this,
  `FORCE_COLOR=1` overrides).
- Pipe targets in: `echo 10.0.0.1 | nmapReconFlow.sh -f - -t Port`. This
  implies autopilot, since stdin is not a keyboard.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `requires bash 4.3+` on macOS | `brew install bash` |
| `Missing tools (will be skipped): ...` | install with the printed command, or `install.sh --with-recon` |
| UDP phase `skipped (needs root)` | run as root or `sudo -v` before an autopilot run |
| `Exclude file not found` | `-x` needs an existing file (one IP/CIDR/hostname per line, `#` comments) |
| HTML report skipped | install `xsltproc` (`apt install xsltproc`; built into macOS) |
| `ndiff` Python `TypeError` | upstream ndiff bug; use `--diff` |
| One port takes ~2 minutes in the Script scan | nmap couldn't identify that service, so version detection tries all ~30 probes (5 s timeout each). Normal on every OS; recognised services take seconds. (In CI this shows up on macOS because nmap there doesn't recognise the Python test server; real servers such as Apache are identified in ~7 s on macOS, same as Linux.) |
| Want to resume after Ctrl+C | re-run the same command with `--resume`. Partial scans are redone, finished ones skipped |
