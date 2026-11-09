# Getting Started with NmapReconFlow

New to scanning? This guide takes you from zero to your first results in about
10 minutes. No prior experience needed.

---

## What does it do?

You give NmapReconFlow a target (an IP address or a website name). It then:

1. finds which **ports** are open (the "doors" a computer has open to the network),
2. works out what **software** is running behind each door, and its version,
3. looks up **known vulnerabilities (CVEs)** for that software,
4. runs extra **recon tools** (for example nikto for websites),
5. writes a **report** you can read, and files other tools can use.

It runs [nmap](https://nmap.org) and other well-known tools for you, so you
don't have to remember dozens of commands.

> ⚠️ **Only scan systems you own or have written permission to test.**
> Scanning other people's computers or networks can be illegal. Good places to
> practise: your own machine (`127.0.0.1`), a virtual machine you set up, a lab
> such as Hack The Box or TryHackMe, or `scanme.nmap.org` (light scans only:
> Nmap's authors allow it).

---

## Step 1: Install

Pick your system. Copy each block into a terminal and press Enter.

### Kali Linux, Debian or Ubuntu

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/whatsdd/NmapReconFlow.git
cd NmapReconFlow
sudo ./install.sh --with-deps --with-recon
```

`--with-deps` installs nmap and the basics. `--with-recon` adds the optional
recon tools (nikto, ffuf, ...). On Ubuntu and Debian a few tools aren't
packaged; the installer tells you which. That's fine, they are just skipped.

### macOS

You need [Homebrew](https://brew.sh) first. Then:

```bash
brew install git bash nmap
git clone https://github.com/whatsdd/NmapReconFlow.git
cd NmapReconFlow
sudo ./install.sh --with-deps
```

(macOS ships an old bash; `brew install bash` gets a new one. NmapReconFlow
uses it automatically.)

### Docker (any system)

```bash
git clone https://github.com/whatsdd/NmapReconFlow.git
cd NmapReconFlow
docker build -t nmapreconflow .
```

Then run scans with `docker run --rm -it --net=host -v "$PWD:/output" nmapreconflow`
followed by the options shown below.

### Check it works

```bash
nmapReconFlow --version
```

You should see `NmapReconFlow v...`. If you skipped `install.sh`, use
`./nmapReconFlow.sh` from the project folder instead of `nmapReconFlow`
everywhere in this guide.

---

## Step 2: Your first scan (the easy way)

Just run it with no options:

```bash
nmapReconFlow
```

A guided setup asks you seven simple questions:

1. **What to scan.** Type `127.0.0.1` (your own machine) for a safe first try.
2. **What kind of scan.** Press Enter for "Standard".
3. **How fast.** Press Enter for "Normal".
4. **Run without more questions?** Press Enter (yes).
5. **HTML report?** Press Enter (yes).
6. **Folder for results.** Press Enter.
7. **Do you have permission?** Type `y`. It's your own machine.

Before it starts, it shows the real command, for example:

```
Running: nmapReconFlow.sh -H 127.0.0.1 -t Script -a --html
```

Next time you can type that command directly and skip the questions.
`nmapReconFlow --wizard` starts the guided setup again any time.

---

## Step 3: Look at the results

Results go in a folder named after your target (e.g. `127.0.0.1/`).

| Open this | What it is |
|-----------|------------|
| `summary.html` | The easiest: open it in your browser (made when you answer yes to the HTML question) |
| `summary.md` | The same report as text; readable in any editor |
| `exports/urls.txt` | Every website found, one per line |
| `exports/services.csv` | All open ports and software, opens in Excel/LibreOffice/Numbers |
| `recon/` | Raw output of each recon tool (e.g. nikto) |

Or browse the results with the built-in explorer:

```bash
nmapReconFlow --explore 127.0.0.1
```

It shows a summary and a menu. Type a number and press Enter:

```
  1) summary     2) hosts      3) ports       4) services
  5) urls        6) vulns      7) recon files 8) recommended commands
  9) show file  10) search    11) filter ports  e) rebuild exports   q) quit
```

- **3) ports** lists every open port and what's running on it.
- **6) vulns** lists known vulnerabilities (CVE numbers you can search online).
- **8) recommended commands** shows the next commands an expert would try.
- **q** quits.

---

## Step 4: Choose the right scan

| Scan type (`-t`) | What it does | Time | Use it when |
|------------------|--------------|------|-------------|
| `Port` | Finds open ports | ~15 s | You want a quick look |
| `Script` | Ports + software versions | ~5 min | **Good default** |
| `Full` | All 65,535 ports | ~5-10 min | Things might hide on unusual ports |
| `Vulns` | Looks up known vulnerabilities | ~5-15 min | You want to know what's exploitable |
| `Recon` | Standard scan + follow-up tools (nikto, ...) | varies | Websites and services to dig into |
| `All` | Everything, including UDP | ~20-30 min | You want the full picture and can wait |
| `UDP` | UDP ports (needs `sudo`) | ~5 min | DNS, SNMP and similar services |
| `Network` | Finds live machines on the network | ~15 s | You don't know what's on the network yet |

---

## Copy-paste recipes

```bash
# The full picture, no questions asked (-a = autopilot)
nmapReconFlow -H 10.10.10.5 -t All -a

# Same, with a browser-friendly report
nmapReconFlow -H 10.10.10.5 -t All -a --html

# Several targets: put one per line in targets.txt
nmapReconFlow -f targets.txt -t Script -a

# A whole network range
nmapReconFlow -H 192.168.1.0/24 -t Port -a

# Slow and quiet
nmapReconFlow -H 10.10.10.5 -t Script -a --profile stealth

# Fast (labs and CTFs)
nmapReconFlow -H 10.10.10.5 -t All -a --profile aggressive

# Save results in a folder you choose
nmapReconFlow -H 10.10.10.5 -t Script -a -o my-results

# Stopped it with Ctrl+C? Re-run the same command with --resume
nmapReconFlow -H 10.10.10.5 -t All -a --resume

# Never touch certain machines (one IP or range per line in skip.txt)
nmapReconFlow -H 192.168.1.0/24 -t Port -a -x skip.txt

# Compare two scans: what's new, what closed?
nmapReconFlow --diff old-results new-results

# See what would run, without scanning
nmapReconFlow -H 10.10.10.5 -t All --dry-run
```

`nmapReconFlow --help` lists every option.

---

## Troubleshooting

| You see | Do this |
|---------|---------|
| `command not found: nmapReconFlow` | Run `sudo ./install.sh` from the project folder, or use `./nmapReconFlow.sh` |
| `requires bash 4.3+` (macOS) | `brew install bash` |
| `Nmap is not installed` | Kali/Debian/Ubuntu: `sudo apt install nmap`. macOS: `brew install nmap` |
| `Missing tools (will be skipped): ...` | Optional. Install them with the command it prints, or ignore it |
| UDP phase says `skipped (needs root)` | Run with `sudo`, or run `sudo -v` first |
| `Invalid IP or URL!` | Check for typos: an IP looks like `10.10.10.5`, a name like `example.com` |
| `Host is likely running ...` looks wrong | It's a guess from network behaviour; the script scan's result is more reliable |
| No open ports found | The target may be off, or blocking scans: try `-t Full`, check the IP, check your VPN |
| The scan seems stuck | Each step has a time limit and moves on by itself. Ctrl+C stops it, and `--resume` continues later |
| The Script/Standard scan takes ~2 minutes on one port | Normal: nmap couldn't recognise the software there, so it tries all ~30 of its identification probes and waits a few seconds for each. Recognised services take seconds |

More detail: [PLATFORMS.md](PLATFORMS.md) (setup and troubleshooting per
system), [RESULTS.md](RESULTS.md) (explore and diff),
[EXPORTS.md](EXPORTS.md) (using the results with other tools).

---

## Words you'll see

| Word | Meaning |
|------|---------|
| **Port** | A numbered "door" on a computer. Web servers usually use 80/443, SSH uses 22. |
| **Open port** | A door that answers: some software is listening there. |
| **Service** | The software behind a port (e.g. `http`, `ssh`). |
| **Version** | Which release of that software, e.g. `OpenSSH 8.2`. Old versions often have known bugs. |
| **CVE** | A public ID for a known vulnerability, e.g. `CVE-2021-41773`. Search it online to learn more. |
| **Recon** | Reconnaissance: gathering information about a target. |
| **TCP / UDP** | Two kinds of network traffic. Most services use TCP; some (DNS, SNMP) use UDP. |
| **Autopilot (`-a`)** | Run everything without asking questions. |
| **Profile** | Speed setting: `stealth` (slow, quiet), `normal`, `aggressive` (fast, loud). |
| **Campaign** | Scanning several targets in one go (`-f targets.txt`). |
| **nmap** | The scanner NmapReconFlow is built on. |
