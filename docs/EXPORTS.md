# Exports

After every scan NmapReconFlow writes `exports/` inside the target directory.
Campaigns also get an aggregated `campaign_*/exports/` covering all targets.
Files are plain text in formats other tools read directly.

- Disable: `--no-exports` or `GENERATE_EXPORTS=false`.
- Rebuild from existing results (e.g. old runs, or after deleting files):
  `nmapReconFlow.sh --export <target-dir|campaign-dir>`. No scanning, no nmap.

Data comes from the nmap results in `nmap/` (Port, Script, Full, Full_Extra,
UDP, UDP_Extra, CVEs, Vulns), with the same merge rules as `summary.md`.
Version info from script scans replaces the bare port-scan entry.

## Files

| File | Format | Example line |
|------|--------|--------------|
| `hosts.txt` | one target per line (only targets with open ports) | `10.10.10.5` |
| `tcp_ports.txt` | comma list, sorted, unique | `22,80,443` |
| `udp_ports.txt` | comma list (empty if none) | `53,161` |
| `host_port.txt` | `host:port`, TCP, IPv6 as `[addr]:port` | `10.10.10.5:443` |
| `urls.txt` | web services as URLs | `https://10.10.10.5:443` |
| `services.csv` | RFC 4180 CSV with header | `"10.10.10.5",22,"tcp","open","ssh","OpenSSH 8.2p1","port_scan"` |
| `services.jsonl` | one JSON object per service | `{"host":"10.10.10.5","port":22,...}` |
| `cves.csv` | `host,cve,confidence` | `"10.10.10.5","CVE-2021-41773","confirmed"` |
| `by_service/<service>_<proto>.txt` | `host:port` per service | `by_service/ssh_tcp.txt` |
| `nmap_merged.xml` | one valid `<nmaprun>` with all scans' `<host>` blocks | — |
| `nmap_merged.gnmap` | all scans' grepable lines | `Host: 10.10.10.5 ()	Ports: 22/open/tcp//ssh//...` |
| `README.txt` | this list, inside the folder | — |

`services.csv` columns: `host, port, proto, state, service, version, discovered_in`
(`discovered_in` is `port_scan`, `script_scan`, `full_scan` or `udp_scan`).

CVE `confidence` is `confirmed` (vulners on detected versions) or `probable`
(nmap `vuln` scripts).

A service counts as web when nmap names it `http*`, `https*`, `ssl/http*`,
`http-proxy` or `http-alt`. It gets `https` when the name says so or the port is
443/4443/8443/9443. Windows RPC (`ncacn_http`, `http-rpc-epmap`) is excluded.

Only complete XML files (ending in `</nmaprun>`) are merged, so an interrupted
scan cannot corrupt `nmap_merged.xml`.

## Recipes

```bash
cd 10.10.10.5/exports

# Re-scan only what was open, with your own nmap options
nmap -sV -sC -p "$(cat tcp_ports.txt)" -iL hosts.txt -oA rescan

# Web: probe, template-scan, screenshot
httpx -l host_port.txt -title -tech-detect
nuclei -l urls.txt -severity medium,high,critical
gowitness scan file -f urls.txt

# TLS
testssl.sh --file host_port.txt

# Credential attacks (authorised engagements only - mind lockout policies)
brutespray -f nmap_merged.gnmap
hydra -M <(cut -d: -f1 by_service/ssh_tcp.txt) -L users.txt -P pass.txt ssh
nxc smb $(cut -d: -f1 by_service/microsoft-ds_tcp.txt)

# Metasploit
msfconsole -q -x "db_import $(pwd)/nmap_merged.xml; hosts; services; exit"

# HTML report from the merged XML
xsltproc nmap_merged.xml -o report.html

# Query with jq / pandas
jq -r 'select(.service|test("http")) | "\(.host):\(.port)"' services.jsonl
python3 -c "import pandas as p; print(p.read_csv('services.csv').groupby('service').size())"
```

For a campaign, use `campaign_*/exports/` the same way. It covers every target.
