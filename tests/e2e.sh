#!/usr/bin/env bash
# NmapReconFlow - end-to-end smoke test against a local web server.
# Runs real nmap scans of 127.0.0.1, so it needs: nmap, python3.
# Used by CI on Ubuntu, Debian, Kali and macOS. Exit 0 = all checks passed.
#
#   bash tests/e2e.sh            (from the repo root)

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NRF="${ROOT}/nmapReconFlow.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nrf_e2e.XXXXXX")"
PORT=8000   # must be in nmap's default top-1000 ports
pass=0
fail=0

ok()   { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }
check() { local msg="$1"; shift; if "$@"; then ok "${msg}"; else bad "${msg}"; fi; }

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "${SRV_PID}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

for t in nmap python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "e2e: $t is required"; exit 2; }
done

cd "${WORK}" || exit 2
mkdir www && echo "hello" > www/index.html
(cd www && exec python3 -m http.server "${PORT}" --bind 127.0.0.1 >/dev/null 2>&1) &
SRV_PID=$!
for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 0.2
done

echo "# platform: $(uname -s) $(uname -m), bash ${BASH_VERSION}, $(nmap --version | head -n 1)"

# 1. Invocation compatibility
check "sh/dash invocation re-execs bash" sh -c "sh '${NRF}' --version | grep -q 'NmapReconFlow v'"
check "--version" sh -c "'${NRF}' --version | grep -q 'NmapReconFlow v'"
if [ "$(uname -s)" = "Darwin" ] && [ -x /bin/bash ]; then
    check "macOS /bin/bash 3.2 re-execs Homebrew bash" sh -c "/bin/bash '${NRF}' --version | grep -q 'NmapReconFlow v'"
fi
check "invalid IPv4 octet rejected" sh -c "! '${NRF}' -H 10.0.0.999 -t Port >/dev/null 2>&1"
check "missing flag value rejected" sh -c "! '${NRF}' -H >/dev/null 2>&1"
check "no ANSI escapes when piped" sh -c "! '${NRF}' --help 2>&1 | grep -q \"\$(printf '\\033')\""

# 2. Single target: Port + Script + Recon, all report/export formats
"${NRF}" -H 127.0.0.1 -t Recon -a --format both --html -o single > single.log 2>&1
rc=$?
check "single-target Recon run exits 0 (rc=${rc})" [ "${rc}" -eq 0 ]
T="single"
check "Port scan found ${PORT}" grep -q "^${PORT}/tcp" "${T}/nmap/Port_127.0.0.1.nmap"
check "Script scan wrote -oN/-oX/-oG" sh -c "[ -s '${T}/nmap/Script_127.0.0.1.nmap' ] && [ -s '${T}/nmap/Script_127.0.0.1.xml' ] && [ -s '${T}/nmap/Script_127.0.0.1.gnmap' ]"
check "recon recommendations written" [ -f "${T}/nmap/Recon_127.0.0.1.nmap" ]
check "summary.md has YAML port ${PORT}" grep -q "port: ${PORT}" "${T}/summary.md"
check "summary.json is valid JSON" sh -c "python3 -I -m json.tool '${T}/summary.json' >/dev/null"
if command -v xsltproc >/dev/null 2>&1; then
    check "summary.html rendered" grep -qi '<html' "${T}/summary.html"
fi
check "exports/services.csv has ${PORT}" grep -q ",${PORT},\"tcp\"" "${T}/exports/services.csv"
check "exports/urls.txt has web URL" grep -qx "http://127.0.0.1:${PORT}" "${T}/exports/urls.txt"
check "exports/host_port.txt" grep -qx "127.0.0.1:${PORT}" "${T}/exports/host_port.txt"
# (CI runners may have other services on 127.0.0.1: check membership, not equality)
check "exports/tcp_ports.txt" grep -qE "(^|,)${PORT}(,|\$)" "${T}/exports/tcp_ports.txt"
check "exports/nmap_merged.xml is well-formed" python3 -I -c "import xml.dom.minidom as m; m.parse('${T}/exports/nmap_merged.xml')"
check "exports/services.jsonl is valid JSON Lines" python3 -I -c "
import json
for line in open('${T}/exports/services.jsonl'):
    json.loads(line)"
check "run log written" [ -s "${T}/nmapReconFlow_127.0.0.1_Recon.txt" ]
check "phase headers printed with colors off" grep -q -- '-----Starting Port Scan' "${T}/nmapReconFlow_127.0.0.1_Recon.txt"
check "no stray progress bars in run log" sh -c "! grep -q 'In progress:' '${T}/nmapReconFlow_127.0.0.1_Recon.txt'"

# 2b. Interactive recon: choose a tool at the prompt; it runs and the run ends
#     promptly (regression: an orphaned watchdog sleep kept the log open).
mkdir -p stubbin
printf '#!/bin/sh\necho stub-nikto "$@"\n' > stubbin/nikto
chmod +x stubbin/nikto
_t0="$(date +%s)"
(sleep 4; echo nikto) | PATH="${WORK}/stubbin:${PATH}" "${NRF}" -H 127.0.0.1 -t Recon --no-exports -o interactive > interactive.log 2>&1
_t1="$(date +%s)"
check "interactive recon ran chosen tool" grep -q 'stub-nikto' "interactive/recon/nikto_127.0.0.1_${PORT}.txt"
check "interactive run finished promptly ($((_t1 - _t0))s)" [ $((_t1 - _t0)) -lt 120 ]
check "recon tool status in report" grep -q 'tool: nikto' interactive/summary.md

# 3. Resume: completed phases are skipped
"${NRF}" -H 127.0.0.1 -t Recon -a --resume -o single > resume.log 2>&1
check "--resume run exits 0" [ $? -eq 0 ]

# 4. Explore + export + diff (no scanning)
check "--explore summary" sh -c "'${NRF}' --explore '${T}' summary | grep -q '127.0.0.1'"
check "--explore ports filter" sh -c "'${NRF}' --explore '${T}' ports http | grep -q '${PORT}'"
check "--explore urls" sh -c "'${NRF}' --explore '${T}' urls | grep -qx 'http://127.0.0.1:${PORT}'"
check "--explore search" sh -c "'${NRF}' --explore '${T}' search SimpleHTTP | grep -q Script_127.0.0.1"
rm -rf "${T}/exports"
check "--export rebuilds exports" sh -c "'${NRF}' --export '${T}' >/dev/null && [ -s '${T}/exports/services.csv' ]"
"${NRF}" --diff "${T}" "${T}" > diff.log 2>&1
check "--diff identical runs exits 0" [ $? -eq 0 ]

# 5. Campaign from stdin (echo | -f -), with an invalid entry and an exclusion
printf '127.0.0.2\n' > excl.txt
printf '127.0.0.1\n10.0.0.999\n127.0.0.2\nlocalhost\n' \
    | "${NRF}" -f - -t Port -x excl.txt -P 2 -o camp > camp.log 2>&1
rc=$?
check "stdin campaign exits 0 (rc=${rc})" [ "${rc}" -eq 0 ]
CS="$(ls -d camp/campaign_*/ 2>/dev/null | head -n 1)"
check "campaign summary lists 127.0.0.1 done" grep -q '| 127.0.0.1 | done |' "${CS}campaign_summary.md"
check "campaign skipped invalid target" grep -q 'Skipping invalid target: 10.0.0.999' camp.log
check "campaign honoured exclude file" sh -c "! [ -d '${CS}127.0.0.2' ]"
check "campaign aggregated exports" grep -q '127.0.0.1' "${CS}exports/hosts.txt"
check "campaign open_ports counted" grep -qE 'open_ports: [1-9][0-9]*$' "${CS}campaign_summary.md"
check "campaign counts are single numbers (no '0\\n0' bug)" sh -c "! grep -qE '^ *[0-9]+$' '${CS}campaign_summary.md'"

# 6. Scope: excluded single target refused
printf '127.0.0.1\n' > excl2.txt
check "excluded single target refused" sh -c "! '${NRF}' -H 127.0.0.1 -t Port -x excl2.txt -o nope >/dev/null 2>&1"

# 7. Signals: TERM stops the run and leaves no nmap behind
"${NRF}" -H 127.0.0.1 -t Full -a --profile stealth -o sigtest > sig.log 2>&1 &
SIG_PID=$!
sleep 6
kill -TERM "${SIG_PID}" 2>/dev/null
wait "${SIG_PID}" 2>/dev/null
sleep 3
check "TERM leaves no orphaned nmap" sh -c "! ps -A -o args | grep -v grep | grep -q 'nmap.*sigtest\\|nmap.*Full_127.0.0.1'"
check "stealth profile accepted by nmap (scan-delay in ms)" sh -c "! grep -q 'QUITTING' sig.log"

echo
printf '# e2e: %d passed, %d failed\n' "${pass}" "${fail}"
if [ "${fail}" -gt 0 ]; then
    echo "# --- single.log ---"; tail -n 40 single.log
    echo "# --- camp.log ---"; tail -n 40 camp.log
    exit 1
fi
exit 0
