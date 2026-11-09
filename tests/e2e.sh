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

# True if an HTTP server on 127.0.0.1:$1 answers within 5s (proxies bypassed).
http_alive() {
    python3 -I -c "
import sys, urllib.request
o = urllib.request.build_opener(urllib.request.ProxyHandler({}))
o.open('http://127.0.0.1:%s/' % sys.argv[1], timeout=5).read()" "$1" >/dev/null 2>&1
}

# Wait up to ~10s for a TCP listener on 127.0.0.1:$1.
wait_port() {
    local _
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "${SRV_PID}" 2>/dev/null
    [ -n "${SRV2_PID:-}" ] && kill "${SRV2_PID}" 2>/dev/null
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
_s0="$(date +%s)"
"${NRF}" -H 127.0.0.1 -t Recon -a --format both --html -o single > single.log 2>&1
rc=$?
SINGLE_SECS=$(( $(date +%s) - _s0 ))
# Per-phase timing, for diagnosing slow platforms from the CI log.
awk '/^phases:/{p=1;next} p&&/^---/{exit} p&&/name:/{n=$3} p&&/duration_seconds:/{printf "# timing: %s phase %ss\n", n, $2}' single/summary.md 2>/dev/null
echo "# timing: whole Recon run ${SINGLE_SECS}s"
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
# Relative to the identical non-interactive run above on this machine: the
# regression this guards (an orphaned watchdog sleep holding the run log open)
# adds the full recon timeout (~600s); the prompt and a stub tool add ~10s.
check "interactive run finished promptly ($((_t1 - _t0))s vs ${SINGLE_SECS}s plain)" \
    [ $((_t1 - _t0)) -lt $((SINGLE_SECS + 90)) ]
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

# 8. UDP scan. Needs root; the Debian and Kali CI containers run as root,
#    Ubuntu and macOS runners do not. Localhost UDP is fast.
if [ "$(id -u)" = "0" ]; then
    "${NRF}" -H 127.0.0.1 -t UDP -a --no-exports -o udp > udp.log 2>&1
    rc=$?
    check "UDP run exits 0 (rc=${rc})" [ "${rc}" -eq 0 ]
    check "UDP phase ran as root (not skipped)" grep -qx 'UDP=done' udp/.nmapReconFlow.state
    check "UDP scan wrote nmap output" [ -s "udp/nmap/UDP_127.0.0.1.nmap" ]
    check "UDP not reported as needing root" sh -c "! grep -q 'needs root' udp.log"
else
    echo "# (not root; skipping UDP scan check - run in the Debian/Kali CI job)"
fi

# 8b. The signal (7) and UDP (8) tests must not disturb processes the tool
#     does not own: the web server started at the top must still answer.
check "unrelated web server still alive after signal/UDP tests" http_alive "${PORT}"

# 9. A real recon tool, when one is installed (the Kali CI job installs
#    nikto). Section 2b uses a stub; this exercises the real tee/timeout path
#    and a real tool's output file. It gets its own fresh web server on
#    another top-1000 port, and the shared one is stopped first, so this
#    measures nikto and nothing else (a heavy nikto run in section 2 has
#    already hit the shared server with thousands of requests).
PORT2=8080
if command -v nikto >/dev/null 2>&1; then
    kill "${SRV_PID}" 2>/dev/null; wait "${SRV_PID}" 2>/dev/null; SRV_PID=""
    (cd www && exec python3 -m http.server "${PORT2}" --bind 127.0.0.1 >/dev/null 2>&1) &
    SRV2_PID=$!
    check "dedicated web server for real recon is up" wait_port "${PORT2}"
    "${NRF}" -H 127.0.0.1 -t Recon -a --no-exports -o realrecon > realrecon.log 2>&1
    check "real recon run exits 0" [ $? -eq 0 ]
    check "real recon found port ${PORT2} open" grep -q "^${PORT2}/tcp *open" realrecon/nmap/Port_127.0.0.1.nmap
    check "real nikto wrote non-empty output" [ -s "realrecon/recon/nikto_127.0.0.1_${PORT2}.txt" ]
    check "real recon tool recorded in report" grep -q 'tool: nikto' realrecon/summary.md
else
    echo "# (no real recon tool installed; skipping real-recon check)"
fi

# 10. --explore with no view on a non-terminal prints the summary and exits
#     (the menu itself opens only on a TTY; it is unit-tested in test_export.sh).
printf '' | "${NRF}" --explore "${T}" > explore_default.out 2>/dev/null
check "--explore with no view prints summary on non-tty" grep -q '127.0.0.1' explore_default.out

echo
printf '# e2e: %d passed, %d failed\n' "${pass}" "${fail}"
if [ "${fail}" -gt 0 ]; then
    for _log in single.log camp.log sig.log udp.log realrecon.log; do
        [ -f "${_log}" ] || continue
        echo "# --- ${_log} ---"; tail -n 40 "${_log}"
    done
    exit 1
fi
exit 0
