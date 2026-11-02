#!/usr/bin/env bash
# NmapReconFlow - Automated reconnaissance workflow
# Based on nmapAutomator by @21y4d
# https://github.com/whatsdd/NmapReconFlow

# Run under a capable bash no matter how we were started:
#  - `sh nmapReconFlow.sh` (dash on Debian/Ubuntu) or `zsh nmapReconFlow.sh`
#    (macOS default shell) -> re-exec with bash. POSIX syntax only up here.
#  - macOS /bin/bash is 3.2 -> re-exec with Homebrew bash 4.3+ if installed.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || \
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
    if [ -z "${NMAPRF_REEXEC:-}" ]; then
        for _b in /opt/homebrew/bin/bash /usr/local/bin/bash /opt/local/bin/bash; do
            if [ -x "${_b}" ]; then
                export NMAPRF_REEXEC=1
                exec "${_b}" "$0" "$@"
            fi
        done
    fi
    printf "NmapReconFlow requires bash 4.3+. Current: %s\n" "${BASH_VERSION:-unknown}" >&2
    printf "macOS users: brew install bash\n" >&2
    exit 1
fi

set -o pipefail

# Resolve our real location through symlinks (install.sh links
# /usr/local/bin/nmapReconFlow -> <prefix>/nmapReconFlow.sh) so lib/ is found.
_self="${BASH_SOURCE[0]}"
while [ -L "${_self}" ]; do
    _link="$(readlink "${_self}")"
    case "${_link}" in
        /*) _self="${_link}" ;;
        *)  _self="$(dirname "${_self}")/${_link}" ;;
    esac
done
SCRIPT_DIR="$(cd "$(dirname "${_self}")" && pwd -P)"
unset _self _link

for _lib in config timeout ui utils scans recon report export explore campaign; do
    # shellcheck disable=SC1090
    source "${SCRIPT_DIR}/lib/${_lib}.sh"
done

detect_platform
install_signal_handlers

elapsedStart="$(date +%s)"
REMOTE=false
AUTOPILOT=false
RESUME_SCAN=false
TARGETS_FILE=""
CLI_CONFIG=""
POSITIONAL=""
TOOL_MODE=""
EXPLORE_DIR=""
EXPORT_DIR=""
DIFF_OLD=""
DIFF_NEW=""
OUTPUTDIR_SET=false

usage() {
    echo
    printf "${BOLD}${GREEN}NmapReconFlow v${NMAPRF_VERSION}${NC}\n"
    echo
    printf "${RED}Usage: $(basename "$0") -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>\n"
    printf "${RED}       $(basename "$0") -f/--file ${NC}<TARGETS-FILE>${RED} -t/--type ${NC}<TYPE>\n"
    printf "${RED}       $(basename "$0") --explore ${NC}<RESULTS-DIR> [VIEW]\n"
    printf "${RED}       $(basename "$0") --export ${NC}<RESULTS-DIR>\n"
    printf "${RED}       $(basename "$0") --diff ${NC}<OLD-DIR> <NEW-DIR>\n"
    printf "${YELLOW}\nRequired:\n"
    printf "${YELLOW}  -H, --host ${NC}<TARGET>       ${YELLOW}Target IP, hostname, IPv6, or CIDR (CIDR runs as a campaign)\n"
    printf "${YELLOW}  -f, --file ${NC}<FILE>         ${YELLOW}File with targets (one per line; '-' reads stdin)\n"
    printf "${YELLOW}  -t, --type ${NC}<TYPE>         ${YELLOW}Scan type (see below)\n"
    printf "${YELLOW}\nOptional:\n"
    printf "${YELLOW}  -a, --autopilot            ${NC}Run unattended, no prompts\n"
    printf "${YELLOW}  -d, --dns ${NC}<DNS>            ${YELLOW}Custom DNS server\n"
    printf "${YELLOW}  -o, --output ${NC}<DIR>         ${YELLOW}Output directory\n"
    printf "${YELLOW}  -s, --static-nmap ${NC}<PATH>   ${YELLOW}Path to static nmap binary\n"
    printf "${YELLOW}  -r, --remote               ${NC}Remote mode (limited scans)\n"
    printf "${YELLOW}  -c, --config ${NC}<FILE>        ${YELLOW}Config file path\n"
    printf "${YELLOW}  -P, --parallel ${NC}<N>         ${YELLOW}Campaign parallelism (default: 1)\n"
    printf "${YELLOW}  -x, --exclude ${NC}<FILE>       ${YELLOW}Never scan IPs/CIDRs/hosts listed in FILE (scope control)\n"
    printf "${YELLOW}  --resume                   ${NC}Resume a previously interrupted scan\n"
    printf "${YELLOW}  --no-report                ${NC}Skip summary.md generation\n"
    printf "${YELLOW}  --no-exports               ${NC}Skip exports/ (CSV, URLs, host:port, port lists, merged XML)\n"
    printf "${YELLOW}  --format ${NC}<FORMAT>          ${YELLOW}Report format: markdown, json, or both (default: markdown)\n"
    printf "${YELLOW}  --dry-run                  ${NC}Show what would be executed without running scans\n"
    printf "${YELLOW}  --html                     ${NC}Also generate summary.html from nmap XML (needs xsltproc)\n"
    printf "${YELLOW}  --brute                    ${NC}Auto-run hydra against ssh/ftp/rdp (lockout risk!)\n"
    printf "${YELLOW}  --nuclei                   ${NC}Run nuclei templates against discovered web URLs\n"
    printf "${YELLOW}  --screenshots              ${NC}Screenshot discovered web URLs with gowitness\n"
    printf "${YELLOW}  --profile ${NC}<NAME>           ${YELLOW}Timing profile: stealth, normal, aggressive (default: normal)\n"
    printf "${YELLOW}  --per-port-dirs            ${NC}Group recon output under recon/<port>/ (AutoRecon-style)\n"
    printf "${YELLOW}  --no-color                 ${NC}Plain output (also: NO_COLOR=1; auto when not a terminal)\n"
    printf "${YELLOW}  -v, --version              ${NC}Print version\n"
    printf "${YELLOW}  -h, --help                 ${NC}Show this help\n"
    printf "${YELLOW}\nScan Types:\n"
    printf "${YELLOW}  Network  ${NC}Shows all live hosts in the host's network ${YELLOW}(~15 seconds)\n"
    printf "${YELLOW}  Port     ${NC}Shows all open ports ${YELLOW}(~15 seconds)\n"
    printf "${YELLOW}  Script   ${NC}Runs a script scan on found ports ${YELLOW}(~5 minutes)\n"
    printf "${YELLOW}  Full     ${NC}Full range port scan + script scan on new ports ${YELLOW}(~5-10 minutes)\n"
    printf "${YELLOW}  UDP      ${NC}Runs a UDP scan (requires root/sudo) ${YELLOW}(~5 minutes)\n"
    printf "${YELLOW}  Vulns    ${NC}Runs CVE scan and nmap Vulns scan ${YELLOW}(~5-15 minutes)\n"
    printf "${YELLOW}  Recon    ${NC}Suggests and runs recon tools on found services\n"
    printf "${YELLOW}  All      ${NC}Runs all scans ${YELLOW}(~20-30 minutes)\n"
    printf "${YELLOW}\nResults tools (no scanning, no nmap needed):\n"
    printf "${YELLOW}  --explore ${NC}<DIR> [VIEW]     ${YELLOW}Browse results (interactive menu on a terminal). Views:\n"
    printf "${NC}                             summary, hosts, ports [FILTER], services, urls, vulns,\n"
    printf "${NC}                             recon, show <FILE>, search <REGEX>, commands\n"
    printf "${YELLOW}  --export ${NC}<DIR>             ${YELLOW}(Re)build exports/ for a result or campaign directory\n"
    printf "${YELLOW}  --diff ${NC}<OLD> <NEW>         ${YELLOW}Compare two runs: new/closed ports, changed services\n"
    printf "${NC}\n"
    exit 1
}

# Require a value for flags that take one (catches `-H` at the end of the line).
need_arg() {
    if [ -z "${2:-}" ] || [[ "${2}" == -* && "${2}" != "-" ]]; then
        printf "${RED}Option $1 requires a value.${NC}\n" >&2
        usage
    fi
}

# Parse flags
while [ $# -gt 0 ]; do
    key="$1"
    case "${key}" in
        -H|--host)
            need_arg "$1" "${2:-}"; HOST="$2"; shift; shift ;;
        -t|--type)
            need_arg "$1" "${2:-}"; TYPE="$2"; shift; shift ;;
        -d|--dns)
            need_arg "$1" "${2:-}"; DNS="$2"; shift; shift ;;
        -o|--output)
            need_arg "$1" "${2:-}"; OUTPUTDIR="$2"; OUTPUTDIR_SET=true; shift; shift ;;
        -s|--static-nmap)
            need_arg "$1" "${2:-}"; NMAPPATH="$2"; shift; shift ;;
        -r|--remote)
            REMOTE=true; shift ;;
        -a|--autopilot)
            AUTOPILOT=true; shift ;;
        -f|--file)
            need_arg "$1" "${2:-}"; TARGETS_FILE="$2"; shift; shift ;;
        -P|--parallel)
            need_arg "$1" "${2:-}"; CAMPAIGN_PARALLEL="$2"; shift; shift ;;
        -c|--config)
            need_arg "$1" "${2:-}"; CLI_CONFIG="$2"; shift; shift ;;
        -x|--exclude)
            need_arg "$1" "${2:-}"; EXCLUDE_FILE="$2"; shift; shift ;;
        --no-report)
            GENERATE_REPORT=false; shift ;;
        --no-exports)
            GENERATE_EXPORTS=false; shift ;;
        --format)
            need_arg "$1" "${2:-}"; REPORT_FORMAT="$2"; shift; shift ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --resume)
            RESUME_SCAN=true; shift ;;
        --html)
            REPORT_HTML=true; shift ;;
        --brute)
            RUN_BRUTE=true; shift ;;
        --nuclei)
            RUN_NUCLEI=true; shift ;;
        --screenshots)
            RUN_SCREENSHOTS=true; shift ;;
        --profile)
            need_arg "$1" "${2:-}"; SCAN_PROFILE="$2"; shift; shift ;;
        --per-port-dirs)
            RECON_PER_PORT_DIRS=true; shift ;;
        --no-color)
            disable_colors; shift ;;
        --explore)
            need_arg "$1" "${2:-}"; TOOL_MODE="explore"; EXPLORE_DIR="$2"; shift; shift ;;
        --export)
            need_arg "$1" "${2:-}"; TOOL_MODE="export"; EXPORT_DIR="$2"; shift; shift ;;
        --diff)
            need_arg "$1" "${2:-}"; need_arg "$1" "${3:-}"
            TOOL_MODE="diff"; DIFF_OLD="$2"; DIFF_NEW="$3"; shift 3 ;;
        -v|--version)
            echo "NmapReconFlow v${NMAPRF_VERSION}"; exit 0 ;;
        -h|--help)
            usage ;;
        *)
            POSITIONAL="${POSITIONAL} $1"; shift ;;
    esac
done
# shellcheck disable=SC2086
set -- ${POSITIONAL}

# Load configuration
load_config

# Results tools: work on existing output, no scanning and no nmap required.
case "${TOOL_MODE}" in
    explore)
        explore_results "${EXPLORE_DIR}" "$@"
        exit $? ;;
    export)
        export_results_dir "${EXPORT_DIR}"
        exit $? ;;
    diff)
        diff_results "${DIFF_OLD}" "${DIFF_NEW}"
        exit $? ;;
esac

# Legacy positional args
[ -z "${HOST}" ] && HOST="$1"
[ -z "${TYPE}" ] && TYPE="$2"

# Legacy type aliases
case "${TYPE}" in
    [Qq]uick) TYPE="Port" ;;
    [Bb]asic) TYPE="Script" ;;
esac

if [ -n "${EXCLUDE_FILE}" ] && [ ! -f "${EXCLUDE_FILE}" ]; then
    printf "${RED}Exclude file not found: ${EXCLUDE_FILE}${NC}\n" >&2
    exit 1
fi
# Absolute path: campaign workers cd into per-target directories.
[ -n "${EXCLUDE_FILE}" ] && EXCLUDE_FILE="$(cd "$(dirname "${EXCLUDE_FILE}")" && pwd -P)/$(basename "${EXCLUDE_FILE}")"

if ! [[ "${CAMPAIGN_PARALLEL}" =~ ^[1-9][0-9]*$ ]]; then
    printf -- "${RED}--parallel must be a positive integer (got '${CAMPAIGN_PARALLEL}').${NC}\n" >&2
    exit 1
fi

# Set DNS
detect_dns_server

# Set output dir
[ -z "${OUTPUTDIR:-}" ] && OUTPUTDIR="${HOST:-campaign}"

# Detect nmap binary
detect_nmap_binary

# Run one phase unless --resume says it already finished.
run_phase() {
    local phase="$1" fn="$2"
    if $RESUME_SCAN && is_phase_completed "${phase}"; then
        skip_phase "${phase}" "resumed"
        return 0
    fi
    start_phase "${phase}"
    "${fn}" "${HOST}"
    end_phase "${phase}" $?
}

# Full pipeline for one target, run from inside its output directory. Defined
# before campaign dispatch: campaign workers call it too.
main() {
    # Traps are reset in subshells (campaign workers); re-arm so Ctrl+C or
    # TERM kills this target's tool process groups.
    install_signal_handlers

    assignPorts "${HOST}"
    init_phases "${TYPE}"
    header

    if $RESUME_SCAN; then
        load_phase_state
    fi

    case "${TYPE}" in
        [Nn]etwork)
            run_phase "Network" networkScan
            ;;
        [Pp]ort)
            run_phase "Port" portScan
            ;;
        [Ss]cript)
            [ -f "nmap/Port_${HOST}.nmap" ] || run_phase "Port" portScan
            run_phase "Script" scriptScan
            ;;
        [Ff]ull)
            run_phase "Full" fullScan
            ;;
        [Uu][Dd][Pp])
            run_phase "UDP" UDPScan
            ;;
        [Vv]ulns)
            [ -f "nmap/Port_${HOST}.nmap" ] || run_phase "Port" portScan
            run_phase "Vulns" vulnsScan
            ;;
        [Rr]econ)
            [ -f "nmap/Port_${HOST}.nmap" ] || run_phase "Port" portScan
            [ -f "nmap/Script_${HOST}.nmap" ] || run_phase "Script" scriptScan
            run_phase "Recon" recon
            ;;
        [Aa]ll)
            run_phase "Port" portScan
            run_phase "Script" scriptScan
            run_phase "Full" fullScan
            run_phase "UDP" UDPScan
            run_phase "Vulns" vulnsScan
            run_phase "Recon" recon
            ;;
    esac

    footer
    generate_report "${HOST}"
    if [ "${GENERATE_EXPORTS}" = "true" ] && ! ${DRY_RUN}; then
        generate_exports "${HOST}"
    fi
}

# Campaign output root: -o DIR if given, else the current directory.
CAMPAIGN_ROOT="."
${OUTPUTDIR_SET} && CAMPAIGN_ROOT="${OUTPUTDIR}"

# `-f -`: read targets from stdin, e.g. `echo 10.0.0.1 | nmapReconFlow.sh -f - -t Port`
# or `cat scope.txt | ...`. Copied to a temp file first (stdin is then free
# for the interactive recon prompt, and campaign workers can re-read it).
if [ "${TARGETS_FILE}" = "-" ]; then
    _stdin_targets="$(mktemp "${TMPDIR:-/tmp}/nmaprf_stdin.XXXXXX")"
    cat > "${_stdin_targets}"
    TARGETS_FILE="${_stdin_targets}"
    trap 'rm -f "${_stdin_targets}"' EXIT
    # Stdin was a pipe: there is nobody to answer prompts.
    AUTOPILOT=true
fi

# Campaign mode
if [ -n "${TARGETS_FILE}" ]; then
    if [ -z "${TYPE}" ]; then
        printf "${RED}Scan type is required. Use -t/--type <TYPE>\n${NC}"
        usage
    fi
    if is_valid_scan_type "${TYPE}"; then
        run_campaign "${TARGETS_FILE}"
        exit $?
    else
        printf "${RED}Invalid scan type: ${TYPE}\n${NC}"
        usage
    fi
fi

# Single target mode - validate args
if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then
    usage
fi

# CIDR range: expand into a campaign of individual hosts
if is_cidr "${HOST}"; then
    if ! is_valid_scan_type "${TYPE}"; then
        printf "${RED}Invalid scan type: ${TYPE}\n${NC}"
        usage
    fi
    if $REMOTE; then
        printf "${RED}\nCIDR expansion needs nmap (not available in Remote mode).\n${NC}"
        exit 1
    fi
    _cidr_targets="$(mktemp "${TMPDIR:-/tmp}/nmaprf_targets.XXXXXX")"
    expand_cidr "${HOST}" > "${_cidr_targets}"
    if [ ! -s "${_cidr_targets}" ]; then
        rm -f "${_cidr_targets}"
        printf "${RED}\nCould not expand CIDR range: ${HOST}\n${NC}"
        usage
    fi
    printf "${GREEN}Expanded ${HOST} into $(($(wc -l < "${_cidr_targets}"))) hosts; running as campaign.${NC}\n"
    run_campaign "${_cidr_targets}"
    _rc=$?
    rm -f "${_cidr_targets}"
    exit ${_rc}
fi

# Validate host format (IPv4, IPv6, or hostname)
if ! is_ipv4 "${HOST}" && ! is_ipv6 "${HOST}" && ! is_hostname "${HOST}"; then
    printf "${RED}\nInvalid IP or URL!\n${NC}"
    usage
fi

if ! validate_host_safe "${HOST}"; then
    printf "${RED}\nHost contains unsafe characters!\n${NC}"
    usage
fi

if is_excluded "${HOST}"; then
    printf "${RED}\n${HOST} is listed in the exclude file (${EXCLUDE_FILE}); refusing to scan.\n${NC}"
    exit 1
fi

# Validate scan type
if ! is_valid_scan_type "${TYPE}"; then
    printf "${RED}\nInvalid Type!\n${NC}"
    usage
fi

mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage

# main runs in THIS shell (not a pipeline subshell) so its CHILD_PIDS are
# visible to our INT/TERM trap; output is mirrored to the run log via tee.
main > >(tee "nmapReconFlow_${HOST}_${TYPE}.txt")
_rc=$?
# Let tee flush before we print anything else (bash 4.4+ can wait on it).
_tee_pid=$!
wait "${_tee_pid}" 2>/dev/null || true

send_notification "NmapReconFlow: ${TYPE} scan of ${HOST} complete. Results in ${OUTPUTDIR}/"
exit ${_rc}
