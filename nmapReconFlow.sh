#!/usr/bin/env bash
# NmapReconFlow - Automated reconnaissance workflow
# Based on nmapAutomator by @21y4d
# https://github.com/whatsdd/NmapReconFlow

set -o pipefail

if [ -z "${BASH_VERSINFO[0]:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] || \
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
    printf "NmapReconFlow requires bash 4.3+. Current: %s\n" "${BASH_VERSION:-unknown}" >&2
    printf "macOS users: brew install bash\n" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for _lib in config timeout ui utils scans recon report campaign; do
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

usage() {
    echo
    printf "${BOLD}${GREEN}NmapReconFlow v${NMAPRF_VERSION}${NC}\n"
    echo
    printf "${RED}Usage: $(basename "$0") -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>\n"
    printf "${RED}       $(basename "$0") -f/--file ${NC}<TARGETS-FILE>${RED} -t/--type ${NC}<TYPE>\n"
    printf "${YELLOW}\nRequired:\n"
    printf "${YELLOW}  -H, --host ${NC}<TARGET>       ${YELLOW}Target IP, hostname, IPv6, or CIDR (CIDR runs as a campaign)\n"
    printf "${YELLOW}  -f, --file ${NC}<FILE>         ${YELLOW}File with targets (one per line)\n"
    printf "${YELLOW}  -t, --type ${NC}<TYPE>         ${YELLOW}Scan type (see below)\n"
    printf "${YELLOW}\nOptional:\n"
    printf "${YELLOW}  -a, --autopilot            ${NC}Run unattended, no prompts\n"
    printf "${YELLOW}  -d, --dns ${NC}<DNS>            ${YELLOW}Custom DNS server\n"
    printf "${YELLOW}  -o, --output ${NC}<DIR>         ${YELLOW}Output directory\n"
    printf "${YELLOW}  -s, --static-nmap ${NC}<PATH>   ${YELLOW}Path to static nmap binary\n"
    printf "${YELLOW}  -r, --remote               ${NC}Remote mode (limited scans)\n"
    printf "${YELLOW}  -c, --config ${NC}<FILE>        ${YELLOW}Config file path\n"
    printf "${YELLOW}  -P, --parallel ${NC}<N>         ${YELLOW}Campaign parallelism (default: 1)\n"
    printf "${YELLOW}  --resume                   ${NC}Resume a previously interrupted scan\n"
    printf "${YELLOW}  --no-report                ${NC}Skip summary.md generation\n"
    printf "${YELLOW}  --format ${NC}<FORMAT>          ${YELLOW}Report format: markdown, json, or both (default: markdown)\n"
    printf "${YELLOW}  --dry-run                  ${NC}Show what would be executed without running scans\n"
    printf "${YELLOW}  --html                     ${NC}Also generate summary.html from nmap XML (needs xsltproc)\n"
    printf "${YELLOW}  --brute                    ${NC}Auto-run hydra against ssh/ftp/rdp (lockout risk!)\n"
    printf "${YELLOW}  --profile ${NC}<NAME>           ${YELLOW}Timing profile: stealth, normal, aggressive (default: normal)\n"
    printf "${YELLOW}  --per-port-dirs            ${NC}Group recon output under recon/<port>/ (AutoRecon-style)\n"
    printf "${YELLOW}  -v, --version              ${NC}Print version\n"
    printf "${YELLOW}  -h, --help                 ${NC}Show this help\n"
    printf "${YELLOW}\nScan Types:\n"
    printf "${YELLOW}  Network  ${NC}Shows all live hosts in the host's network ${YELLOW}(~15 seconds)\n"
    printf "${YELLOW}  Port     ${NC}Shows all open ports ${YELLOW}(~15 seconds)\n"
    printf "${YELLOW}  Script   ${NC}Runs a script scan on found ports ${YELLOW}(~5 minutes)\n"
    printf "${YELLOW}  Full     ${NC}Full range port scan + script scan on new ports ${YELLOW}(~5-10 minutes)\n"
    printf "${YELLOW}  UDP      ${NC}Runs a UDP scan (requires sudo) ${YELLOW}(~5 minutes)\n"
    printf "${YELLOW}  Vulns    ${NC}Runs CVE scan and nmap Vulns scan ${YELLOW}(~5-15 minutes)\n"
    printf "${YELLOW}  Recon    ${NC}Suggests and runs recon tools on found services\n"
    printf "${YELLOW}  All      ${NC}Runs all scans ${YELLOW}(~20-30 minutes)\n"
    printf "${NC}\n"
    exit 1
}

# Parse flags
while [ $# -gt 0 ]; do
    key="$1"
    case "${key}" in
        -H|--host)
            HOST="$2"; shift; shift ;;
        -t|--type)
            TYPE="$2"; shift; shift ;;
        -d|--dns)
            DNS="$2"; shift; shift ;;
        -o|--output)
            OUTPUTDIR="$2"; shift; shift ;;
        -s|--static-nmap)
            NMAPPATH="$2"; shift; shift ;;
        -r|--remote)
            REMOTE=true; shift ;;
        -a|--autopilot)
            AUTOPILOT=true; shift ;;
        -f|--file)
            TARGETS_FILE="$2"; shift; shift ;;
        -P|--parallel)
            CAMPAIGN_PARALLEL="$2"; shift; shift ;;
        -c|--config)
            CLI_CONFIG="$2"; shift; shift ;;
        --no-report)
            GENERATE_REPORT=false; shift ;;
        --format)
            REPORT_FORMAT="$2"; shift; shift ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --resume)
            RESUME_SCAN=true; shift ;;
        --html)
            REPORT_HTML=true; shift ;;
        --brute)
            RUN_BRUTE=true; shift ;;
        --profile)
            SCAN_PROFILE="$2"; shift; shift ;;
        --per-port-dirs)
            RECON_PER_PORT_DIRS=true; shift ;;
        -v|--version)
            echo "NmapReconFlow v${NMAPRF_VERSION}"; exit 0 ;;
        -h|--help)
            usage ;;
        *)
            POSITIONAL="${POSITIONAL} $1"; shift ;;
    esac
done
set -- ${POSITIONAL}

# Legacy positional args
[ -z "${HOST}" ] && HOST="$1"
[ -z "${TYPE}" ] && TYPE="$2"

# Legacy type aliases
case "${TYPE}" in
    [Qq]uick) TYPE="Port" ;;
    [Bb]asic) TYPE="Script" ;;
esac

# Load configuration
load_config

# Set DNS
detect_dns_server

# Set output dir
[ -z "${OUTPUTDIR:-}" ] && OUTPUTDIR="${HOST:-campaign}"

# Detect nmap binary
detect_nmap_binary

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
    _cidr_targets="$(mktemp "${TMPDIR:-/tmp}/nmaprf_targets.XXXXXX")"
    expand_cidr "${HOST}" > "${_cidr_targets}"
    if [ ! -s "${_cidr_targets}" ]; then
        rm -f "${_cidr_targets}"
        printf "${RED}\nCould not expand CIDR range: ${HOST}\n${NC}"
        usage
    fi
    printf "${GREEN}Expanded ${HOST} into $(wc -l < "${_cidr_targets}") hosts; running as campaign.${NC}\n"
    run_campaign "${_cidr_targets}"
    _rc=$?
    rm -f "${_cidr_targets}"
    exit ${_rc}
fi

# Validate host format (IPv4, IPv6, or hostname)
if ! [[ "${HOST}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && \
   ! is_ipv6 "${HOST}" && \
   ! [[ "${HOST}" =~ ^(([[:alnum:]-]{1,63}\.)*[[:alpha:]]{2,6})$ ]]; then
    printf "${RED}\nInvalid IP or URL!\n${NC}"
    usage
fi

if ! validate_host_safe "${HOST}"; then
    printf "${RED}\nHost contains unsafe characters!\n${NC}"
    usage
fi

# Validate scan type
if is_valid_scan_type "${TYPE}"; then
    mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage

    main() {
        assignPorts "${HOST}"
        init_phases "${TYPE}"
        header

        if $RESUME_SCAN; then
            load_phase_state
        fi

        case "${TYPE}" in
            [Nn]etwork)
                if ! $RESUME_SCAN || ! is_phase_completed "Network"; then
                    start_phase "Network"
                    networkScan "${HOST}"
                    end_phase "Network" $?
                else
                    skip_phase "Network" "resumed"
                fi
                ;;
            [Pp]ort)
                if ! $RESUME_SCAN || ! is_phase_completed "Port"; then
                    start_phase "Port"
                    portScan "${HOST}"
                    end_phase "Port" $?
                else
                    skip_phase "Port" "resumed"
                fi
                ;;
            [Ss]cript)
                if [ ! -f "nmap/Port_${HOST}.nmap" ]; then
                    if ! $RESUME_SCAN || ! is_phase_completed "Port"; then
                        start_phase "Port"
                        portScan "${HOST}"
                        end_phase "Port" $?
                    else
                        skip_phase "Port" "resumed"
                    fi
                fi
                if ! $RESUME_SCAN || ! is_phase_completed "Script"; then
                    start_phase "Script"
                    scriptScan "${HOST}"
                    end_phase "Script" $?
                else
                    skip_phase "Script" "resumed"
                fi
                ;;
            [Ff]ull)
                if ! $RESUME_SCAN || ! is_phase_completed "Full"; then
                    start_phase "Full"
                    fullScan "${HOST}"
                    end_phase "Full" $?
                else
                    skip_phase "Full" "resumed"
                fi
                ;;
            [Uu][Dd][Pp])
                if ! $RESUME_SCAN || ! is_phase_completed "UDP"; then
                    start_phase "UDP"
                    UDPScan "${HOST}"
                    end_phase "UDP" $?
                else
                    skip_phase "UDP" "resumed"
                fi
                ;;
            [Vv]ulns)
                if [ ! -f "nmap/Port_${HOST}.nmap" ]; then
                    if ! $RESUME_SCAN || ! is_phase_completed "Port"; then
                        start_phase "Port"
                        portScan "${HOST}"
                        end_phase "Port" $?
                    else
                        skip_phase "Port" "resumed"
                    fi
                fi
                if ! $RESUME_SCAN || ! is_phase_completed "Vulns"; then
                    start_phase "Vulns"
                    vulnsScan "${HOST}"
                    end_phase "Vulns" $?
                else
                    skip_phase "Vulns" "resumed"
                fi
                ;;
            [Rr]econ)
                if [ ! -f "nmap/Port_${HOST}.nmap" ]; then
                    if ! $RESUME_SCAN || ! is_phase_completed "Port"; then
                        start_phase "Port"
                        portScan "${HOST}"
                        end_phase "Port" $?
                    else
                        skip_phase "Port" "resumed"
                    fi
                fi
                if [ ! -f "nmap/Script_${HOST}.nmap" ]; then
                    if ! $RESUME_SCAN || ! is_phase_completed "Script"; then
                        start_phase "Script"
                        scriptScan "${HOST}"
                        end_phase "Script" $?
                    else
                        skip_phase "Script" "resumed"
                    fi
                fi
                if ! $RESUME_SCAN || ! is_phase_completed "Recon"; then
                    start_phase "Recon"
                    recon "${HOST}"
                    end_phase "Recon" $?
                else
                    skip_phase "Recon" "resumed"
                fi
                ;;
            [Aa]ll)
                if ! $RESUME_SCAN || ! is_phase_completed "Port"; then
                    start_phase "Port"
                    portScan "${HOST}"
                    end_phase "Port" $?
                else
                    skip_phase "Port" "resumed"
                fi

                if ! $RESUME_SCAN || ! is_phase_completed "Script"; then
                    start_phase "Script"
                    scriptScan "${HOST}"
                    end_phase "Script" $?
                else
                    skip_phase "Script" "resumed"
                fi

                if ! $RESUME_SCAN || ! is_phase_completed "Full"; then
                    start_phase "Full"
                    fullScan "${HOST}"
                    end_phase "Full" $?
                else
                    skip_phase "Full" "resumed"
                fi

                if ! $RESUME_SCAN || ! is_phase_completed "UDP"; then
                    start_phase "UDP"
                    UDPScan "${HOST}"
                    end_phase "UDP" $?
                else
                    skip_phase "UDP" "resumed"
                fi

                if ! $RESUME_SCAN || ! is_phase_completed "Vulns"; then
                    start_phase "Vulns"
                    vulnsScan "${HOST}"
                    end_phase "Vulns" $?
                else
                    skip_phase "Vulns" "resumed"
                fi

                if ! $RESUME_SCAN || ! is_phase_completed "Recon"; then
                    start_phase "Recon"
                    recon "${HOST}"
                    end_phase "Recon" $?
                else
                    skip_phase "Recon" "resumed"
                fi
                ;;
        esac

        footer
        generate_report "${HOST}"
    }

    main | tee "nmapReconFlow_${HOST}_${TYPE}.txt"

    send_notification "NmapReconFlow: ${TYPE} scan of ${HOST} complete. Results in ${OUTPUTDIR}/"
else
    printf "${RED}\nInvalid Type!\n${NC}"
    usage
fi
