#!/usr/bin/env bash
# NmapReconFlow - UI: colors, progress bar, dashboard

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

IS_TTY=false
[ -t 1 ] && IS_TTY=true

declare -a SCAN_PHASES=()
declare -A PHASE_STATUS=()
declare -A PHASE_START=()
declare -A PHASE_END=()
declare -A PHASE_NOTE=()

init_phases() {
    local type="$1"
    SCAN_PHASES=()
    case "$type" in
        [Nn]etwork) SCAN_PHASES=("Network") ;;
        [Pp]ort)    SCAN_PHASES=("Port") ;;
        [Ss]cript)  SCAN_PHASES=("Port" "Script") ;;
        [Ff]ull)    SCAN_PHASES=("Full") ;;
        [Uu][Dd][Pp]) SCAN_PHASES=("UDP") ;;
        [Vv]ulns)   SCAN_PHASES=("Port" "Vulns") ;;
        [Rr]econ)   SCAN_PHASES=("Port" "Script" "Recon") ;;
        [Aa]ll)     SCAN_PHASES=("Port" "Script" "Full" "UDP" "Vulns" "Recon") ;;
    esac
    for phase in "${SCAN_PHASES[@]}"; do
        PHASE_STATUS["$phase"]="pending"
    done
}

start_phase() {
    local phase="$1"
    PHASE_STATUS["$phase"]="running"
    PHASE_START["$phase"]="$(date +%s)"
    render_dashboard
}

end_phase() {
    local phase="$1"
    local rc="${2:-0}"
    PHASE_END["$phase"]="$(date +%s)"
    if [ "$rc" -eq 124 ]; then
        PHASE_STATUS["$phase"]="timeout"
    elif [ "$rc" -ne 0 ]; then
        PHASE_STATUS["$phase"]="error"
    else
        PHASE_STATUS["$phase"]="done"
    fi
    save_phase_state "$phase" "${PHASE_STATUS[$phase]}"
    render_dashboard
}

skip_phase() {
    local phase="$1"
    local reason="${2:-}"
    PHASE_STATUS["$phase"]="skipped"
    PHASE_NOTE["$phase"]="$reason"
    render_dashboard
}

save_phase_state() {
    local phase="$1"
    local status="$2"
    echo "${phase}=${status}" >> ".nmapReconFlow.state"
}

load_phase_state() {
    declare -gA COMPLETED_PHASES=()
    [ -f ".nmapReconFlow.state" ] || return 0
    while IFS='=' read -r phase status; do
        [ -n "$phase" ] && COMPLETED_PHASES["$phase"]="$status"
    done < ".nmapReconFlow.state"
}

is_phase_completed() {
    local phase="$1"
    [ "${COMPLETED_PHASES[$phase]:-}" = "done" ]
}

format_duration() {
    local secs="$1"
    printf '%02d:%02d' $((secs / 60)) $((secs % 60))
}

render_dashboard() {
    $IS_TTY || return 0

    local total=${#SCAN_PHASES[@]}
    [ "$total" -eq 0 ] && return 0

    local done_count=0
    local dashboard=""

    dashboard+="\033[1m=== NmapReconFlow Dashboard === Target: ${HOST} ===\033[0m\n"

    for phase in "${SCAN_PHASES[@]}"; do
        local status="${PHASE_STATUS[$phase]:-pending}"
        local icon="" color=""
        case "$status" in
            pending) icon="[ ]"; color="${NC}" ;;
            running) icon="[>]"; color="${YELLOW}" ;;
            done)    icon="[x]"; color="${GREEN}"; ((done_count++)) ;;
            timeout) icon="[!]"; color="${RED}"; ((done_count++)) ;;
            error)   icon="[E]"; color="${RED}"; ((done_count++)) ;;
            skipped) icon="[-]"; color="${BLUE}"; ((done_count++)) ;;
        esac

        local elapsed=""
        if [ -n "${PHASE_START[$phase]:-}" ]; then
            local end_time="${PHASE_END[$phase]:-$(date +%s)}"
            local secs=$((end_time - PHASE_START[$phase]))
            elapsed="$(format_duration "$secs")"
        fi

        local note="${PHASE_NOTE[$phase]:-}"
        [ -n "$note" ] && note=" (${note})"

        dashboard+=" ${color}${icon} $(printf '%-10s' "$phase") ${elapsed}${note}${NC}\n"
    done

    dashboard+=" Progress: ${done_count}/${total} phases complete\n"
    dashboard+="\n"

    printf "$dashboard" >&2
}

progressBar() {
    [ -z "${2##*[!0-9]*}" ] && return 1
    local cols
    cols="$(stty size 2>/dev/null | cut -d ' ' -f 2)"
    [ -z "$cols" ] && cols=80
    local width=50
    [ "$cols" -gt 120 ] && width=100
    local filled=$((width == 100 ? $2 : ($2 / 2)))
    local empty=$((width - filled))
    local fill="$(printf "%-${filled}s" "#" | tr ' ' '#')"
    local space="$(printf "%-${empty}s" " ")"
    printf "In progress: $1 Scan ($3 elapsed - $4 remaining)   \n"
    printf "[${fill}>${space}] $2%% done   \n"
    printf "\033[2A"
}

nmapProgressBar() {
    local output_file="$1"
    local refreshRate="${2:-1}"
    local timeout_secs="${3:-${TIMEOUT_NMAP_PORT}}"
    shift 3
    local outputFile="${output_file}"
    local tmpOutputFile="${outputFile}.tmp"
    local start_epoch nmap_rc=0 timed_out=false
    start_epoch="$(date +%s)"

    if $DRY_RUN; then
        printf "${YELLOW}[DRY-RUN] Would execute: %s${NC}\n" "$*" >&2
        return 0
    fi

    if [ ! -e "${outputFile}" ]; then
        "$@" --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
        local nmap_pid=$!
        CHILD_PIDS["$nmap_pid"]=1
    fi

    while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}" 2>/dev/null; } && \
          { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}" 2>/dev/null; }; do

        local now_epoch
        now_epoch="$(date +%s)"
        local elapsed_secs=$((now_epoch - start_epoch))
        if [ "$timeout_secs" -gt 0 ] && [ "$elapsed_secs" -ge "$timeout_secs" ]; then
            if [ -n "${nmap_pid:-}" ] && kill -0 "$nmap_pid" 2>/dev/null; then
                _kill_tree "$nmap_pid" TERM
                sleep 2
                _kill_tree "$nmap_pid" KILL
            fi
            log_warning "nmap scan timed out after ${timeout_secs}s"
            timed_out=true
            break
        fi

        local scanType percent elapsed remaining
        scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -n '/elapsed/s/.*undergoing \(.*\) Scan.*/\1/p')"
        percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -n '/% done/s/.*About \(.*\)\..*% done.*/\1/p')"
        elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -n '/elapsed/s/Stats: \(.*\) elapsed.*/\1/p')"
        remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -n '/remaining/s/.* (\(.*\) remaining.*/\1/p')"
        progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
        sleep "${refreshRate}"
    done
    printf "\033[0K\r\n\033[0K\r\n"

    if [ -n "${nmap_pid:-}" ]; then
        wait "$nmap_pid" 2>/dev/null
        nmap_rc=$?
        unset CHILD_PIDS["$nmap_pid"]
    fi

    if [ -e "${outputFile}" ]; then
        awk '/PORT.*STATE.*SERVICE/{found=1} found{if(/^# Nmap/){exit}; print}' "${outputFile}" | awk '!/^SF(:|-)/' | grep -v 'service unrecognized despite'
    else
        cat "${tmpOutputFile}"
    fi
    rm -f "${tmpOutputFile}"

    $timed_out && return 124
    return $nmap_rc
}

log_warning() {
    printf "${YELLOW}[WARNING] $1${NC}\n" >&2
}

log_error() {
    printf "${RED}[ERROR] $1${NC}\n" >&2
}

log_info() {
    printf "${GREEN}[INFO] $1${NC}\n" >&2
}
