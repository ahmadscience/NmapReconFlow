#!/usr/bin/env bash
# NmapReconFlow - UI: colors, progress bar, dashboard

IS_TTY=false
[ -t 1 ] && IS_TTY=true

# ANSI colors only on a terminal. Piped output, cron/CI logs and NO_COLOR
# (https://no-color.org) get plain text. FORCE_COLOR=1 overrides.
enable_colors() {
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
}
disable_colors() {
    RED='' YELLOW='' GREEN='' BLUE='' BOLD='' NC=''
}
if [ -n "${FORCE_COLOR:-}" ]; then
    enable_colors
elif [ -n "${NO_COLOR:-}" ] || ! ${IS_TTY}; then
    disable_colors
else
    enable_colors
fi

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
    elif [ "$rc" -eq 125 ]; then
        # Phase chose not to run (e.g. UDP without root/sudo in autopilot)
        PHASE_STATUS["$phase"]="skipped"
        [ -z "${PHASE_NOTE[$phase]:-}" ] && PHASE_NOTE["$phase"]="not runnable"
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

    dashboard+="${BOLD}=== NmapReconFlow Dashboard === Target: ${HOST} ===${NC}\n"

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

# Draws to stderr, and only on a terminal: stdout is tee'd into the run log,
# where a redrawn progress bar would just be thousands of junk lines.
progressBar() {
    $IS_TTY || return 0
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
    {
        printf "In progress: $1 Scan ($3 elapsed - $4 remaining)   \n"
        printf "[${fill}>${space}] $2%% done   \n"
        printf "\033[2A"
    } >&2
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

    # A partial result from an interrupted run (no "Nmap done" footer) would
    # otherwise be waited on until the timeout: discard it and re-scan.
    if [ -e "${outputFile}" ] && ! grep -q "Nmap done at" "${outputFile}" 2>/dev/null; then
        rm -f "${outputFile}" "${outputFile%.nmap}.xml" "${outputFile%.nmap}.gnmap"
    fi

    local nmap_pid=""
    if [ ! -e "${outputFile}" ]; then
        # Own process group so timeouts/Ctrl+C kill nmap and its helpers.
        _spawn_group "$@" --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1
        nmap_pid="${SPAWNED_PID}"
        CHILD_PIDS["$nmap_pid"]=1
    fi

    while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}" 2>/dev/null; } && \
          { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}" 2>/dev/null; }; do

        # nmap exited without writing "Nmap done"/"QUITTING" (bad target,
        # resolution failure, crash): stop waiting instead of spinning until
        # the timeout.
        if [ -n "${nmap_pid}" ] && ! kill -0 "$nmap_pid" 2>/dev/null; then
            break
        fi

        local now_epoch
        now_epoch="$(date +%s)"
        local elapsed_secs=$((now_epoch - start_epoch))
        if [ "$timeout_secs" -gt 0 ] && [ "$elapsed_secs" -ge "$timeout_secs" ]; then
            if [ -n "${nmap_pid}" ] && kill -0 "$nmap_pid" 2>/dev/null; then
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
    $IS_TTY && printf "\033[0K\r\n\033[0K\r\n" >&2

    if [ -n "${nmap_pid}" ]; then
        wait "$nmap_pid" 2>/dev/null
        nmap_rc=$?
        unset 'CHILD_PIDS[$nmap_pid]'
    fi

    if [ -e "${outputFile}" ]; then
        awk '/PORT.*STATE.*SERVICE/{found=1} found{if(/^# Nmap/){exit}; print}' "${outputFile}" \
            | awk '!/^SF(:|-)/ && !/^Read data files from:/' | grep -v 'service unrecognized despite'
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

# Send a completion notification to NOTIFY_WEBHOOK, if configured.
# Supports Slack/Discord incoming webhooks and a generic {"text": ...} JSON.
send_notification() {
    local message="$1"
    [ -z "${NOTIFY_WEBHOOK:-}" ] && return 0
    command -v curl >/dev/null 2>&1 || { log_warning "NOTIFY_WEBHOOK set but curl not found"; return 0; }

    if ${DRY_RUN:-false}; then
        printf "${YELLOW}[DRY-RUN] Would notify: %s${NC}\n" "${message}" >&2
        return 0
    fi

    # JSON-escape the message (backslash, double-quote, newline).
    local esc="${message//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    esc="${esc//$'\n'/\\n}"

    local payload
    case "${NOTIFY_STYLE:-slack}" in
        discord) payload="{\"content\": \"${esc}\"}" ;;
        slack)   payload="{\"text\": \"${esc}\"}" ;;
        *)       payload="{\"text\": \"${esc}\"}" ;;
    esac

    curl -s -m 15 -X POST -H 'Content-Type: application/json' \
        -d "${payload}" "${NOTIFY_WEBHOOK}" >/dev/null 2>&1 \
        && log_info "Notification sent" \
        || log_warning "Failed to send notification"
}
