#!/usr/bin/env bash
# NmapReconFlow - Timeout management and signal handling

declare -A CHILD_PIDS=()
_CLEANUP_RUNNING=false

_kill_tree() {
    local pid="$1"
    local sig="${2:-TERM}"
    kill -0 "$pid" 2>/dev/null || return 0
    # Kill the process group if possible, fall back to single PID
    kill -"$sig" -- -"$pid" 2>/dev/null || kill -"$sig" "$pid" 2>/dev/null || true
}

# Run a command with a wall-clock timeout
# Returns: 0 on success, 124 on timeout, or the command's exit code
run_with_timeout() {
    local timeout_secs="$1"
    local label="$2"
    shift 2

    if [ "$timeout_secs" -le 0 ]; then
        "$@"
        return $?
    fi

    setsid "$@" &
    local child_pid=$!
    CHILD_PIDS["$child_pid"]=1

    (
        sleep "$timeout_secs"
        if kill -0 "$child_pid" 2>/dev/null; then
            log_warning "${label} exceeded timeout (${timeout_secs}s). Sending SIGTERM..."
            _kill_tree "$child_pid" TERM
            sleep 5
            if kill -0 "$child_pid" 2>/dev/null; then
                log_warning "${label} did not respond to SIGTERM. Sending SIGKILL..."
                _kill_tree "$child_pid" KILL
            fi
        fi
    ) &
    local watchdog_pid=$!
    CHILD_PIDS["$watchdog_pid"]=1

    wait "$child_pid" 2>/dev/null
    local exit_code=$?

    kill "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null

    unset CHILD_PIDS["$watchdog_pid"]
    unset CHILD_PIDS["$child_pid"]

    if [ $exit_code -eq 137 ] || [ $exit_code -eq 143 ]; then
        log_warning "${label} was killed after ${timeout_secs}s timeout"
        return 124
    fi
    return $exit_code
}

cleanup_and_exit() {
    $_CLEANUP_RUNNING && return
    _CLEANUP_RUNNING=true

    printf "\n${RED}Interrupted. Cleaning up background processes...${NC}\n" >&2
    for pid in "${!CHILD_PIDS[@]}"; do
        _kill_tree "$pid" TERM
    done
    sleep 2
    for pid in "${!CHILD_PIDS[@]}"; do
        _kill_tree "$pid" KILL
    done
    rm -f nmap/*.tmp 2>/dev/null
    printf "${YELLOW}Cleanup complete.${NC}\n" >&2
    exit 130
}

install_signal_handlers() {
    trap 'cleanup_and_exit' INT TERM
}
