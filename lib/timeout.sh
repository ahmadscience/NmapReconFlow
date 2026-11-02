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

# Start "$@" in the background as the leader of a new process group, so the
# whole tree (e.g. nmap NSE helpers, ffuf workers, `tool | tee`) can be killed
# with one group signal. Sets SPAWNED_PID. Must be called directly (not inside
# $(...)) so the job is a child of the current shell. Redirections given to
# this function apply to the spawned command.
#   1. perl setpgrp(): new group, SAME session/controlling tty, so a cached
#      `sudo -v` ticket keeps working (UDP scans). perl is on macOS and is
#      Essential (perl-base) on Debian/Ubuntu/Kali.
#   2. util-linux setsid: new session (drops the tty) - fine for recon tools.
#   3. plain background job: single-PID kill fallback.
_spawn_group() {
    if command -v perl >/dev/null 2>&1; then
        perl -e 'setpgrp(0, 0); exec { $ARGV[0] } @ARGV or die "exec $ARGV[0]: $!\n"' "$@" &
    elif command -v setsid >/dev/null 2>&1; then
        setsid "$@" &
    else
        "$@" &
    fi
    SPAWNED_PID=$!
}

# Run a command with a wall-clock timeout
# Returns: 0 on success, 124 on timeout, or the command's exit code
run_with_timeout() {
    local timeout_secs="$1"
    local label="$2"
    shift 2

    if ! [[ "${timeout_secs}" =~ ^[0-9]+$ ]] || [ "$timeout_secs" -le 0 ]; then
        "$@"
        return $?
    fi

    _spawn_group "$@"
    local child_pid="${SPAWNED_PID}"
    CHILD_PIDS["$child_pid"]=1

    # Watchdog. Its sleep runs as a tracked child that is killed with the
    # watchdog (an orphaned `sleep N` would linger for N seconds), and its
    # stdout is detached so it never holds the run-log pipe (tee) open.
    (
        sleep "$timeout_secs" &
        _wd_sleep=$!
        trap 'kill "${_wd_sleep}" 2>/dev/null; exit 0' TERM
        wait "${_wd_sleep}"
        if kill -0 "$child_pid" 2>/dev/null; then
            log_warning "${label} exceeded timeout (${timeout_secs}s). Sending SIGTERM..."
            _kill_tree "$child_pid" TERM
            sleep 5
            if kill -0 "$child_pid" 2>/dev/null; then
                log_warning "${label} did not respond to SIGTERM. Sending SIGKILL..."
                _kill_tree "$child_pid" KILL
            fi
        fi
    ) >/dev/null &
    local watchdog_pid=$!
    CHILD_PIDS["$watchdog_pid"]=1

    wait "$child_pid" 2>/dev/null
    local exit_code=$?

    kill "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null

    unset 'CHILD_PIDS[$watchdog_pid]'
    unset 'CHILD_PIDS[$child_pid]'

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
    local pid
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

# Bash resets caught traps in subshells (pipelines, ( ... ), campaign workers),
# so every shell that tracks CHILD_PIDS must call this itself.
install_signal_handlers() {
    _CLEANUP_RUNNING=false
    trap 'cleanup_and_exit' INT TERM HUP
}
