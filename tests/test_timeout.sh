#!/usr/bin/env bash
# Tests for lib/timeout.sh

# --- run_with_timeout: exit codes ---
assert_exit 0 run_with_timeout 10 "true" true
assert_exit 3 run_with_timeout 10 "exit3" sh -c 'exit 3'
assert_exit 124 run_with_timeout 1 "sleeper" sleep 8
assert_exit 0 run_with_timeout 0 "no-timeout" true

# --- run_with_timeout: output passes through ---
assert_eq "hello" "$(run_with_timeout 10 echo echo hello 2>/dev/null)" "run_with_timeout: stdout preserved"

# --- watchdog leaves no orphaned `sleep <timeout>` behind ---
run_with_timeout 47 "quick" true
sleep 0.3
assert_eq "0" "$(ps -A -o args 2>/dev/null | grep -c '^sleep 47$')" "run_with_timeout: watchdog sleep is reaped"

# --- _spawn_group: child leads its own process group ---
_spawn_group sleep 3
_sg_pid="${SPAWNED_PID}"
_sg_pgid="$(ps -o pgid= -p "${_sg_pid}" 2>/dev/null | tr -d ' ')"
assert_eq "${_sg_pid}" "${_sg_pgid}" "_spawn_group: pgid == pid (group-killable)"
_kill_tree "${_sg_pid}" TERM
wait "${_sg_pid}" 2>/dev/null
assert_exit 1 kill -0 "${_sg_pid}"
