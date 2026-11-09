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
# The perl wrapper calls setpgrp() only once it has started, so read the pgid
# after it settles (macOS is slower to start perl than Linux). Poll up to ~3s:
# a startup race passes; setpgrp genuinely not working still fails.
_spawn_group sleep 5
_sg_pid="${SPAWNED_PID}"
_sg_pgid=""
for _i in $(seq 1 30); do
    _sg_pgid="$(ps -o pgid= -p "${_sg_pid}" 2>/dev/null | tr -d ' ')"
    [ "${_sg_pgid}" = "${_sg_pid}" ] && break
    sleep 0.1
done
assert_eq "${_sg_pid}" "${_sg_pgid}" "_spawn_group: pgid == pid (group-killable)"
# A child of the spawned process is in the same group, so a group kill
# reaches it (what timeouts rely on to stop `tool | tee` and NSE helpers).
_spawn_group sh -c 'sleep 37.5 & wait'
_sg2="${SPAWNED_PID}"
for _i in $(seq 1 30); do
    [ "$(ps -o pgid= -p "${_sg2}" 2>/dev/null | tr -d ' ')" = "${_sg2}" ] && break
    sleep 0.1
done
sleep 0.3
_kill_tree "${_sg2}" TERM
wait "${_sg2}" 2>/dev/null
sleep 0.3
# Match by the unique duration, not by group: a child left in the wrong group
# is exactly the failure this must catch.
assert_eq "0" "$(ps -A -o args= 2>/dev/null | grep -c '^sleep 37\.5$')" \
    "_kill_tree: group kill also stops the spawned command's children"
_kill_tree "${_sg_pid}" TERM
wait "${_sg_pid}" 2>/dev/null
assert_exit 1 kill -0 "${_sg_pid}"
