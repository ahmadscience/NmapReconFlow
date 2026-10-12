#!/usr/bin/env bash
# NmapReconFlow - TAP-format test runner
# Sources all tests/test_*.sh files and reports pass/fail

set -uo pipefail

_test_count=0
_test_fail=0

assert_eq() {
    local expected="$1" actual="$2" msg="${3:-unnamed test}"
    _test_count=$((_test_count + 1))
    if [ "$expected" = "$actual" ]; then
        printf "ok %d - %s\n" "$_test_count" "$msg"
    else
        printf "not ok %d - %s\n" "$_test_count" "$msg"
        printf "#   expected: %s\n#   actual:   %s\n" "$expected" "$actual"
        _test_fail=$((_test_fail + 1))
    fi
}

assert_match() {
    local pattern="$1" actual="$2" msg="${3:-unnamed test}"
    _test_count=$((_test_count + 1))
    if [[ "$actual" =~ $pattern ]]; then
        printf "ok %d - %s\n" "$_test_count" "$msg"
    else
        printf "not ok %d - %s\n" "$_test_count" "$msg"
        printf "#   pattern: %s\n#   actual:  %s\n" "$pattern" "$actual"
        _test_fail=$((_test_fail + 1))
    fi
}

assert_exit() {
    local expected_code="$1"
    shift
    "$@" >/dev/null 2>&1
    local actual_code=$?
    _test_count=$((_test_count + 1))
    if [ "$expected_code" -eq "$actual_code" ]; then
        printf "ok %d - exit code %d: %s\n" "$_test_count" "$expected_code" "$*"
    else
        printf "not ok %d - exit code expected %d got %d: %s\n" "$_test_count" "$expected_code" "$actual_code" "$*"
        _test_fail=$((_test_fail + 1))
    fi
}

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source libs in order (config must be first for platform detection)
for _lib in config timeout ui utils; do
    source "${SCRIPT_DIR}/lib/${_lib}.sh"
done

# Source report.sh separately (depends on ui.sh for format_duration)
source "${SCRIPT_DIR}/lib/report.sh"

# Source recon.sh for recon_outfile() (function defs only; no side effects)
source "${SCRIPT_DIR}/lib/recon.sh"

# Initialize platform and defaults so tests run against real config
detect_platform
set_defaults

# Discover and source all test files
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_test_files=()
for _tf in "${TEST_DIR}"/test_*.sh; do
    [ -f "$_tf" ] || continue
    _test_files+=("$_tf")
done

if [ ${#_test_files[@]} -eq 0 ]; then
    printf "Bail out! No test files found in %s\n" "${TEST_DIR}"
    exit 1
fi

# Print TAP plan header (deferred until after all tests run)
# We collect output, then prepend the plan line
_tap_output=""

for _tf in "${_test_files[@]}"; do
    printf "# Running %s\n" "$(basename "$_tf")"
    source "$_tf"
done

# TAP plan
printf "1..%d\n" "$_test_count"

# Summary
printf "# Tests: %d   Pass: %d   Fail: %d\n" "$_test_count" "$((_test_count - _test_fail))" "$_test_fail"

if [ "$_test_fail" -gt 0 ]; then
    printf "# FAIL\n"
    exit 1
else
    printf "# OK\n"
    exit 0
fi
