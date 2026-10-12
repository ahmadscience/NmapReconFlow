#!/usr/bin/env bash
# Tests for lib/config.sh

# --- detect_platform ---
# detect_platform was already called by the runner; verify results
_current_os="$(uname -s)"
if [ "$_current_os" = "Linux" ]; then
    assert_eq "true" "$IS_LINUX" "detect_platform: IS_LINUX is true on Linux"
    assert_eq "false" "$IS_MACOS" "detect_platform: IS_MACOS is false on Linux"
    assert_eq "W" "$PING_TIMEOUT_FLAG" "detect_platform: PING_TIMEOUT_FLAG is W on Linux"
elif [ "$_current_os" = "Darwin" ]; then
    assert_eq "false" "$IS_LINUX" "detect_platform: IS_LINUX is false on macOS"
    assert_eq "true" "$IS_MACOS" "detect_platform: IS_MACOS is true on macOS"
    assert_eq "t" "$PING_TIMEOUT_FLAG" "detect_platform: PING_TIMEOUT_FLAG is t on macOS"
fi

# --- set_defaults: timeout variables are set and positive ---
_timeout_vars=(
    TIMEOUT_NMAP_PORT
    TIMEOUT_NMAP_FULL
    TIMEOUT_NMAP_SCRIPT
    TIMEOUT_NMAP_UDP
    TIMEOUT_NMAP_VULNS
    TIMEOUT_RECON_DEFAULT
)
for _tvar in "${_timeout_vars[@]}"; do
    _tval="${!_tvar}"
    _is_positive="false"
    [ -n "$_tval" ] && [ "$_tval" -gt 0 ] 2>/dev/null && _is_positive="true"
    assert_eq "true" "$_is_positive" "set_defaults: ${_tvar} is set and positive (=${_tval})"
done

# --- set_defaults: NMAP_TIMING ---
assert_eq "4" "$NMAP_TIMING" "set_defaults: NMAP_TIMING defaults to 4"

# --- set_defaults: REPORT_FORMAT ---
assert_eq "markdown" "$REPORT_FORMAT" "set_defaults: REPORT_FORMAT defaults to markdown"

# --- set_defaults: DRY_RUN ---
assert_eq "false" "$DRY_RUN" "set_defaults: DRY_RUN defaults to false"

# --- set_defaults: new feature toggles ---
assert_eq "false" "$REPORT_HTML" "set_defaults: REPORT_HTML defaults to false"
assert_eq "false" "$RUN_BRUTE" "set_defaults: RUN_BRUTE defaults to false"
assert_eq "slack" "$NOTIFY_STYLE" "set_defaults: NOTIFY_STYLE defaults to slack"
assert_eq "" "$NOTIFY_WEBHOOK" "set_defaults: NOTIFY_WEBHOOK empty by default"

# --- send_notification: no-op when webhook unset ---
NOTIFY_WEBHOOK=""
assert_exit 0 send_notification "test message"

# --- send_notification: dry-run does not call curl ---
NOTIFY_WEBHOOK="https://example.invalid/hook"
DRY_RUN=true
assert_exit 0 send_notification "dry-run message"
DRY_RUN=false
NOTIFY_WEBHOOK=""
