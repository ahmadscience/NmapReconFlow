#!/usr/bin/env bash
# Tests for lib/ui.sh

# --- format_duration ---
assert_eq "01:30" "$(format_duration 90)" "format_duration: 90s => 01:30"
assert_eq "00:00" "$(format_duration 0)" "format_duration: 0s => 00:00"
assert_eq "61:01" "$(format_duration 3661)" "format_duration: 3661s => 61:01"
assert_eq "00:01" "$(format_duration 1)" "format_duration: 1s => 00:01"
assert_eq "16:40" "$(format_duration 1000)" "format_duration: 1000s => 16:40"
