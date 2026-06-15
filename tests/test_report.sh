#!/usr/bin/env bash
# Tests for lib/report.sh

# --- yaml_escape ---
assert_eq '"hello"' "$(yaml_escape 'hello')" "yaml_escape: plain string"
assert_eq '"say \\"hi\\""' "$(yaml_escape 'say "hi"')" "yaml_escape: double quotes"

# Newline handling
_input_nl=$'line1\nline2'
assert_eq '"line1\\nline2"' "$(yaml_escape "$_input_nl")" "yaml_escape: newlines"

# Tab handling
_input_tab=$'col1\tcol2'
assert_eq '"col1\\tcol2"' "$(yaml_escape "$_input_tab")" "yaml_escape: tabs"

# Carriage return handling
_input_cr=$'line1\r'
assert_eq '"line1\\r"' "$(yaml_escape "$_input_cr")" "yaml_escape: carriage returns"

# --- json_escape ---
assert_eq "hello" "$(json_escape 'hello')" "json_escape: plain string"
assert_eq 'say \\"hi\\"' "$(json_escape 'say "hi"')" "json_escape: double quotes"
assert_eq 'path\\/to\\/file' "$(json_escape 'path/to/file')" "json_escape: forward slashes"

# Tab handling
_json_tab=$'col1\tcol2'
assert_eq 'col1\\tcol2' "$(json_escape "$_json_tab")" "json_escape: tabs"

# Newline handling
_json_nl=$'line1\nline2'
assert_eq 'line1\\nline2' "$(json_escape "$_json_nl")" "json_escape: newlines"
