#!/usr/bin/env bash
# Tests for lib/report.sh

# --- yaml_escape ---
assert_eq '"hello"' "$(yaml_escape 'hello')" "yaml_escape: plain string"

# Double quotes: say "hi" -> "say \"hi\""
_yaml_quotes_expected="\"say \\\"hi\\\"\""
assert_eq "$_yaml_quotes_expected" "$(yaml_escape 'say "hi"')" "yaml_escape: double quotes"

# Newline handling: literal newline replaced with \n
_input_nl=$'line1\nline2'
_yaml_nl_expected="\"line1\\nline2\""
assert_eq "$_yaml_nl_expected" "$(yaml_escape "$_input_nl")" "yaml_escape: newlines"

# Tab handling: literal tab replaced with \t
_input_tab=$'col1\tcol2'
_yaml_tab_expected="\"col1\\tcol2\""
assert_eq "$_yaml_tab_expected" "$(yaml_escape "$_input_tab")" "yaml_escape: tabs"

# Carriage return handling: literal CR replaced with \r
_input_cr=$'line1\r'
_yaml_cr_expected="\"line1\\r\""
assert_eq "$_yaml_cr_expected" "$(yaml_escape "$_input_cr")" "yaml_escape: carriage returns"

# --- json_escape ---
assert_eq "hello" "$(json_escape 'hello')" "json_escape: plain string"

# Double quotes: say "hi" -> say \"hi\"
_json_quotes_expected="say \\\"hi\\\""
assert_eq "$_json_quotes_expected" "$(json_escape 'say "hi"')" "json_escape: double quotes"

# Forward slashes: path/to/file -> path\/to\/file
_json_slash_expected="path\\/to\\/file"
assert_eq "$_json_slash_expected" "$(json_escape 'path/to/file')" "json_escape: forward slashes"

# Tab handling
_json_tab=$'col1\tcol2'
_json_tab_expected="col1\\tcol2"
assert_eq "$_json_tab_expected" "$(json_escape "$_json_tab")" "json_escape: tabs"

# Newline handling
_json_nl=$'line1\nline2'
_json_nl_expected="line1\\nline2"
assert_eq "$_json_nl_expected" "$(json_escape "$_json_nl")" "json_escape: newlines"
