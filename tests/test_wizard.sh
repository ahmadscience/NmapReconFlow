#!/usr/bin/env bash
# Tests for lib/wizard.sh (the interactive flow itself is covered in e2e.sh)

_wargs() { wizard_build_args "$@" | paste -sd' ' -; }

assert_eq "-H 10.0.0.5 -t Script -a" "$(_wargs 10.0.0.5 Script normal true false '')" \
    "wizard_build_args: defaults (normal profile omitted, autopilot on)"
assert_eq "-H 10.0.0.0/24 -t All --profile stealth --html -o lab" "$(_wargs 10.0.0.0/24 All stealth false true lab)" \
    "wizard_build_args: profile, html, output dir, no autopilot"
_wtf="$(mktemp)"
assert_eq "-f ${_wtf} -t Port -a" "$(_wargs "${_wtf}" Port normal true false '')" \
    "wizard_build_args: existing file becomes -f (target list)"
rm -f "${_wtf}"

# Every menu entry maps to a valid scan type.
for _we in "${WIZARD_TYPES[@]}"; do
    IFS='|' read -r _wn _wt _wd <<< "${_we}"
    assert_exit 0 is_valid_scan_type "${_wt}"
done
