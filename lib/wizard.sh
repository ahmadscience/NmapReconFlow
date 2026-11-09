#!/usr/bin/env bash
# NmapReconFlow - Guided setup for new users (--wizard, or no arguments on a
# terminal). Asks a few plain questions, prints the equivalent command so the
# user learns the flags, then runs it.

# Scan-type menu: number|type|description
WIZARD_TYPES=(
    "1|Port|Quick: find open ports (~15 seconds)"
    "2|Script|Standard: open ports + what software runs on them (~5 minutes)"
    "3|Full|Thorough: all 65535 ports + details (~5-10 minutes)"
    "4|Vulns|Vulnerabilities: look up known CVEs for the services (~5-15 minutes)"
    "5|Recon|Recon: standard scan + follow-up tools like nikto (varies)"
    "6|All|Everything above + UDP (~20-30 minutes)"
    "7|UDP|UDP ports only (needs root/sudo, ~5 minutes)"
    "8|Network|Find live hosts on the target's /24 network (~15 seconds)"
)

# Build the command-line arguments from the wizard's answers, one per line.
#   $1 target  $2 type  $3 profile  $4 autopilot(true|false)
#   $5 html(true|false)  $6 output dir (empty = default)
# A target that is an existing file becomes -f (a list of targets).
wizard_build_args() {
    local target="$1" type="$2" profile="$3" autopilot="$4" html="$5" outdir="$6"
    if [ -f "${target}" ]; then
        printf '%s\n' "-f" "${target}"
    else
        printf '%s\n' "-H" "${target}"
    fi
    printf '%s\n' "-t" "${type}"
    [ "${profile}" != "normal" ] && printf '%s\n' "--profile" "${profile}"
    [ "${autopilot}" = "true" ] && printf '%s\n' "-a"
    [ "${html}" = "true" ] && printf '%s\n' "--html"
    [ -n "${outdir}" ] && printf '%s\n' "-o" "${outdir}"
    return 0
}

# Read one answer; fail (end the wizard) on end of input.
_wizard_ask() {
    local prompt="$1" __var="$2" __ans
    printf '%b' "${prompt}"
    IFS= read -r __ans || { echo; return 1; }
    # Trim surrounding whitespace.
    __ans="${__ans#"${__ans%%[![:space:]]*}"}"
    __ans="${__ans%"${__ans##*[![:space:]]}"}"
    printf -v "${__var}" '%s' "${__ans}"
}

# Yes/no question with a default ("y" or "n"). Sets the named var to true/false.
_wizard_yesno() {
    local prompt="$1" def="$2" __var="$3" ans hint="[y/N]"
    [ "${def}" = "y" ] && hint="[Y/n]"
    while true; do
        _wizard_ask "${prompt} ${hint} " ans || return 1
        [ -z "${ans}" ] && ans="${def}"
        case "${ans}" in
            [Yy]|[Yy][Ee][Ss]) printf -v "${__var}" 'true'; return 0 ;;
            [Nn]|[Nn][Oo])     printf -v "${__var}" 'false'; return 0 ;;
            *) echo "  Please answer y or n." ;;
        esac
    done
}

# Interactive guided setup. $1 = path of nmapReconFlow.sh to run at the end.
# Exits: runs the scan (exec), or exits 1 if the user stops or input ends.
run_wizard() {
    local self="$1"
    local target="" type="" profile="normal" autopilot="true" html="false" outdir="" permitted="false"
    local ans entry n t d

    printf "\n${BOLD}${GREEN}NmapReconFlow - guided setup${NC}\n"
    echo "Answer a few questions (press Enter to take the [default]). Ctrl+C quits."
    echo

    # 1. Target
    echo "1) What do you want to scan?"
    echo "   An IP (10.10.10.5), a hostname (example.com), a range (10.10.10.0/24),"
    echo "   or a file with one target per line."
    while true; do
        _wizard_ask "   Target: " target || exit 1
        if [ -z "${target}" ]; then
            echo "   Please enter a target."
        elif [ -f "${target}" ]; then
            break
        elif validate_host_safe "${target}" && \
             { is_ipv4 "${target}" || is_ipv6 "${target}" || is_cidr "${target}" || is_hostname "${target}"; }; then
            break
        else
            echo "   '${target}' doesn't look like an IP, hostname, range or existing file. Try again."
        fi
    done
    echo

    # 2. Scan type
    echo "2) What kind of scan?"
    for entry in "${WIZARD_TYPES[@]}"; do
        IFS='|' read -r n t d <<< "${entry}"
        printf "   %s) %-8s %s\n" "${n}" "${t}" "${d}"
    done
    while true; do
        _wizard_ask "   Choose 1-8 [2]: " ans || exit 1
        [ -z "${ans}" ] && ans=2
        type=""
        for entry in "${WIZARD_TYPES[@]}"; do
            IFS='|' read -r n t d <<< "${entry}"
            [ "${ans}" = "${n}" ] && type="${t}"
        done
        [ -n "${type}" ] && break
        echo "   Please choose a number from 1 to 8."
    done
    echo

    # 3. Speed
    echo "3) How fast?"
    echo "   1) Normal (recommended)   2) Stealth (slow and quiet)   3) Aggressive (fast and loud, labs/CTFs)"
    while true; do
        _wizard_ask "   Choose 1-3 [1]: " ans || exit 1
        case "${ans:-1}" in
            1) profile="normal"; break ;;
            2) profile="stealth"; break ;;
            3) profile="aggressive"; break ;;
            *) echo "   Please choose 1, 2 or 3." ;;
        esac
    done
    echo

    # 4. Unattended
    _wizard_yesno "4) Run everything without asking more questions?" "y" autopilot || exit 1
    echo

    # 5. HTML report
    if command -v xsltproc >/dev/null 2>&1; then
        _wizard_yesno "5) Also make an HTML report you can open in a browser?" "y" html || exit 1
    else
        echo "5) HTML report: skipped (needs xsltproc - $(install_hint xsltproc))"
        html="false"
    fi
    echo

    # 6. Output folder
    local defdir="${target}"
    [ -f "${target}" ] && defdir="current folder"
    _wizard_ask "6) Save results in which folder? [${defdir}]: " outdir || exit 1
    echo

    # 7. Permission
    printf "${YELLOW}Only scan systems you own or have written permission to test.${NC}\n"
    printf "${YELLOW}Scanning other people's systems can be illegal.${NC}\n"
    _wizard_yesno "7) Do you have permission to scan ${target}?" "n" permitted || exit 1
    if [ "${permitted}" != "true" ]; then
        echo
        echo "Stopped - nothing was scanned. Tip: practise on your own machine (127.0.0.1)"
        echo "or on scanme.nmap.org, which Nmap's authors allow for light test scans."
        exit 1
    fi

    local -a args=()
    local line
    while IFS= read -r line; do
        args+=("${line}")
    done < <(wizard_build_args "${target}" "${type}" "${profile}" "${autopilot}" "${html}" "${outdir}")

    echo
    printf "${GREEN}Running:${NC} %s" "$(basename "${self}")"
    printf ' %q' "${args[@]}"
    echo
    echo "(Next time you can type that command directly and skip the questions.)"
    echo
    exec "${self}" "${args[@]}"
}
