#!/bin/bash
# ==============================================================================
# FOXHUNT v5.0
# Copyright (c) 2026 NullFox
#
# Licensed under the MIT License. 
# See LICENSE file in the project root for full license information.
# ==============================================================================
#
# Interactive bug bounty recon shell.
# Run as: foxhunt  (drops into interactive prompt)
#    or:  foxhunt <cmd> [args]  (single-shot from terminal)
#
# Workflow:
#   foxhunt
#   [foxhunt] set program HackerOne-ExampleCorp
#   [foxhunt] set scope *.example.com,example.com  (or: set scope scope.txt)
#   [foxhunt] verify scope
#   [foxhunt] set target api.example.com
#   [foxhunt] run
#
# No-program mode (quick target, no program context):
#   [foxhunt] set target example.com
#   [foxhunt] run
#
# Per-program config persists in:
#   $BOUNTY_DIR/<program>/.program_config
#
# Global user defaults:  ~/.recon_config
#
# Ctrl+C during a stage  → skip that stage, pipeline continues
# Ctrl+C again (<2s)     → exit cleanly
# Ctrl+C between stages  → exit cleanly
#
# Scope file format (CRLF and LF handled, wildcards supported):
#   *.example.com
#   example.com
#   # comments ignored
#
# Quick mode skips: amass / assetfinder / github-subdomains,
#   DNS bruteforce, VHost fuzzing, cloud enum, screenshots,
#   katana crawl, x8, JS download/LinkFinder, tech-conditional
#   scanning, 403 bypass, directory bruteforce.
#   Nuclei: takeover+token templates only.
#
# ~/.recon_config overrides (global defaults):
#   BOUNTY_DIR           WORDLIST_DNS_BRUTE   WORDLIST_COMMON
#   WORDLIST_VHOST       GITHUB_TOKEN         SHODAN_API_KEY
#   LINKFINDER_PY        CORSY_PY             CLOUD_ENUM_PY
#
# Install guide (all FOSS):
#   go: subfinder amass assetfinder httpx-toolkit katana dnsx asnmap
#   go: nuclei dalfox gau uro github-subdomains puredns byp4xx
#   pip: trufflehog paramspider shodan
#   cargo: rustscan
#   apt: nmap ffuf gowitness massdns s3scanner x8
#   git: LinkFinder  Corsy  cloud_enum
# ==============================================================================


set -o pipefail

# ── Load user global config ────────────────────────────────────────────────────
[ -f "$HOME/.recon_config" ] && source "$HOME/.recon_config"

# ── Global paths ───────────────────────────────────────────────────────────────
BOUNTY_DIR="${BOUNTY_DIR:-$HOME/Projects/Bounties}"
GLOBAL_SESSION_FILE="$HOME/.foxhunt_session"

# ── Runtime state (populated by load_state) ────────────────────────────────────
ACTIVE_PROGRAM=""        # current program name (empty = no-program mode)
ACTIVE_TARGET=""         # current target domain
ACTIVE_SCOPE=()          # array of scope entries

# ── Pipeline stage control ─────────────────────────────────────────────────────
STAGE_SKIPPED=false
_SKIP_COOLDOWN=false
TOTAL_STAGES=24

# ==============================================================================
# COLOUR / OUTPUT HELPERS
# ==============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

_info()  { echo -e "${CYAN}[*]${RESET} $*"; }
_ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
_warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
_err()   { echo -e "${RED}[!]${RESET} $*" >&2; }
_stage() { echo -e "${BOLD}${CYAN}[$1/$TOTAL_STAGES]${RESET} $2"; }

# ==============================================================================
# DEFAULT CONFIG VALUES
# These are the baseline for any new program or no-program session.
# ==============================================================================

_config_defaults() {
    CFG_PROXY="false"
    CFG_PROXY_PORT="8080"
    CFG_EXPLOIT="false"
    CFG_PORTSCAN="false"
    CFG_NUCLEI="true"
    CFG_NUCLEI_TIMEOUT="300"
    CFG_HTTPX_TIMEOUT="10"
    CFG_ASNMAP_TIMEOUT="0"
    CFG_MODE="full"
    CFG_NOTIFY="false"
    CFG_RATE="50"
    CFG_THREADS="10"
    CFG_DNS="8.8.8.8"
    CFG_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    CFG_HEADERS=()
}

# ==============================================================================
# STATE PERSISTENCE
# Global session: ~/.foxhunt_session  (active program + target)
# Program config: $BOUNTY_DIR/<program>/.program_config
# ==============================================================================

# Save which program/target is active across shell sessions
_save_global_session() {
    {
        echo "ACTIVE_PROGRAM=$(printf '%q' "$ACTIVE_PROGRAM")"
        echo "ACTIVE_TARGET=$(printf '%q' "$ACTIVE_TARGET")"
    } > "$GLOBAL_SESSION_FILE"
}

_load_global_session() {
    if [ -f "$GLOBAL_SESSION_FILE" ]; then
        # shellcheck source=/dev/null
        source "$GLOBAL_SESSION_FILE" 2>/dev/null || true
    fi
}

# Write the current CFG_* vars + scope to the program config file
_save_program_config() {
    local prog_dir="$BOUNTY_DIR/$ACTIVE_PROGRAM"
    local cfg="$prog_dir/.program_config"

    # Only save if a program is active
    [ -z "$ACTIVE_PROGRAM" ] && return 0

    mkdir -p "$prog_dir"
    {
        echo "CFG_PROXY=$(printf '%q' "$CFG_PROXY")"
        echo "CFG_PROXY_PORT=$(printf '%q' "$CFG_PROXY_PORT")"
        echo "CFG_EXPLOIT=$(printf '%q' "$CFG_EXPLOIT")"
        echo "CFG_PORTSCAN=$(printf '%q' "$CFG_PORTSCAN")"
        echo "CFG_NUCLEI=$(printf '%q' "$CFG_NUCLEI")"
        echo "CFG_NUCLEI_TIMEOUT=$(printf '%q' "$CFG_NUCLEI_TIMEOUT")"
        echo "CFG_HTTPX_TIMEOUT=$(printf '%q' "$CFG_HTTPX_TIMEOUT")"
        echo "CFG_ASNMAP_TIMEOUT=$(printf '%q' "$CFG_ASNMAP_TIMEOUT")"
        echo "CFG_MODE=$(printf '%q' "$CFG_MODE")"
        echo "CFG_NOTIFY=$(printf '%q' "$CFG_NOTIFY")"
        echo "CFG_RATE=$(printf '%q' "$CFG_RATE")"
        echo "CFG_THREADS=$(printf '%q' "$CFG_THREADS")"
        echo "CFG_DNS=$(printf '%q' "$CFG_DNS")"
        echo "CFG_UA=$(printf '%q' "$CFG_UA")"
        # Scope array
        for i in "${!ACTIVE_SCOPE[@]}"; do
            echo "ACTIVE_SCOPE[$i]=$(printf '%q' "${ACTIVE_SCOPE[$i]}")"
        done
        # Headers array
        for i in "${!CFG_HEADERS[@]}"; do
            echo "CFG_HEADERS[$i]=$(printf '%q' "${CFG_HEADERS[$i]}")"
        done
    } > "$cfg"
}

# Load config for the given program name into CFG_* vars
_load_program_config() {
    local prog="$1"
    _config_defaults
    ACTIVE_SCOPE=()
    CFG_HEADERS=()

    local cfg="$BOUNTY_DIR/$prog/.program_config"
    if [ -f "$cfg" ]; then
        # Validate file contains only safe assignment lines before sourcing
        if grep -qvE '^(CFG_[A-Z_]+(\[[0-9]+\])?=|ACTIVE_SCOPE\[[0-9]+\]=|#|$)' "$cfg" 2>/dev/null; then
            _warn "Program config looks corrupt, resetting to defaults: $cfg"
        else
            # shellcheck source=/dev/null
            source "$cfg" 2>/dev/null || true
        fi
    fi
}

# Load the full state: global session → program config
load_state() {
    _config_defaults
    ACTIVE_SCOPE=()
    CFG_HEADERS=()
    _load_global_session

    if [ -n "$ACTIVE_PROGRAM" ]; then
        _load_program_config "$ACTIVE_PROGRAM"
    fi
}

# ==============================================================================
# SCOPE HELPERS
# ==============================================================================

# Returns 0 if $1 is in scope based on ACTIVE_SCOPE array
# Handles exact match and wildcard (*.example.com) entries
_in_scope() {
    local target="$1"
    local entry base

    # If no scope defined, everything is in scope
    [ "${#ACTIVE_SCOPE[@]}" -eq 0 ] && return 0

    for entry in "${ACTIVE_SCOPE[@]}"; do
        # Strip leading *. for wildcard check
        if [[ "$entry" == \*.* ]]; then
            base="${entry#\*.}"
            # Matches sub.base or base itself
            [[ "$target" == *".$base" || "$target" == "$base" ]] && return 0
        else
            [[ "$target" == "$entry" || "$target" == *".$entry" ]] && return 0
        fi
    done
    return 1
}

# Parse scope from: comma-separated string, .txt file path, or single entry
# Populates ACTIVE_SCOPE array
_parse_scope_input() {
    local input="$1"
    local -a new_scope=()
    local line entry target_file=""

    ACTIVE_SCOPE=()

    # Determine the actual file path
    if [[ -f "$input" ]]; then
        target_file="$input"
    elif [[ -n "$ACTIVE_PROGRAM" && -f "$BOUNTY_DIR/$ACTIVE_PROGRAM/$input" ]]; then
        target_file="$BOUNTY_DIR/$ACTIVE_PROGRAM/$input"
    fi

    # If we found a file, parse it
    if [[ -n "$target_file" ]]; then
        while IFS= read -r line || [ -n "$line" ]; do
            # Strip whitespace and carriage returns
            line=$(echo "$line" | tr -d '\r' | xargs 2>/dev/null)
            # Skip comments and empty lines
            [[ "$line" =~ ^# || -z "$line" ]] && continue
            new_scope+=("$line")
        done < "$target_file"
    else
        # Not a file? Treat as comma-separated list
        IFS=',' read -ra entries <<< "$input"
        for entry in "${entries[@]}"; do
            entry=$(echo "$entry" | tr -d '\r' | xargs 2>/dev/null)
            [ -n "$entry" ] && new_scope+=("$entry")
        done
    fi

    if [ "${#new_scope[@]}" -eq 0 ]; then
        _err "No valid scope entries found."
        return 1
    fi

    ACTIVE_SCOPE=("${new_scope[@]}")
    return 0
}

# ==============================================================================
# TERMINAL / SIGNAL HANDLING
# ==============================================================================

_restore_terminal() {
    stty sane 2>/dev/null || true
    tput cnorm 2>/dev/null || true
}

_sigint_exit() {
    echo ""
    _restore_terminal
    _warn "Interrupted. Exiting foxhunt."
    exit 130
}

_sigint_skip() {
    if [ "$_SKIP_COOLDOWN" = true ]; then
        echo ""
        _restore_terminal
        _warn "Exit."
        exit 130
    fi
    _SKIP_COOLDOWN=true
    STAGE_SKIPPED=true
    echo ""
    _warn "Skipping stage (Ctrl+C). Press again within 2s to exit."
    # Auto-reset cooldown after 2 seconds in background
    ( sleep 2; kill -USR1 $$ 2>/dev/null ) &
}

# SIGUSR1 resets the double-tap cooldown after 2s
_sigint_cooldown_reset() {
    _SKIP_COOLDOWN=false
}

trap '_sigint_cooldown_reset' USR1

# Run a command that can be skipped with Ctrl+C.
# Child process is started in background so SIGINT actually reaches it.
# Usage: skippable <cmd> [args...]
skippable() {
    STAGE_SKIPPED=false
    _SKIP_COOLDOWN=false
    trap '_sigint_skip' INT

    # Run child in background, wait for it so we can be interrupted
    "$@" &
    local child_pid=$!
    wait "$child_pid"
    local rc=$?

    # If we were skipped, the wait above returned early; kill the child cleanly
    if [ "$STAGE_SKIPPED" = true ]; then
        kill "$child_pid" 2>/dev/null
        wait "$child_pid" 2>/dev/null
    fi

    trap '_sigint_exit' INT
    _SKIP_COOLDOWN=false
    return $rc
}

# Variant: wrap an external timeout so Ctrl+C kills the whole process tree
# Usage: skippable_timeout <seconds> <cmd> [args...]
skippable_timeout() {
    local secs="$1"; shift
    STAGE_SKIPPED=false
    _SKIP_COOLDOWN=false
    trap '_sigint_skip' INT

    timeout "$secs" "$@" &
    local child_pid=$!
    wait "$child_pid"
    local rc=$?

    if [ "$STAGE_SKIPPED" = true ]; then
        kill "$child_pid" 2>/dev/null
        wait "$child_pid" 2>/dev/null
    fi

    trap '_sigint_exit' INT
    _SKIP_COOLDOWN=false
    return $rc
}

stage_ok()   { [ "$STAGE_SKIPPED" = false ]; }
quick_mode() { [ "$CFG_MODE" = "quick" ]; }

# ==============================================================================
# CHECKPOINT SYSTEM
# ==============================================================================

CHECKPOINT_FILE=""

check_checkpoint() { [ -f "$CHECKPOINT_FILE" ] && grep -qxF "$1" "$CHECKPOINT_FILE" 2>/dev/null; }

mark_checkpoint() {
    echo "$1" >> "$CHECKPOINT_FILE"
    sort -u -o "$CHECKPOINT_FILE" "$CHECKPOINT_FILE"
}

# ==============================================================================
# SESSION LOCK
# Prevents two simultaneous foxhunt instances from writing to the same target.
# ==============================================================================

LOCK_FILE=""

acquire_lock() {
    LOCK_FILE="$OUTDIR/.lock"
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            _err "Another foxhunt instance is already running for this target."
            _err "PID: $pid  |  Output: $OUTDIR"
            _err "Kill it first or wait for it to finish."
            return 1
        else
            _info "Stale lock file (PID ${pid:-unknown}) -- clearing"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
    return 0
}

release_lock() {
    [ -n "$LOCK_FILE" ] && [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
}

# ==============================================================================
# HEADER HELPER
# Appends CFG_HEADERS entries to a named array (bash nameref, requires bash 4.3+)
# Usage: append_headers ARRAY_NAME [-H|-header|--header]
# ==============================================================================

append_headers() {
    local -n _arr_ref="$1"
    local flag="${2:--H}"
    local h
    for h in "${CFG_HEADERS[@]}"; do
        _arr_ref+=("$flag" "$h")
    done
}

# ==============================================================================
# NOTIFY
# ==============================================================================

notify_complete() {
    local target="$1" duration="$2"
    [ "$CFG_NOTIFY" != "true" ] && return
    command -v notify-send &>/dev/null \
        && notify-send "Foxhunt Complete" "$target finished in ${duration}s" 2>/dev/null || true
    printf '\a'
    _ok "Notification sent"
}

# ==============================================================================
# COUNT LOADER (for checkpoint resumes -- restores summary variables)
# ==============================================================================

load_counts_from_files() {
    COUNT=$(wc -l < "$DATADIR/subdomains_all.txt" 2>/dev/null | tr -d ' ')
    BRUTE_COUNT=$(wc -l < "$DATADIR/subs_bruteforce.txt" 2>/dev/null | tr -d ' ')
    IP_COUNT=$(wc -l < "$DATADIR/ips_public.txt" 2>/dev/null | tr -d ' ')
    IP_LEAKED=$(wc -l < "$DATADIR/ips_internal_leaked.txt" 2>/dev/null | tr -d ' ')
    CIDR_COUNT=$(wc -l < "$DATADIR/cidrs.txt" 2>/dev/null | tr -d ' ')
    LIVE=$(wc -l < "$DATADIR/live_all.txt" 2>/dev/null | tr -d ' ')
    VHOST_COUNT=$(grep -c ',200,\|,301,\|,302,\|,401,\|,403,' "$DATADIR/vhosts_found.txt" 2>/dev/null || echo 0)
    URL_COUNT=$(wc -l < "$DATADIR/urls_all.txt" 2>/dev/null | tr -d ' ')
    EXT_COUNT=$(wc -l < "$DATADIR/urls_interesting_ext.txt" 2>/dev/null | tr -d ' ')
    INT_COUNT=$(wc -l < "$DATADIR/params_interesting.txt" 2>/dev/null | tr -d ' ')
    X8_COUNT=$(wc -l < "$DATADIR/params_x8.txt" 2>/dev/null | tr -d ' ')
    JS_COUNT=$(wc -l < "$DATADIR/js_bundles.txt" 2>/dev/null | tr -d ' ')
    MANIFEST_COUNT=$(wc -l < "$DATADIR/js_manifest.txt" 2>/dev/null | tr -d ' ')
    EP_COUNT=$(wc -l < "$DATADIR/js_endpoints.txt" 2>/dev/null | tr -d ' ')
    SECRETS_COUNT=$(wc -l < "$DATADIR/secrets_grep.txt" 2>/dev/null | tr -d ' ')
    TH_COUNT=$(wc -l < "$DATADIR/secrets_trufflehog.json" 2>/dev/null | tr -d ' ')
    EXPOSURE_COUNT=$(wc -l < "$DATADIR/exposure_results.txt" 2>/dev/null | tr -d ' ')
    NUCLEI_COUNT=$(wc -l < "$DATADIR/nuclei_results.txt" 2>/dev/null | tr -d ' ')
    CORS_COUNT=$(grep -c 'CORS' "$DATADIR/cors_results.txt" 2>/dev/null || echo 0)
    DIR_COUNT=$(grep -c '200\|401\|403' "$DATADIR/directories.txt" 2>/dev/null || echo 0)
    BYPASS_COUNT=$(wc -l < "$DATADIR/403_bypass.txt" 2>/dev/null | tr -d ' ')
    XSS_COUNT=$(wc -l < "$DATADIR/xss_results.txt" 2>/dev/null | tr -d ' ')
    TECH_SCAN_COUNT=$(wc -l < "$DATADIR/tech_scan_results.txt" 2>/dev/null | tr -d ' ')
}

# ==============================================================================
# COMMAND: show  -- display current session state
# ==============================================================================

cmd_show() {
    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD} FOXHUNT SESSION${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    printf "  %-22s %s\n" "program"         "${ACTIVE_PROGRAM:-${YELLOW}<none>${RESET}  (no-program mode)}"
    printf "  %-22s %s\n" "target"          "${ACTIVE_TARGET:-${YELLOW}<not set>${RESET}}"
    printf "  %-22s %s\n" "mode"            "$CFG_MODE"
    printf "  %-22s %s\n" "proxy"           "$CFG_PROXY  (port: $CFG_PROXY_PORT)"
    printf "  %-22s %s\n" "exploit"         "$CFG_EXPLOIT"
    printf "  %-22s %s\n" "portscan"        "$CFG_PORTSCAN"
    printf "  %-22s %s\n" "nuclei"          "$CFG_NUCLEI  (timeout: ${CFG_NUCLEI_TIMEOUT}s)"
    printf "  %-22s %s\n" "httpx-timeout"   "${CFG_HTTPX_TIMEOUT}s"
    printf "  %-22s %s\n" "asnmap-timeout"  "${CFG_ASNMAP_TIMEOUT}s  (0 = no cap)"
    printf "  %-22s %s\n" "notify"          "$CFG_NOTIFY"
    printf "  %-22s %s\n" "rate"            "$CFG_RATE req/sec"
    printf "  %-22s %s\n" "threads"         "$CFG_THREADS"
    printf "  %-22s %s\n" "dns"             "$CFG_DNS"

    echo ""
    echo "  Scope (${#ACTIVE_SCOPE[@]} entries):"
    if [ "${#ACTIVE_SCOPE[@]}" -eq 0 ]; then
        echo "    <none set -- all targets accepted>"
    else
        for s in "${ACTIVE_SCOPE[@]}"; do printf "    %s\n" "$s"; done
    fi

    if [ "${#CFG_HEADERS[@]}" -gt 0 ]; then
        echo ""
        echo "  Custom headers:"
        for h in "${CFG_HEADERS[@]}"; do printf "    - %s\n" "$h"; done
    fi

    echo ""
    echo -e "${BOLD}  ~/.recon_config overrides:${RESET}"
    printf "    %-22s %s\n" "BOUNTY_DIR"         "${BOUNTY_DIR}"
    printf "    %-22s %s\n" "WORDLIST_DNS_BRUTE" "${WORDLIST_DNS_BRUTE:-~/wordlists/dns_brute.txt}"
    printf "    %-22s %s\n" "WORDLIST_COMMON"    "${WORDLIST_COMMON:-~/wordlists/common.txt}"
    printf "    %-22s %s\n" "WORDLIST_VHOST"     "${WORDLIST_VHOST:-~/wordlists/subdomains.txt}"
    printf "    %-22s %s\n" "SHODAN_API_KEY" "${SHODAN_API_KEY:+<set>}"
    [ -z "$SHODAN_API_KEY" ] && printf "    %-22s %s\n" "SHODAN_API_KEY" "<not set>"
    printf "    %-22s %s\n" "GITHUB_TOKEN"       "${GITHUB_TOKEN:+<set>}"
    [ -z "$GITHUB_TOKEN" ] && printf "    %-22s %s\n" "GITHUB_TOKEN" "<not set>"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
}

# ==============================================================================
# COMMAND: verify scope  -- list scope entries line by line
# ==============================================================================

cmd_verify_scope() {
    if [ "${#ACTIVE_SCOPE[@]}" -eq 0 ]; then
        echo -e "\e[1;33m[!] No scope defined.\e[0m"
        return 1
    fi

    echo -e "\n\e[0;36mCurrent Active Scope:\e[0m"
    echo "-----------------------"
    for entry in "${ACTIVE_SCOPE[@]}"; do
        echo "  • $entry"
    done
    echo "-----------------------"
    echo "Total entries: ${#ACTIVE_SCOPE[@]}"
    echo ""
}

# ==============================================================================
# COMMAND: set <key> <value>
# ==============================================================================

cmd_set() {
    local key="$1"; shift
    local val="$*"

    case "$key" in
        program)
            [ -z "$val" ] && { _err "Usage: set program <name>"; return 1; }
            # Sanitize: alphanumeric, dash, underscore only
            if [[ ! "$val" =~ ^[A-Za-z0-9_-]+$ ]]; then
                _err "Program name may only contain letters, numbers, dashes, and underscores."
                return 1
            fi
            ACTIVE_PROGRAM="$val"
            local prog_dir="$BOUNTY_DIR/$ACTIVE_PROGRAM"
            mkdir -p "$prog_dir"
            # Load existing config if present, otherwise start with defaults
            _load_program_config "$ACTIVE_PROGRAM"
            _save_global_session
            _ok "Program => $ACTIVE_PROGRAM  (dir: $prog_dir)"
            ;;

        target)
            [ -z "$val" ] && { _err "Usage: set target <domain>"; return 1; }
            # Reject bare IPs
            if [[ "$val" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                _err "target must be a domain, not a bare IP."
                return 1
            fi
            # Strip leading *. for the actual target value
            local safe_val="${val#\*.}"
            # Scope check -- warn but don't block (user may intentionally target OOS)
            if ! _in_scope "$safe_val"; then
                _warn "WARNING: '$safe_val' does not match current scope."
                _warn "Proceeding, but double-check this is intentional."
            fi
            ACTIVE_TARGET="$safe_val"
            # Create target directory if a program is active
            if [ -n "$ACTIVE_PROGRAM" ]; then
                local tgt_dir="$BOUNTY_DIR/$ACTIVE_PROGRAM/$ACTIVE_TARGET"
                mkdir -p "$tgt_dir"
                _ok "Target => $ACTIVE_TARGET  (dir: $tgt_dir)"
            else
                _ok "Target => $ACTIVE_TARGET  (no-program mode)"
            fi
            _save_global_session
            ;;

        scope)
            [ -z "$val" ] && { _err "Usage: set scope <domain,domain> | <file.txt>"; return 1; }
            
            # If it's a file, try to copy it to the program dir for persistence
            if [[ -f "$val" && -n "$ACTIVE_PROGRAM" ]]; then
                cp "$val" "$BOUNTY_DIR/$ACTIVE_PROGRAM/scope.txt" 2>/dev/null
                val="$BOUNTY_DIR/$ACTIVE_PROGRAM/scope.txt"
            fi

            if _parse_scope_input "$val"; then
                # Store the path for the config
                SCOPE="$val"
                _ok "Scope set (${#ACTIVE_SCOPE[@]} entries)."
                [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
                cmd_verify_scope
            fi
            ;;

        mode)
            [[ "$val" == "full" || "$val" == "quick" ]] \
                || { _err "mode must be 'full' or 'quick'"; return 1; }
            CFG_MODE="$val"
            _ok "mode => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        proxy)
            [[ "$val" == "true" || "$val" == "false" ]] \
                || { _err "proxy must be true or false"; return 1; }
            CFG_PROXY="$val"
            _ok "proxy => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        proxy-port)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "proxy-port must be a number"; return 1; }
            CFG_PROXY_PORT="$val"
            _ok "proxy-port => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        exploit)
            [[ "$val" == "true" || "$val" == "false" ]] \
                || { _err "exploit must be true or false"; return 1; }
            CFG_EXPLOIT="$val"
            _ok "exploit => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        portscan)
            [[ "$val" == "true" || "$val" == "false" ]] \
                || { _err "portscan must be true or false"; return 1; }
            CFG_PORTSCAN="$val"
            [ "$val" = "true" ] \
                && _warn "portscan => true  (verify this is in scope before running)" \
                || _ok "portscan => false"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        nuclei)
            [[ "$val" == "true" || "$val" == "false" ]] \
                || { _err "nuclei must be true or false"; return 1; }
            CFG_NUCLEI="$val"
            _ok "nuclei => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        nuclei-timeout)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "nuclei-timeout must be a positive integer (seconds)"; return 1; }
            CFG_NUCLEI_TIMEOUT="$val"
            _ok "nuclei-timeout => ${val}s"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        httpx-timeout)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "httpx-timeout must be a positive integer (seconds)"; return 1; }
            CFG_HTTPX_TIMEOUT="$val"
            _ok "httpx-timeout => ${val}s"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        asnmap-timeout)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "asnmap-timeout must be a positive integer (seconds)"; return 1; }
            CFG_ASNMAP_TIMEOUT="$val"
            _ok "asnmap-timeout => ${val}s (0 = no cap)"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        notify)
            [[ "$val" == "true" || "$val" == "false" ]] \
                || { _err "notify must be true or false"; return 1; }
            CFG_NOTIFY="$val"
            _ok "notify => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        rate)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "rate must be a positive integer"; return 1; }
            CFG_RATE="$val"
            _ok "rate => $val req/sec"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        threads)
            [[ "$val" =~ ^[0-9]+$ ]] \
                || { _err "threads must be a positive integer"; return 1; }
            CFG_THREADS="$val"
            _ok "threads => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        dns)
            CFG_DNS="$val"
            _ok "dns => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        ua)
            CFG_UA="$val"
            _ok "ua => $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        header)
            CFG_HEADERS+=("$val")
            _ok "header added: $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;

        *)
            _err "Unknown option: $key"
            echo "  Valid: program, target, scope, mode, proxy, proxy-port, exploit,"
            echo "         portscan, nuclei, nuclei-timeout, httpx-timeout, asnmap-timeout,"
            echo "         notify, rate, threads, dns, ua, header"
            return 1
            ;;
    esac
}

# ==============================================================================
# COMMAND: unset <key>
# ==============================================================================

cmd_unset() {
    local key="$1"; shift
    local val="$*"

    case "$key" in
        header)
            local new_headers=() removed=false
            for h in "${CFG_HEADERS[@]}"; do
                [ "$h" = "$val" ] && removed=true || new_headers+=("$h")
            done
            CFG_HEADERS=("${new_headers[@]}")
            [ "$removed" = true ] && _ok "header removed: $val" || _warn "header not found: $val"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;
        headers)
            CFG_HEADERS=()
            _ok "all headers cleared"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;
        scope)
            ACTIVE_SCOPE=()
            _ok "scope cleared"
            [ -n "$ACTIVE_PROGRAM" ] && _save_program_config
            ;;
        program)
            ACTIVE_PROGRAM=""
            ACTIVE_TARGET=""
            _config_defaults
            ACTIVE_SCOPE=()
            _save_global_session
            _ok "program cleared -- now in no-program mode"
            ;;
        target)
            ACTIVE_TARGET=""
            _save_global_session
            _ok "target cleared"
            ;;
        *)
            _err "Unknown unset target: $key"
            echo "  Valid: header, headers, scope, program, target"
            return 1
            ;;
    esac
}

# ==============================================================================
# COMMAND: check -- verify toolchain
# ==============================================================================

cmd_check() {
    local missing=0 warnings=0

    _check_bin() {
        if command -v "$1" &>/dev/null; then
            printf "  ${GREEN}[+]${RESET} %-26s %s\n" "$1" "$(command -v "$1")"
        else
            printf "  ${RED}[!]${RESET} %-26s NOT FOUND\n" "$1"
            missing=$((missing + 1))
        fi
    }

    _check_file() {
        local label="$1" path="$2"
        if [ -f "$path" ]; then
            printf "  ${GREEN}[+]${RESET} %-26s %s\n" "$label" "$path"
        else
            printf "  ${RED}[!]${RESET} %-26s NOT FOUND (expected: %s)\n" "$label" "$path"
            missing=$((missing + 1))
        fi
    }

    _check_wordlist() {
        local label="$1" path="$2" rec="$3"
        if [ ! -f "$path" ]; then
            printf "  ${RED}[!]${RESET} %-26s NOT FOUND\n" "$label"
            missing=$((missing + 1))
        else
            local lines name
            lines=$(wc -l < "$path" | tr -d ' ')
            name=$(basename "$path")
            if echo "$name" | grep -qiP '^(common|small|mini)\.txt$'; then
                printf "  ${YELLOW}[~]${RESET} %-26s %s (%s lines) -- consider upgrading\n" \
                    "$label" "$path" "$lines"
                printf "      Recommended: %s\n" "$rec"
                warnings=$((warnings + 1))
            else
                printf "  ${GREEN}[+]${RESET} %-26s %s (%s lines)\n" "$label" "$path" "$lines"
            fi
        fi
    }

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD} TOOL CHECK${RESET}"
    echo -e "${BOLD}============================================================${RESET}"

    echo ""; echo "  [Subdomain Enumeration]"
    _check_bin subfinder; _check_bin amass; _check_bin assetfinder; _check_bin github-subdomains

    echo ""; echo "  [DNS]"
    _check_bin puredns; _check_bin massdns; _check_bin dnsx; _check_bin dig

    echo ""; echo "  [Network Mapping]"
    _check_bin asnmap
    if command -v rustscan &>/dev/null; then _check_bin rustscan; else _check_bin nmap; fi

    echo ""; echo "  [Passive Intel]"
    _check_bin shodan
    printf "  %-28s %s\n" "  SHODAN_API_KEY" \
        "${SHODAN_API_KEY:+set}${SHODAN_API_KEY:-not set -- add to ~/.recon_config}"

    echo ""; echo "  [HTTP Probing & Fuzzing]"
    _check_bin httpx-toolkit; _check_bin ffuf; _check_bin gowitness; _check_bin byp4xx

    echo ""; echo "  [URL & Parameter Discovery]"
    _check_bin gau; _check_bin katana; _check_bin uro; _check_bin paramspider; _check_bin x8

    echo ""; echo "  [JS Analysis]"
    _check_bin getJS
    _check_file "linkfinder.py" "${LINKFINDER_PY:-$HOME/tools/LinkFinder/linkfinder.py}"

    echo ""; echo "  [Secrets & Scanning]"
    _check_bin trufflehog; _check_bin nuclei; _check_bin s3scanner
    _check_file "cloud_enum.py" "${CLOUD_ENUM_PY:-$HOME/tools/cloud_enum/cloud_enum.py}"
    _check_file "corsy.py"      "${CORSY_PY:-$HOME/tools/corsy/corsy.py}"

    echo ""; echo "  [Exploit (optional)]"
    _check_bin dalfox

    echo ""; echo "  [Wordlists]"
    _check_wordlist "DNS bruteforce" \
        "${WORDLIST_DNS_BRUTE:-$HOME/wordlists/dns_brute.txt}" \
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
    _check_wordlist "Directories / x8" \
        "${WORDLIST_COMMON:-$HOME/wordlists/common.txt}" \
        "SecLists: Discovery/Web-Content/raft-medium-directories.txt"
    _check_wordlist "VHost fuzzing" \
        "${WORDLIST_VHOST:-$HOME/wordlists/subdomains.txt}" \
        "SecLists: Discovery/DNS/subdomains-top1million-5000.txt"

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    if [ "$missing" -eq 0 ] && [ "$warnings" -eq 0 ]; then
        _ok "All tools and wordlists present."
    else
        [ "$missing"   -gt 0 ] && _warn "$missing tool(s) missing."
        [ "$warnings"  -gt 0 ] && _warn "$warnings wordlist warning(s)."
    fi
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
}

# ==============================================================================
# COMMAND: programs -- list all programs
# ==============================================================================

cmd_programs() {
    echo ""
    if [ ! -d "$BOUNTY_DIR" ]; then
        _warn "Bounty directory does not exist: $BOUNTY_DIR"
        return
    fi
    local count=0
    echo -e "${BOLD}Programs in $BOUNTY_DIR:${RESET}"
    while IFS= read -r -d '' prog_dir; do
        local prog
        prog=$(basename "$prog_dir")
        local marker=""
        [ "$prog" = "$ACTIVE_PROGRAM" ] && marker=" ${GREEN}← active${RESET}"
        local scope_count=0
        [ -f "$prog_dir/.program_config" ] \
            && scope_count=$(grep -c '^ACTIVE_SCOPE\[' "$prog_dir/.program_config" 2>/dev/null || echo 0)
        printf "  %-30s (scope: %s entries)%b\n" "$prog" "$scope_count" "$marker"
        count=$((count+1))
    done < <(find "$BOUNTY_DIR" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null | sort -z)
    [ "$count" -eq 0 ] && echo "  <none>"
    echo ""
}

# ==============================================================================
# COMMAND: clear -- wipe active session
# ==============================================================================

cmd_clear() {
    ACTIVE_PROGRAM=""
    ACTIVE_TARGET=""
    ACTIVE_SCOPE=()
    _config_defaults
    rm -f "$GLOBAL_SESSION_FILE"
    _ok "Session cleared."
}

# ==============================================================================
# COMMAND: run [fresh]
# ==============================================================================

cmd_run() {
    local FRESH="${1:-}"

    # ── Pre-flight checks ────────────────────────────────────────────────────
    if [ -z "$ACTIVE_TARGET" ]; then
        _err "No target set. Use: set target <domain>"
        return 1
    fi

    # Re-source global config in case it changed since startup
    [ -f "$HOME/.recon_config" ] && source "$HOME/.recon_config"

    local TARGET="$ACTIVE_TARGET"
    local SAFE_TARGET="${TARGET#\*.}"
    local COMPANY="${SAFE_TARGET%%.*}"

    # Determine output directory
    if [ -n "$ACTIVE_PROGRAM" ]; then
        OUTDIR="$BOUNTY_DIR/$ACTIVE_PROGRAM/$SAFE_TARGET"
    else
        OUTDIR="$BOUNTY_DIR/no-program/$SAFE_TARGET"
    fi

    local DATADIR="$OUTDIR/data"
    local JSDIR="$DATADIR/js"
    local SSDIR="$OUTDIR/screenshots"
    CHECKPOINT_FILE="$OUTDIR/.checkpoint"
    local PROXY_URL="http://127.0.0.1:$CFG_PROXY_PORT"

    # Wordlists / tool paths (with fallback to ~/.recon_config or defaults)
    local WL_DNS_BRUTE="${WORDLIST_DNS_BRUTE:-$HOME/wordlists/dns_brute.txt}"
    local WL_COMMON="${WORDLIST_COMMON:-$HOME/wordlists/common.txt}"
    local WL_VHOST="${WORDLIST_VHOST:-$HOME/wordlists/subdomains.txt}"
    local LINKFINDER="${LINKFINDER_PY:-$HOME/tools/LinkFinder/linkfinder.py}"
    local CORSY="${CORSY_PY:-$HOME/tools/corsy/corsy.py}"
    local CLOUD_ENUM="${CLOUD_ENUM_PY:-$HOME/tools/cloud_enum/cloud_enum.py}"

    mkdir -p "$OUTDIR" "$DATADIR" "$JSDIR" "$SSDIR"

    # Set up signal handlers for the run
    trap '_sigint_exit' INT
    trap '_restore_terminal; release_lock' EXIT

    # Acquire lock -- returns 1 if another instance is running
    acquire_lock || return 1

    # ── Checkpoint handling ──────────────────────────────────────────────────
    if [ "$FRESH" = "fresh" ] && [ -f "$CHECKPOINT_FILE" ]; then
        _info "Clearing checkpoint (fresh run)"
        rm -f "$CHECKPOINT_FILE"
    elif [ -f "$CHECKPOINT_FILE" ] && [ -s "$CHECKPOINT_FILE" ]; then
        _info "Checkpoint found -- resuming"
        echo "    Completed: $(tr '\n' ' ' < "$CHECKPOINT_FILE")"
        echo "    Run 'run fresh' to restart from scratch"
    fi
    touch "$CHECKPOINT_FILE"

    local RUN_START
    RUN_START=$(date +%s)

    # Zero all count vars
    local COUNT=0 BRUTE_COUNT=0 IP_COUNT=0 IP_LEAKED=0 CIDR_COUNT=0 LIVE=0
    local VHOST_COUNT=0 URL_COUNT=0 EXT_COUNT=0 INT_COUNT=0 X8_COUNT=0
    local JS_COUNT=0 MANIFEST_COUNT=0 EP_COUNT=0 SECRETS_COUNT=0 TH_COUNT=0
    local NUCLEI_COUNT=0 CORS_COUNT=0 DIR_COUNT=0 XSS_COUNT=0
    local EXPOSURE_COUNT=0 BYPASS_COUNT=0 TECH_SCAN_COUNT=0

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD} FOXHUNT: $TARGET${RESET}"
    [ -n "$ACTIVE_PROGRAM" ] && echo " Program: $ACTIVE_PROGRAM"
    echo " Mode:    $CFG_MODE"
    echo " Output:  $OUTDIR"
    echo " Proxy:   $CFG_PROXY$([ "$CFG_PROXY" = "true" ] && echo " ($PROXY_URL)" || echo "")"
    echo " Exploit: $CFG_EXPLOIT  |  Portscan: $CFG_PORTSCAN"
    echo " Nuclei:  $CFG_NUCLEI (timeout: ${CFG_NUCLEI_TIMEOUT}s)"
    echo " Rate:    $CFG_RATE req/sec  Threads: $CFG_THREADS"
    echo " Started: $(date)"
    echo " Ctrl+C:  skip stage  |  Ctrl+C x2: exit"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""

    # ==========================================================================
    # STAGE 1: SUBDOMAIN ENUMERATION
    # Quick mode: subfinder + crt.sh only
    # Full mode:  + amass + assetfinder + github-subdomains
    # ==========================================================================
    if check_checkpoint "subdomain_enum"; then
        _stage 1 "Subdomain enumeration -- done, loading"
        COUNT=$(wc -l < "$DATADIR/subdomains_all.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 1 "Subdomain enumeration$(quick_mode && echo " (quick)" || echo " (full)")..."

        # subfinder -- fast passive
        skippable subfinder -d "$TARGET" -silent -timeout 30 -max-time 3 \
            -o "$DATADIR/subs_subfinder.txt" 2>/dev/null \
            || touch "$DATADIR/subs_subfinder.txt"

        # crt.sh -- certificate transparency
        if stage_ok; then
            skippable curl -sk "https://crt.sh/?q=%25.$SAFE_TARGET&output=json" 2>/dev/null \
                | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            n = name.strip().lstrip('*.')
            if n and n not in seen:
                seen.add(n)
                print(n)
except Exception:
    pass
" > "$DATADIR/subs_crtsh.txt" 2>/dev/null || touch "$DATADIR/subs_crtsh.txt"
        else
            touch "$DATADIR/subs_crtsh.txt"
        fi

        # Full mode: amass + assetfinder + github-subdomains
        if ! quick_mode; then
            if stage_ok && command -v amass &>/dev/null; then
                skippable amass enum -passive -d "$SAFE_TARGET" -timeout 5 \
                    -o "$DATADIR/subs_amass.txt" 2>/dev/null \
                    || touch "$DATADIR/subs_amass.txt"
            else
                touch "$DATADIR/subs_amass.txt"
            fi

            if stage_ok && command -v assetfinder &>/dev/null; then
                skippable assetfinder --subs-only "$SAFE_TARGET" 2>/dev/null \
                    > "$DATADIR/subs_assetfinder.txt" \
                    || touch "$DATADIR/subs_assetfinder.txt"
            else
                touch "$DATADIR/subs_assetfinder.txt"
            fi

            if stage_ok && command -v github-subdomains &>/dev/null \
                    && [ -n "${GITHUB_TOKEN:-}" ]; then
                skippable github-subdomains -d "$SAFE_TARGET" -t "$GITHUB_TOKEN" \
                    -o "$DATADIR/subs_github.txt" 2>/dev/null \
                    || touch "$DATADIR/subs_github.txt"
            else
                touch "$DATADIR/subs_github.txt"
                [ -z "${GITHUB_TOKEN:-}" ] \
                    && _info "github-subdomains skipped (GITHUB_TOKEN not set)"
            fi
        else
            touch "$DATADIR/subs_amass.txt" "$DATADIR/subs_assetfinder.txt" \
                  "$DATADIR/subs_github.txt"
        fi

        # Deduplicate, filter to target domain only
        sort -u "$DATADIR"/subs_*.txt 2>/dev/null \
            | grep -P "\.$SAFE_TARGET$|^$SAFE_TARGET$" \
            | grep -v '^\*' \
            > "$DATADIR/subdomains_all.txt"

        COUNT=$(wc -l < "$DATADIR/subdomains_all.txt" | tr -d ' ')
        _ok "$COUNT unique subdomains"
        mark_checkpoint "subdomain_enum"
    fi
    STAGE_SKIPPED=false

    # Write subdomains.md
    {
        echo "# Subdomains — $TARGET"
        echo ""
        printf "| Source | Count |\n|--------|-------|\n"
        for f in "$DATADIR"/subs_*.txt; do
            [ -f "$f" ] || continue
            local src cnt
            src=$(basename "$f" .txt | sed 's/subs_//')
            cnt=$(wc -l < "$f" | tr -d ' ')
            printf "| %s | %s |\n" "$src" "$cnt"
        done
        echo ""
        echo "**Total (deduplicated):** $COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/subdomains_all.txt"
        echo '```'
    } > "$OUTDIR/subdomains.md"

    # ==========================================================================
    # STAGE 2: DNS RECORDS + EMAIL SECURITY
    # DNS protocol only. No HTTP. Headers irrelevant here.
    # ==========================================================================
    if check_checkpoint "dns_records"; then
        _stage 2 "DNS records -- done, skipping"
    else
        _stage 2 "DNS records + email security..."
        {
            echo "# DNS Records — $TARGET"
            echo ""
            for TYPE in A AAAA MX NS TXT SOA CNAME CAA; do
                local RESULT
                RESULT=$(dig +noall +answer "$TYPE" "$SAFE_TARGET" @"$CFG_DNS" 2>/dev/null)
                if [ -n "$RESULT" ]; then
                    echo "## $TYPE"
                    echo '```'
                    echo "$RESULT"
                    echo '```'
                    echo ""
                fi
            done
            echo "## Zone Transfer Attempts"
            echo '```'
            while IFS= read -r ns; do
                [ -z "$ns" ] && continue
                echo "--- $ns ---"
                dig AXFR "$SAFE_TARGET" @"$ns" 2>/dev/null || echo "Transfer refused"
            done < <(dig +short NS "$SAFE_TARGET" @"$CFG_DNS" 2>/dev/null)
            echo '```'
            echo ""
            echo "## Email Security"
            echo '```'
            printf "SPF:\n"
            dig +short TXT "$SAFE_TARGET" @"$CFG_DNS" 2>/dev/null | grep -i spf || echo "none"
            printf "\nDMARC:\n"
            dig +short TXT "_dmarc.$SAFE_TARGET" @"$CFG_DNS" 2>/dev/null || echo "none"
            printf "\nDKIM (default selector):\n"
            dig +short TXT "default._domainkey.$SAFE_TARGET" @"$CFG_DNS" 2>/dev/null || echo "none"
            echo '```'
        } > "$OUTDIR/dns-records.md"
        _ok "DNS records saved"
        mark_checkpoint "dns_records"
    fi

    # ==========================================================================
    # STAGE 3: DNS BRUTEFORCE (skipped in quick mode)
    # ==========================================================================
    BRUTE_COUNT=0
    if quick_mode; then
        _stage 3 "DNS bruteforce -- skipped (quick mode)"
        touch "$DATADIR/subs_bruteforce.txt"
    elif check_checkpoint "dns_brute"; then
        _stage 3 "DNS bruteforce -- done, loading"
        BRUTE_COUNT=$(wc -l < "$DATADIR/subs_bruteforce.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 3 "DNS bruteforce (puredns)..."
        if ! command -v puredns &>/dev/null; then
            _info "puredns not found -- skipping"
            touch "$DATADIR/subs_bruteforce.txt"
        elif [ ! -f "$WL_DNS_BRUTE" ]; then
            _warn "DNS wordlist not found: $WL_DNS_BRUTE -- skipping"
            touch "$DATADIR/subs_bruteforce.txt"
        else
            skippable puredns bruteforce "$WL_DNS_BRUTE" "$SAFE_TARGET" \
                -r "$CFG_DNS" --wildcard-tests 10 -q \
                -w "$DATADIR/subs_bruteforce.txt" 2>/dev/null \
                || touch "$DATADIR/subs_bruteforce.txt"

            if stage_ok; then
                BRUTE_COUNT=$(wc -l < "$DATADIR/subs_bruteforce.txt" | tr -d ' ')
                _ok "$BRUTE_COUNT subdomains via bruteforce"
                sort -u "$DATADIR/subdomains_all.txt" "$DATADIR/subs_bruteforce.txt" \
                    > "$DATADIR/subdomains_all_tmp.txt"
                mv "$DATADIR/subdomains_all_tmp.txt" "$DATADIR/subdomains_all.txt"
                COUNT=$(wc -l < "$DATADIR/subdomains_all.txt" | tr -d ' ')
                _ok "$COUNT total subdomains"
            fi
        fi
        mark_checkpoint "dns_brute"
    fi
    STAGE_SKIPPED=false

    # ==========================================================================
    # STAGE 4: DNS RESOLUTION + IP MAPPING
    # ==========================================================================
    IP_COUNT=0; IP_LEAKED=0
    if check_checkpoint "dns_resolve"; then
        _stage 4 "DNS resolution -- done, loading"
        IP_COUNT=$(wc -l < "$DATADIR/ips_public.txt" 2>/dev/null | tr -d ' ')
        IP_LEAKED=$(wc -l < "$DATADIR/ips_internal_leaked.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 4 "DNS resolution + IP mapping (dnsx)..."
        if ! command -v dnsx &>/dev/null; then
            _info "dnsx not found -- skipping"
            touch "$DATADIR/dns_resolved.txt" "$DATADIR/ips_public.txt" \
                  "$DATADIR/ips_internal_leaked.txt" "$DATADIR/ips_unique.txt"
        else
            local DNSX_CMD=(dnsx -l "$DATADIR/subdomains_all.txt" -r "$CFG_DNS"
                -a -cname -silent -resp -o "$DATADIR/dns_resolved.txt")
            skippable "${DNSX_CMD[@]}" 2>/dev/null || touch "$DATADIR/dns_resolved.txt"

            if stage_ok; then
                # Extract all IPs from resolved records
                grep -oP '\b(?:\d{1,3}\.){3}\d{1,3}\b' "$DATADIR/dns_resolved.txt" \
                    2>/dev/null | sort -u > "$DATADIR/ips_all.txt"

                # Public IPs (non-RFC1918)
                grep -vP '^(10\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
                    "$DATADIR/ips_all.txt" | sort -u > "$DATADIR/ips_public.txt"

                # Internal IPs leaked in public DNS (potential finding)
                grep -P '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
                    "$DATADIR/ips_all.txt" | sort -u > "$DATADIR/ips_internal_leaked.txt"

                # Backward-compat alias
                cp "$DATADIR/ips_public.txt" "$DATADIR/ips_unique.txt"

                IP_COUNT=$(wc -l < "$DATADIR/ips_public.txt" | tr -d ' ')
                IP_LEAKED=$(wc -l < "$DATADIR/ips_internal_leaked.txt" | tr -d ' ')
                _ok "$IP_COUNT public IPs"
                [ "$IP_LEAKED" -gt 0 ] \
                    && _warn "$IP_LEAKED internal IPs in public DNS -- review ips_internal_leaked.txt"
            fi
        fi
        mark_checkpoint "dns_resolve"
    fi
    STAGE_SKIPPED=false

    {
        echo "# DNS Resolution — $TARGET"
        echo ""
        echo "**Public IPs:** $IP_COUNT"
        [ "${IP_LEAKED:-0}" -gt 0 ] \
            && echo "**⚠ Internal IPs in public DNS:** $IP_LEAKED  ← potential finding"
        echo ""
        echo "## Resolved Records"
        echo '```'
        cat "$DATADIR/dns_resolved.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## Public IPs"
        echo '```'
        cat "$DATADIR/ips_public.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## Internal IPs Leaked in Public DNS"
        echo '```'
        cat "$DATADIR/ips_internal_leaked.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "> Internal IPs in public DNS reveal network topology."
        echo "> Useful for SSRF payloads and understanding internal architecture."
    } > "$OUTDIR/dns-resolution.md"

    # ==========================================================================
    # STAGE 5: ASN / CIDR RECON
    # Fully passive (BGP/WHOIS only).
    # asnmap can hang on slow registries -- timeout + proper kill/wait.
    # Set asnmap-timeout 0 to disable the cap entirely.
    # ==========================================================================
    CIDR_COUNT=0
    if check_checkpoint "asn_cidr"; then
        _stage 5 "ASN/CIDR -- done, loading"
        CIDR_COUNT=$(wc -l < "$DATADIR/cidrs.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 5 "ASN / CIDR recon (asnmap, passive)..."
        _info "  Timeout: ${CFG_ASNMAP_TIMEOUT}s. Set asnmap-timeout 0 to disable cap."
        touch "$DATADIR/cidrs.txt"

        if ! command -v asnmap &>/dev/null; then
            _info "asnmap not found -- skipping"
        else
            local ASNMAP_CMD=(asnmap -d "$SAFE_TARGET" -silent)

            if [ "${CFG_ASNMAP_TIMEOUT:-0}" -gt 0 ] 2>/dev/null; then
                # Use skippable_timeout which runs `timeout <sec> cmd` in
                # background so both SIGINT and the wall-clock cap can kill it.
                skippable_timeout "$CFG_ASNMAP_TIMEOUT" "${ASNMAP_CMD[@]}" \
                    > "$DATADIR/cidrs.txt" 2>/dev/null \
                    || _info "asnmap finished or timed out (${CFG_ASNMAP_TIMEOUT}s)"
            else
                skippable "${ASNMAP_CMD[@]}" > "$DATADIR/cidrs.txt" 2>/dev/null \
                    || true
            fi

            CIDR_COUNT=$(wc -l < "$DATADIR/cidrs.txt" | tr -d ' ')
            _ok "$CIDR_COUNT CIDRs"
        fi
        # Always mark checkpoint so we don't retry a hanging tool next resume
        mark_checkpoint "asn_cidr"
    fi
    STAGE_SKIPPED=false

    {
        echo "# ASN / CIDR Recon — $TARGET"
        echo ""
        echo "**CIDRs:** $CIDR_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/cidrs.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "> In-scope CIDRs with no subdomain DNS are high-value targets."
    } > "$OUTDIR/asn-cidrs.md"

    # ==========================================================================
    # STAGE 6: SHODAN PASSIVE INTEL
    # Queries Shodan's existing database -- never touches target directly.
    # Capped at 20 IPs, 1s sleep between calls (free tier safe).
    # ==========================================================================
    if check_checkpoint "shodan"; then
        _stage 6 "Shodan -- done, skipping"
    else
        _stage 6 "Shodan passive intel..."
        > "$DATADIR/shodan_results.txt"

        if ! command -v shodan &>/dev/null; then
            _info "shodan CLI not found (pip install shodan) -- skipping"
        elif [ -z "${SHODAN_API_KEY:-}" ]; then
            _info "SHODAN_API_KEY not set in ~/.recon_config -- skipping"
        elif [ ! -s "$DATADIR/ips_public.txt" ]; then
            _info "No public IPs to query -- skipping"
        else
            skippable shodan init "$SHODAN_API_KEY" &>/dev/null || true

            # Cap at 20 IPs to stay free-tier safe
            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break
                echo "# $ip" >> "$DATADIR/shodan_results.txt"
                shodan host "$ip" 2>/dev/null \
                    >> "$DATADIR/shodan_results.txt" \
                    || echo "(no data or rate limited)" >> "$DATADIR/shodan_results.txt"
                echo "" >> "$DATADIR/shodan_results.txt"
                sleep 1
            done < <(head -20 "$DATADIR/ips_public.txt")

            # Favicon hash lookup -- find related infrastructure
            if stage_ok && command -v httpx-toolkit &>/dev/null \
                    && [ -s "$DATADIR/live_urls.txt" ]; then
                _info "Extracting favicon hashes..."
                local HTTPX_FAV_CMD=(httpx-toolkit
                    -l "$DATADIR/live_urls.txt"
                    -favicon -silent
                    -o "$DATADIR/favicon_hashes.txt")
                skippable "${HTTPX_FAV_CMD[@]}" 2>/dev/null || true

                if stage_ok && [ -s "$DATADIR/favicon_hashes.txt" ]; then
                    echo "" >> "$DATADIR/shodan_results.txt"
                    echo "# Favicon Hash Lookups" >> "$DATADIR/shodan_results.txt"
                    while IFS= read -r hash; do
                        [ -z "$hash" ] && continue
                        echo "## Hash: $hash" >> "$DATADIR/shodan_results.txt"
                        shodan search "http.favicon.hash:$hash" 2>/dev/null \
                            >> "$DATADIR/shodan_results.txt" || true
                        sleep 1
                    done < <(grep -oP '(?<=favicon_hash=)-?\d+' "$DATADIR/favicon_hashes.txt" \
                        2>/dev/null | sort -u)
                fi
            fi
            stage_ok && _ok "Shodan intel saved"
        fi
        STAGE_SKIPPED=false
        mark_checkpoint "shodan"
    fi

    {
        echo "# Shodan Passive Intel — $TARGET"
        echo ""
        echo "> Passive only. Queries Shodan's existing database."
        echo "> No packets sent to target infrastructure."
        echo ""
        echo "## Host Results (capped at 20 IPs)"
        echo '```'
        cat "$DATADIR/shodan_results.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## Favicon Hashes"
        echo '```'
        cat "$DATADIR/favicon_hashes.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/shodan.md"

    # ==========================================================================
    # STAGE 7: PORT SCAN (opt-in, default OFF)
    # rustscan preferred (faster); falls back to nmap -T3 (conservative).
    # ==========================================================================
    if check_checkpoint "portscan"; then
        _stage 7 "Port scan -- done, skipping"
    else
        if [ "$CFG_PORTSCAN" != "true" ]; then
            _stage 7 "Port scan -- skipped (foxhunt set portscan true to enable)"
            touch "$DATADIR/portscan.txt"
        else
            _stage 7 "Port scan..."
            touch "$DATADIR/portscan.txt"

            if [ ! -s "$DATADIR/ips_public.txt" ]; then
                _info "No public IPs -- skipping port scan"
            else
                local PORTS="80,443,8080,8443,8000,8888,9000,9090,9443,3000,3001,4000,4443,5000,6443"
                if command -v rustscan &>/dev/null; then
                    local IPS_CSV
                    IPS_CSV=$(paste -sd',' "$DATADIR/ips_public.txt")
                    local RUSTSCAN_CMD=(rustscan -a "$IPS_CSV" -p "$PORTS"
                        --batch-size 500 --timeout 2000 -- -sV --open
                        -oN "$DATADIR/portscan.txt")
                    skippable "${RUSTSCAN_CMD[@]}" 2>/dev/null \
                        || touch "$DATADIR/portscan.txt"
                    stage_ok && _ok "Port scan complete (rustscan)"
                elif command -v nmap &>/dev/null; then
                    local NMAP_CMD=(nmap -iL "$DATADIR/ips_public.txt" -p "$PORTS"
                        -sV --open -T3 -oN "$DATADIR/portscan.txt")
                    skippable "${NMAP_CMD[@]}" 2>/dev/null \
                        || touch "$DATADIR/portscan.txt"
                    stage_ok && _ok "Port scan complete (nmap -T3)"
                else
                    _info "rustscan and nmap not found -- skipping"
                fi
            fi
        fi
        STAGE_SKIPPED=false
        mark_checkpoint "portscan"
    fi

    {
        echo "# Port Scan — $TARGET"
        echo ""
        echo "> **portscan:** $CFG_PORTSCAN"
        echo ""
        echo '```'
        cat "$DATADIR/portscan.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/portscan.md"

    # ==========================================================================
    # STAGE 8: LIVE HOST DETECTION
    # httpx probes subdomains + any IP:port pairs from port scan.
    # Multi-round redirect following (max 5 rounds).
    # ==========================================================================
    LIVE=0
    if check_checkpoint "live_hosts"; then
        _stage 8 "Live host detection -- done, loading"
        LIVE=$(wc -l < "$DATADIR/live_all.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 8 "Live host detection (httpx)..."

        # Build probe input: subdomains + port scan IP:port pairs
        {
            cat "$DATADIR/subdomains_all.txt"
            echo "$TARGET"
            grep -oP '\d{1,3}(\.\d{1,3}){3}:\d+' "$DATADIR/portscan.txt" 2>/dev/null | sort -u
        } | sort -u > "$DATADIR/probe_input.txt"

        local ROUND=0
        cp "$DATADIR/probe_input.txt" "$DATADIR/probe_current.txt"
        : > "$DATADIR/all_seen_hosts.txt"

        while true; do
            ROUND=$((ROUND + 1))

            local HTTPX_CMD=(httpx-toolkit
                -l "$DATADIR/probe_current.txt"
                -follow-redirects -status-code -title -tech-detect
                -ip -cdn -server -content-length
                -timeout "$CFG_HTTPX_TIMEOUT"
                -rate-limit "$CFG_RATE"
                -r "$CFG_DNS" -silent
                -o "$DATADIR/live_round${ROUND}.txt"
            )
            [ "$CFG_PROXY" = "true" ] && HTTPX_CMD+=(-http-proxy "$PROXY_URL")
            append_headers HTTPX_CMD -H
            skippable "${HTTPX_CMD[@]}" 2>/tmp/httpx_err.txt || true

            [ ! -f "$DATADIR/live_round${ROUND}.txt" ] \
                && touch "$DATADIR/live_round${ROUND}.txt"

            # Extract redirect targets within scope
            grep -oP 'https?://[^\s\]]+' "$DATADIR/live_round${ROUND}.txt" 2>/dev/null \
                | grep -P "\.$SAFE_TARGET(/|$)|^https?://$SAFE_TARGET(/|$)" \
                | sort -u > "$DATADIR/redirects_round${ROUND}.txt"

            # Find hosts not yet probed
            comm -23 \
                <(sort "$DATADIR/redirects_round${ROUND}.txt") \
                <(sort "$DATADIR/all_seen_hosts.txt") \
                > "$DATADIR/probe_next.txt"

            cat "$DATADIR/probe_current.txt" >> "$DATADIR/all_seen_hosts.txt"
            sort -u -o "$DATADIR/all_seen_hosts.txt" "$DATADIR/all_seen_hosts.txt"

            local NEW ROUND_LIVE
            NEW=$(wc -l < "$DATADIR/probe_next.txt" | tr -d ' ')
            ROUND_LIVE=$(wc -l < "$DATADIR/live_round${ROUND}.txt" | tr -d ' ')
            _ok "  Round $ROUND: $ROUND_LIVE live, $NEW new redirect targets"

            [ "$STAGE_SKIPPED" = true ] && break
            [ "$NEW" -eq 0 ] && break
            [ "$ROUND" -ge 5 ] && _info "Redirect loop limit (5 rounds)" && break
            cp "$DATADIR/probe_next.txt" "$DATADIR/probe_current.txt"
        done
        STAGE_SKIPPED=false

        cat "$DATADIR"/live_round*.txt 2>/dev/null | sort -u > "$DATADIR/live_all.txt"
        LIVE=$(wc -l < "$DATADIR/live_all.txt" | tr -d ' ')
        _ok "$LIVE total live hosts"

        # Extract clean URLs for downstream tools
        awk '{print $1}' "$DATADIR/live_all.txt" \
            | grep -oP 'https?://[^\s]+' | sort -u > "$DATADIR/live_urls.txt"
        mark_checkpoint "live_hosts"
    fi

    {
        echo "# Live Hosts — $TARGET"
        echo ""
        echo "**Total:** $LIVE"
        echo ""
        echo "| URL | Status | Title | Tech | IP | CDN | Server |"
        echo "|-----|--------|-------|------|----|-----|--------|"
        while IFS= read -r line; do echo "| $line |"; done < "$DATADIR/live_all.txt"
    } > "$OUTDIR/live-hosts.md"

    {
        echo "# Redirect Chains — $TARGET"
        echo ""
        for f in "$DATADIR"/redirects_round*.txt; do
            [ -f "$f" ] || continue
            local RNUM
            RNUM=$(basename "$f" | grep -oP '\d+')
            echo "## Round $RNUM"
            echo '```'
            cat "$f" 2>/dev/null
            echo '```'
            echo ""
        done
    } > "$OUTDIR/redirect-chains.md"

    # ==========================================================================
    # STAGE 9: QUICK WINS
    # robots.txt, sitemap.xml (both modes)
    # ==========================================================================
    if check_checkpoint "quick_wins"; then
        _stage 9 "Quick wins -- done, skipping"
    else
        _stage 9 "Quick wins (robots.txt / sitemap.xml)..."
        > "$DATADIR/robots_results.txt"
        > "$DATADIR/sitemap_results.txt"

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            [ "$STAGE_SKIPPED" = true ] && break

            local CURL_BASE=(curl -sk --max-time 10 -A "$CFG_UA")
            [ "$CFG_PROXY" = "true" ] && CURL_BASE+=(--proxy "$PROXY_URL")
            append_headers CURL_BASE -H

            local ROBOTS
            ROBOTS=$("${CURL_BASE[@]}" "$host/robots.txt" 2>/dev/null)
            if echo "$ROBOTS" | grep -iqP '^(User-agent|Disallow|Allow|Sitemap):'; then
                echo "# $host" >> "$DATADIR/robots_results.txt"
                echo "$ROBOTS" >> "$DATADIR/robots_results.txt"
                echo "" >> "$DATADIR/robots_results.txt"
            fi

            local sm STATUS
            for sm in "/sitemap.xml" "/sitemap_index.xml"; do
                STATUS=$("${CURL_BASE[@]}" -o /dev/null -w "%{http_code}" \
                    "$host$sm" 2>/dev/null)
                [ "$STATUS" = "200" ] \
                    && echo "$host$sm" >> "$DATADIR/sitemap_results.txt"
            done
        done < "$DATADIR/live_urls.txt"
        STAGE_SKIPPED=false

        local ROBOTS_COUNT SITEMAP_COUNT
        ROBOTS_COUNT=$(grep -c '^#' "$DATADIR/robots_results.txt" 2>/dev/null || echo 0)
        SITEMAP_COUNT=$(wc -l < "$DATADIR/sitemap_results.txt" 2>/dev/null | tr -d ' ')
        _ok "$ROBOTS_COUNT robots.txt files, $SITEMAP_COUNT sitemaps"
        mark_checkpoint "quick_wins"
    fi

    {
        echo "# Quick Wins — $TARGET"
        echo ""
        echo "## robots.txt"
        echo '```'
        cat "$DATADIR/robots_results.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## Sitemaps"
        echo '```'
        cat "$DATADIR/sitemap_results.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## Favicon Hashes"
        echo '```'
        cat "$DATADIR/favicon_hashes.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/quick-wins.md"

    # ==========================================================================
    # STAGE 10: VIRTUAL HOST FUZZING (skipped in quick mode)
    # Uses baseline response size to filter catch-all responses.
    # ==========================================================================
    VHOST_COUNT=0
    if quick_mode; then
        _stage 10 "VHost fuzzing -- skipped (quick mode)"
        touch "$DATADIR/vhosts_found.txt"
    elif check_checkpoint "vhost_fuzz"; then
        _stage 10 "VHost fuzzing -- done, loading"
        VHOST_COUNT=$(grep -c ',200,\|,301,\|,302,\|,401,\|,403,' \
            "$DATADIR/vhosts_found.txt" 2>/dev/null || echo 0)
    else
        _stage 10 "Virtual host fuzzing (ffuf)..."
        > "$DATADIR/vhosts_found.txt"

        if [ ! -f "$WL_VHOST" ]; then
            _warn "VHost wordlist not found: $WL_VHOST -- skipping"
        elif [ ! -s "$DATADIR/ips_public.txt" ]; then
            _info "No public IPs -- skipping VHost fuzzing"
        else
            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break

                local BASELINE
                BASELINE=$(curl -sk --max-time 5 -o /dev/null -w "%{size_download}" \
                    -H "Host: probe-$(openssl rand -hex 4).$SAFE_TARGET" \
                    -A "$CFG_UA" "https://$ip/" 2>/dev/null || echo "0")
                _info "VHost $ip (catch-all: ${BASELINE}b)"

                local VHOST_CMD=(ffuf -u "https://$ip/" -H "Host: FUZZ.$SAFE_TARGET"
                    -w "$WL_VHOST:FUZZ" -mc "200,301,302,401,403" -fs "$BASELINE"
                    -rate "$CFG_RATE" -t "$CFG_THREADS" -timeout 5
                    -H "User-Agent: $CFG_UA" -of csv
                    -o "/tmp/vhost_${ip//\./_}.csv" -s)
                [ "$CFG_PROXY" = "true" ] && VHOST_CMD+=(-x "$PROXY_URL")
                append_headers VHOST_CMD -H
                skippable "${VHOST_CMD[@]}" 2>/dev/null || true

                if [ -f "/tmp/vhost_${ip//\./_}.csv" ]; then
                    echo "# $ip" >> "$DATADIR/vhosts_found.txt"
                    cat "/tmp/vhost_${ip//\./_}.csv" >> "$DATADIR/vhosts_found.txt"
                    rm -f "/tmp/vhost_${ip//\./_}.csv"
                fi
            done < "$DATADIR/ips_public.txt"
            STAGE_SKIPPED=false

            VHOST_COUNT=$(grep -c ',200,\|,301,\|,302,\|,401,\|,403,' \
                "$DATADIR/vhosts_found.txt" 2>/dev/null || echo 0)
            _ok "$VHOST_COUNT VHost hits"
        fi
        mark_checkpoint "vhost_fuzz"
    fi

    {
        echo "# Virtual Hosts — $TARGET"
        echo ""
        echo "**Hits:** $VHOST_COUNT"
        echo ""
        echo "> Not in DNS -- probe directly with a Host: header."
        echo ""
        echo '```'
        cat "$DATADIR/vhosts_found.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/vhosts.md"

    # ==========================================================================
    # STAGE 11: CLOUD ASSET DISCOVERY (skipped in quick mode)
    # ==========================================================================
    if quick_mode; then
        _stage 11 "Cloud assets -- skipped (quick mode)"
        touch "$DATADIR/cloud_s3.txt" "$DATADIR/cloud_enum_results.txt"
    elif check_checkpoint "cloud_assets"; then
        _stage 11 "Cloud assets -- done, skipping"
    else
        _stage 11 "Cloud asset discovery..."
        > "$DATADIR/cloud_s3.txt"
        > "$DATADIR/cloud_enum_results.txt"

        local CLOUD_KEYWORDS=("$COMPANY" "$SAFE_TARGET" "${COMPANY}-backup"
            "${COMPANY}-assets" "${COMPANY}-static" "${COMPANY}-dev"
            "${COMPANY}-prod" "${COMPANY}-stage" "${COMPANY}-data"
            "${COMPANY}-uploads")

        if command -v s3scanner &>/dev/null; then
            local kw
            for kw in "${CLOUD_KEYWORDS[@]}"; do
                [ "$STAGE_SKIPPED" = true ] && break
                s3scanner scan --bucket "$kw" 2>/dev/null >> "$DATADIR/cloud_s3.txt"
            done
            stage_ok && _ok "s3scanner complete"
        else
            _info "s3scanner not found -- skipping S3 checks"
        fi

        if stage_ok && [ -f "$CLOUD_ENUM" ]; then
            local CLOUD_CMD=(python3 "$CLOUD_ENUM" -k "$COMPANY"
                -o "$DATADIR/cloud_enum_results.txt" --threads "$CFG_THREADS")
            skippable "${CLOUD_CMD[@]}" 2>/dev/null || true
            stage_ok && _ok "cloud_enum complete"
        else
            [ ! -f "$CLOUD_ENUM" ] && _info "cloud_enum.py not found -- skipping"
        fi
        STAGE_SKIPPED=false
        mark_checkpoint "cloud_assets"
    fi

    {
        echo "# Cloud Assets — $TARGET"
        echo ""
        echo "**Keyword:** \`$COMPANY\`"
        echo ""
        echo "## S3 Scanner"
        echo '```'
        cat "$DATADIR/cloud_s3.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## cloud_enum (S3 / Azure / GCP)"
        echo '```'
        cat "$DATADIR/cloud_enum_results.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/cloud-assets.md"

    # ==========================================================================
    # STAGE 12: SCREENSHOTS (skipped in quick mode)
    # ==========================================================================
    if quick_mode; then
        _stage 12 "Screenshots -- skipped (quick mode)"
    elif check_checkpoint "screenshots"; then
        _stage 12 "Screenshots -- done, skipping"
    else
        _stage 12 "Screenshots (gowitness)..."
        local CHROMIUM_BIN
        CHROMIUM_BIN=$(command -v chromium || command -v chromium-browser || echo "")

        local GOWITNESS_CMD=(gowitness scan file -f "$DATADIR/live_urls.txt"
            -s "$SSDIR" --chrome-user-agent "$CFG_UA" --write-none -q)
        [ -n "$CHROMIUM_BIN" ]       && GOWITNESS_CMD+=(--chrome-path "$CHROMIUM_BIN")
        [ "$CFG_PROXY" = "true" ]    && GOWITNESS_CMD+=(--chrome-proxy "$PROXY_URL")
        append_headers GOWITNESS_CMD --chrome-header

        skippable "${GOWITNESS_CMD[@]}" 2>/dev/null \
            && _ok "Screenshots saved to $SSDIR/" \
            || _warn "gowitness failed -- verify chromium is installed (check)"
        STAGE_SKIPPED=false
        mark_checkpoint "screenshots"
    fi

    # ==========================================================================
    # STAGE 13: URL DISCOVERY
    # Quick mode: gau only
    # Full mode:  gau + katana + uro dedup
    # ==========================================================================
    URL_COUNT=0
    if check_checkpoint "url_discovery"; then
        _stage 13 "URL discovery -- done, loading"
        URL_COUNT=$(wc -l < "$DATADIR/urls_all.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 13 "URL discovery$(quick_mode && echo " (quick: gau)" || echo " (gau + katana + uro)")..."

        skippable gau "$SAFE_TARGET" --threads "$CFG_THREADS" --subs 2>/dev/null \
            > "$DATADIR/urls_gau.txt" || touch "$DATADIR/urls_gau.txt"

        if ! quick_mode && stage_ok; then
            local KATANA_INPUT
            if [ -s "$DATADIR/live_urls.txt" ]; then
                KATANA_INPUT="$DATADIR/live_urls.txt"
            else
                sed 's|^|https://|' "$DATADIR/subdomains_all.txt" \
                    > "$DATADIR/katana_input.txt"
                KATANA_INPUT="$DATADIR/katana_input.txt"
            fi
            local KATANA_CMD=(katana -list "$KATANA_INPUT" -depth 3 -js-crawl -silent
                -rate-limit "$CFG_RATE" -o "$DATADIR/urls_katana.txt")
            append_headers KATANA_CMD -H
            skippable "${KATANA_CMD[@]}" 2>/dev/null || touch "$DATADIR/urls_katana.txt"
        else
            touch "$DATADIR/urls_katana.txt"
        fi

        sort -u "$DATADIR/urls_gau.txt" "$DATADIR/urls_katana.txt" 2>/dev/null \
            > "$DATADIR/urls_combined.txt"

        if command -v uro &>/dev/null; then
            uro -i "$DATADIR/urls_combined.txt" -o "$DATADIR/urls_all.txt" 2>/dev/null \
                || cp "$DATADIR/urls_combined.txt" "$DATADIR/urls_all.txt"
        else
            cp "$DATADIR/urls_combined.txt" "$DATADIR/urls_all.txt"
        fi
        STAGE_SKIPPED=false

        URL_COUNT=$(wc -l < "$DATADIR/urls_all.txt" | tr -d ' ')
        local RAW_COUNT
        RAW_COUNT=$(wc -l < "$DATADIR/urls_combined.txt" | tr -d ' ')
        _ok "$URL_COUNT URLs (from $RAW_COUNT raw)"
        mark_checkpoint "url_discovery"
    fi

    {
        echo "# URLs — $TARGET"
        echo ""
        echo "**After dedup:** $URL_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/urls_all.txt"
        echo '```'
    } > "$OUTDIR/urls.md"

    # ==========================================================================
    # STAGE 14: EXTENSION FILTERING
    # ==========================================================================
    EXT_COUNT=0
    if check_checkpoint "ext_filter"; then
        _stage 14 "Extension filtering -- done, loading"
        EXT_COUNT=$(wc -l < "$DATADIR/urls_interesting_ext.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 14 "Extension filtering..."
        local EXTS="php|asp|aspx|jsp|jspx|cfm|cgi|bak|old|backup|sql|db|sqlite|json|xml|yaml|yml|config|conf|env|ini|log|txt|csv|pdf|zip|tar|gz|7z|rar|pem|key|crt|p12|wsdl|wadl|graphql"
        grep -iEP "\.($EXTS)(\?|#|$)" "$DATADIR/urls_all.txt" 2>/dev/null \
            | sort -u > "$DATADIR/urls_interesting_ext.txt"
        EXT_COUNT=$(wc -l < "$DATADIR/urls_interesting_ext.txt" | tr -d ' ')
        _ok "$EXT_COUNT interesting extension URLs"
        mark_checkpoint "ext_filter"
    fi

    {
        echo "# Interesting Extension URLs — $TARGET"
        echo ""
        echo "**Total:** $EXT_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/urls_interesting_ext.txt"
        echo '```'
    } > "$OUTDIR/interesting-ext.md"

    # ==========================================================================
    # STAGE 15: EXPOSURE CHECK (.git, .env, etc.)
    # High ROI. Runs in both modes.
    # ==========================================================================
    EXPOSURE_COUNT=0
    if check_checkpoint "exposure_check"; then
        _stage 15 "Exposure check -- done, loading"
        EXPOSURE_COUNT=$(wc -l < "$DATADIR/exposure_results.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 15 ".git / .env exposure check..."
        > "$DATADIR/exposure_results.txt"

        declare -A EXPOSURE_CHECKS=(
            ["/.git/HEAD"]="ref: refs/"
            ["/.git/config"]="[core]"
            ["/.env"]="APP_|DB_|SECRET|KEY|TOKEN|PASSWORD"
            ["/.env.backup"]="APP_|DB_|SECRET"
            ["/.env.local"]="APP_|DB_|SECRET"
            ["/.env.production"]="APP_|DB_|SECRET"
            ["/.DS_Store"]=""
            ["/config.php"]=""
            ["/wp-config.php.bak"]=""
            ["/database.yml"]="adapter:|database:"
            ["/config/database.yml"]="adapter:|database:"
            ["/.htpasswd"]=""
            ["/server-status"]="Apache Server Status"
            ["/phpinfo.php"]="PHP Version"
            ["/.well-known/security.txt"]="Contact:"
        )

        local host path pattern
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            [ "$STAGE_SKIPPED" = true ] && break

            for path in "${!EXPOSURE_CHECKS[@]}"; do
                [ "$STAGE_SKIPPED" = true ] && break
                pattern="${EXPOSURE_CHECKS[$path]}"

                local CURL_BASE=(curl -sk --max-time 8 -A "$CFG_UA" -w "\n%{http_code}")
                [ "$CFG_PROXY" = "true" ] && CURL_BASE+=(--proxy "$PROXY_URL")
                append_headers CURL_BASE -H

                local RESPONSE STATUS BODY
                RESPONSE=$("${CURL_BASE[@]}" "$host$path" 2>/dev/null)
                STATUS=$(echo "$RESPONSE" | tail -1)
                BODY=$(echo "$RESPONSE" | head -n -1)

                if [ "$STATUS" = "200" ]; then
                    if [ -z "$pattern" ] || echo "$BODY" | grep -qiP "$pattern"; then
                        _warn "EXPOSED: $host$path" | tee -a "$DATADIR/exposure_results.txt"
                    fi
                fi
            done
        done < "$DATADIR/live_urls.txt"
        STAGE_SKIPPED=false

        EXPOSURE_COUNT=$(wc -l < "$DATADIR/exposure_results.txt" | tr -d ' ')
        _ok "$EXPOSURE_COUNT exposure hits"
        mark_checkpoint "exposure_check"
    fi

    {
        echo "# Exposure Checks — $TARGET"
        echo ""
        echo "**Hits:** $EXPOSURE_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/exposure_results.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/exposure.md"

    # ==========================================================================
    # STAGE 16: PARAMETER DISCOVERY
    # Quick mode: paramspider only
    # Full mode:  + x8 active bruteforce (capped at 20 hosts)
    # ==========================================================================
    INT_COUNT=0; X8_COUNT=0
    if check_checkpoint "param_discovery"; then
        _stage 16 "Parameter discovery -- done, loading"
        INT_COUNT=$(wc -l < "$DATADIR/params_interesting.txt" 2>/dev/null | tr -d ' ')
        X8_COUNT=$(wc -l < "$DATADIR/params_x8.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 16 "Parameter discovery$(quick_mode && echo " (quick)" || echo " (full)")..."

        skippable paramspider -d "$TARGET" \
            -o "$DATADIR/params_paramspider_raw.txt" 2>/dev/null \
            || touch "$DATADIR/params_paramspider_raw.txt"

        grep -viP '[?&](unset|undefined|null|none|true|false|FUZZ)=' \
            "$DATADIR/params_paramspider_raw.txt" 2>/dev/null \
            | sort -u > "$DATADIR/params_paramspider.txt"

        local INTERESTING_PARAMS="redirect|url|next|return|dest(ination)?|file|path|include|page|load|fetch|src|href|callback|token|api[_-]?key|key|secret|pass|auth|session|continue|goto|target|uri|link|window|debug|test|preview|format|template|lang|locale|ref|referrer"
        grep -iE "$INTERESTING_PARAMS" "$DATADIR/params_paramspider.txt" 2>/dev/null \
            | sort -u > "$DATADIR/params_interesting.txt"

        INT_COUNT=$(wc -l < "$DATADIR/params_interesting.txt" | tr -d ' ')
        _ok "$INT_COUNT interesting parameters"

        if ! quick_mode && stage_ok && command -v x8 &>/dev/null; then
            grep -P '\[(200|401|403)\]' "$DATADIR/live_all.txt" 2>/dev/null \
                | grep -oP 'https?://[^\s\[]+' \
                | head -20 | sort -u > "$DATADIR/x8_input.txt"

            if [ -s "$DATADIR/x8_input.txt" ]; then
                > "$DATADIR/params_x8.txt"
                local url
                while IFS= read -r url; do
                    [ -z "$url" ] && continue
                    [ "$STAGE_SKIPPED" = true ] && break
                    local X8_CMD=(x8 -u "$url" -w "$WL_COMMON"
                        --output "$DATADIR/params_x8_tmp.txt"
                        -H "User-Agent: $CFG_UA"
                        --workers "$CFG_THREADS")
                    [ "$CFG_PROXY" = "true" ] && X8_CMD+=(-p "$PROXY_URL")
                    append_headers X8_CMD -H
                    skippable "${X8_CMD[@]}" 2>/dev/null || true
                    [ -f "$DATADIR/params_x8_tmp.txt" ] \
                        && cat "$DATADIR/params_x8_tmp.txt" >> "$DATADIR/params_x8.txt"
                    rm -f "$DATADIR/params_x8_tmp.txt"
                done < "$DATADIR/x8_input.txt"
                STAGE_SKIPPED=false
                X8_COUNT=$(wc -l < "$DATADIR/params_x8.txt" | tr -d ' ')
                _ok "$X8_COUNT params from x8"
            fi
        else
            touch "$DATADIR/params_x8.txt"
        fi
        STAGE_SKIPPED=false
        mark_checkpoint "param_discovery"
    fi

    {
        echo "# Parameters — $TARGET"
        echo ""
        echo "## Interesting Parameters ($INT_COUNT)"
        echo '```'
        cat "$DATADIR/params_interesting.txt"
        echo '```'
        echo ""
        echo "## x8 Active Discovery ($X8_COUNT)"
        echo '```'
        cat "$DATADIR/params_x8.txt" 2>/dev/null
        echo '```'
        echo ""
        echo "## All Parameters (paramspider)"
        echo '```'
        sort -u "$DATADIR/params_paramspider.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/parameters.md"

    # ==========================================================================
    # STAGE 17: JS BUNDLE ANALYSIS
    # Quick mode: URL grep only (no download)
    # Full mode:  download to data/js/, build manifest, run LinkFinder
    #
    # To search corpus after run:
    #   grep -rn "pattern" data/js/
    #   grep "<hash>" data/js_manifest.txt   # → source URL
    # ==========================================================================
    JS_COUNT=0; MANIFEST_COUNT=0; EP_COUNT=0
    if check_checkpoint "js_analysis"; then
        _stage 17 "JS analysis -- done, loading"
        JS_COUNT=$(wc -l < "$DATADIR/js_bundles.txt" 2>/dev/null | tr -d ' ')
        MANIFEST_COUNT=$(wc -l < "$DATADIR/js_manifest.txt" 2>/dev/null | tr -d ' ')
        EP_COUNT=$(wc -l < "$DATADIR/js_endpoints.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 17 "JS bundle analysis$(quick_mode && echo " (quick: URL grep)" || echo " (full: download + LinkFinder)")..."

        > "$DATADIR/js_bundles.txt"
        > "$DATADIR/js_endpoints.txt"
        > "$DATADIR/js_manifest.txt"
        rm -f "$JSDIR"/*.js

        # Always: extract JS URLs from discovered URL corpus
        grep -iP '\.js(\?|$)' "$DATADIR/urls_all.txt" 2>/dev/null \
            >> "$DATADIR/js_bundles.txt"

        # Full mode: also use getJS per live host
        if ! quick_mode; then
            local host
            while IFS= read -r host; do
                [ -z "$host" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break
                skippable getJS --url "$host" --resolve 2>/dev/null \
                    >> "$DATADIR/js_bundles.txt"
            done < "$DATADIR/live_urls.txt"
            STAGE_SKIPPED=false
        fi

        sort -u -o "$DATADIR/js_bundles.txt" "$DATADIR/js_bundles.txt"
        JS_COUNT=$(wc -l < "$DATADIR/js_bundles.txt" | tr -d ' ')
        _ok "$JS_COUNT JS files found"

        # Full mode: download each JS file and run LinkFinder / regex fallback
        if ! quick_mode; then
            local js_url JS_HASH JS_FILE FOUND
            while IFS= read -r js_url; do
                [ -z "$js_url" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break

                JS_HASH=$(echo "$js_url" | md5sum | cut -c1-8)
                JS_FILE="$JSDIR/${JS_HASH}.js"

                local CURL_CMD=(curl -sk "$js_url" --max-time 15 -A "$CFG_UA" -o "$JS_FILE")
                [ "$CFG_PROXY" = "true" ] && CURL_CMD+=(--proxy "$PROXY_URL")
                append_headers CURL_CMD -H
                skippable "${CURL_CMD[@]}" 2>/dev/null || true

                if [ -s "$JS_FILE" ]; then
                    printf "%s\t%s\n" "${JS_HASH}.js" "$js_url" >> "$DATADIR/js_manifest.txt"
                    FOUND=$(python3 "$LINKFINDER" -i "$JS_FILE" -o cli 2>/dev/null)
                    if [ -n "$FOUND" ]; then
                        echo "$FOUND" >> "$DATADIR/js_endpoints.txt"
                    else
                        # Regex fallback if LinkFinder returns nothing
                        grep -oP '(?<=["`'"'"'])/[a-zA-Z0-9_\-/\.]+(?=["`'"'"'])' \
                            "$JS_FILE" 2>/dev/null >> "$DATADIR/js_endpoints.txt"
                        grep -oP 'https?://[a-zA-Z0-9._/\-?=&%]+' \
                            "$JS_FILE" 2>/dev/null >> "$DATADIR/js_endpoints.txt"
                    fi
                else
                    rm -f "$JS_FILE"
                fi
            done < "$DATADIR/js_bundles.txt"
            STAGE_SKIPPED=false
        fi

        sort -u -o "$DATADIR/js_endpoints.txt" "$DATADIR/js_endpoints.txt"
        MANIFEST_COUNT=$(wc -l < "$DATADIR/js_manifest.txt" | tr -d ' ')
        EP_COUNT=$(wc -l < "$DATADIR/js_endpoints.txt" | tr -d ' ')
        _ok "$MANIFEST_COUNT downloaded, $EP_COUNT endpoints extracted"
        mark_checkpoint "js_analysis"
    fi

    {
        echo "# JS Bundles — $TARGET"
        echo ""
        echo "**Found:** $JS_COUNT  |  **Downloaded:** $MANIFEST_COUNT  |  **Endpoints:** $EP_COUNT"
        echo ""
        echo "## Searching the corpus"
        echo '```bash'
        echo "grep -rn 'apiKey' data/js/"
        echo "grep 'abc12345' data/js_manifest.txt"
        echo "grep -rl 'pattern' data/js/ | while read f; do"
        echo "  hash=\$(basename \$f .js)"
        echo "  url=\$(grep \"\$hash\" data/js_manifest.txt | cut -f2)"
        echo "  echo \"\$url\"; grep -n 'pattern' \"\$f\""
        echo "done"
        echo '```'
        echo ""
        echo "## Manifest (hash → URL)"
        echo '```'
        cat "$DATADIR/js_manifest.txt"
        echo '```'
        echo ""
        echo "## Extracted Endpoints"
        echo '```'
        cat "$DATADIR/js_endpoints.txt"
        echo '```'
    } > "$OUTDIR/js-bundles.md"

    # ==========================================================================
    # STAGE 18: SECRETS SCANNING
    # TruffleHog (verified only) + targeted regex per downloaded JS file.
    # Each hit is attributed to filename (hash) → resolve URL via manifest.
    # ==========================================================================
    SECRETS_COUNT=0; TH_COUNT=0
    if check_checkpoint "secrets_scan"; then
        _stage 18 "Secrets -- done, loading"
        SECRETS_COUNT=$(wc -l < "$DATADIR/secrets_grep.txt" 2>/dev/null | tr -d ' ')
        TH_COUNT=$(wc -l < "$DATADIR/secrets_trufflehog.json" 2>/dev/null | tr -d ' ')
    else
        _stage 18 "Secrets scanning..."
        > "$DATADIR/secrets_grep.txt"
        > "$DATADIR/secrets_trufflehog.json"

        if [ "$(ls -A "$JSDIR" 2>/dev/null)" ]; then
            # TruffleHog: verified secrets only
            skippable trufflehog filesystem "$JSDIR" --json 2>/dev/null \
                | grep '"Verified":true' > "$DATADIR/secrets_trufflehog.json"
            TH_COUNT=$(wc -l < "$DATADIR/secrets_trufflehog.json" | tr -d ' ')
            _ok "TruffleHog: $TH_COUNT verified"

            if stage_ok; then
                local js_file FNAME
                while IFS= read -r js_file; do
                    [ -f "$js_file" ] || continue
                    FNAME=$(basename "$js_file")
                    {
                        grep -oP 'AKIA[A-Z0-9]{16}' "$js_file" 2>/dev/null \
                            | grep -v 'AKIAIOSFODNN7EXAMPLE' | sed "s|^|$FNAME: AWS_KEY: |"
                        grep -oP 'AIza[0-9A-Za-z\-_]{35}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: FIREBASE: |"
                        grep -oP 'pk_(live|test)_[0-9a-zA-Z]{24,}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: STRIPE_PK: |"
                        grep -oP 'sk_(live|test)_[0-9a-zA-Z]{24,}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: STRIPE_SK: |"
                        grep -oP 'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}' \
                            "$js_file" 2>/dev/null | sed "s|^|$FNAME: SENDGRID: |"
                        grep -oP 'key-[0-9a-zA-Z]{32}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: MAILGUN: |"
                        grep -oP 'xox[bpso]-[0-9a-zA-Z\-]{10,}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: SLACK: |"
                        grep -oP 'gh[pousr]_[A-Za-z0-9_]{36,}' "$js_file" 2>/dev/null \
                            | sed "s|^|$FNAME: GITHUB_TOKEN: |"
                        grep -oP '(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|private[_-]?key)\s*[:=]\s*["\x27][a-zA-Z0-9+/=_\-\.]{20,}["\x27]' \
                            "$js_file" 2>/dev/null \
                            | grep -viP '(your[-_]?value|placeholder|example|changeme|xxxxxxxx|00000000|undefined|null|base64|data:|version|boolean)' \
                            | sed "s|^|$FNAME: SECRET: |"
                    } >> "$DATADIR/secrets_grep.txt"
                done < <(find "$JSDIR" -name '*.js' -type f)
            fi
        else
            # Fallback: grep URL corpus for inline tokens (quick mode or no downloads)
            _info "No JS files downloaded -- grepping URL corpus for inline tokens"
            grep -iP '(api_key|apikey|token|secret|password)=[a-zA-Z0-9+/=_\-]{16,}' \
                "$DATADIR/urls_all.txt" 2>/dev/null \
                | sed 's/^/URL_CORPUS: /' > "$DATADIR/secrets_grep.txt"
        fi
        STAGE_SKIPPED=false

        SECRETS_COUNT=$(wc -l < "$DATADIR/secrets_grep.txt" | tr -d ' ')
        _ok "$SECRETS_COUNT pattern matches, $TH_COUNT verified"
        [ "$SECRETS_COUNT" -gt 0 ] \
            && _info "Resolve source: grep '<hash>' $DATADIR/js_manifest.txt"
        mark_checkpoint "secrets_scan"
    fi

    {
        echo "# Secrets — $TARGET"
        echo ""
        echo "> Each match prefixed with filename (hash)."
        echo "> Resolve to URL: \`grep '<hash>' data/js_manifest.txt\`"
        echo ""
        echo "## TruffleHog (Verified Only)"
        echo '```json'
        cat "$DATADIR/secrets_trufflehog.json"
        echo '```'
        echo ""
        echo "## Pattern Grep (filename: type: value)"
        echo '```'
        cat "$DATADIR/secrets_grep.txt"
        echo '```'
    } > "$OUTDIR/secrets.md"

    # ==========================================================================
    # STAGE 19: TECH-CONDITIONAL SCANNING (skipped in quick mode)
    # Reads httpx tech-detect output; fires targeted tools per framework.
    # ==========================================================================
    TECH_SCAN_COUNT=0
    if quick_mode; then
        _stage 19 "Tech-conditional scan -- skipped (quick mode)"
        touch "$DATADIR/tech_scan_results.txt"
    elif check_checkpoint "tech_scan"; then
        _stage 19 "Tech-conditional scan -- done, loading"
        TECH_SCAN_COUNT=$(wc -l < "$DATADIR/tech_scan_results.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 19 "Tech-conditional scanning..."
        > "$DATADIR/tech_scan_results.txt"

        local WP_HOSTS TOMCAT_HOSTS LARAVEL_HOSTS DRUPAL_HOSTS
        WP_HOSTS=$(grep -iP '\[WordPress' "$DATADIR/live_all.txt" 2>/dev/null \
            | grep -oP 'https?://[^\s\[]+' | sort -u)
        TOMCAT_HOSTS=$(grep -iP '\[Apache Tomcat' "$DATADIR/live_all.txt" 2>/dev/null \
            | grep -oP 'https?://[^\s\[]+' | sort -u)
        LARAVEL_HOSTS=$(grep -iP '\[Laravel' "$DATADIR/live_all.txt" 2>/dev/null \
            | grep -oP 'https?://[^\s\[]+' | sort -u)
        DRUPAL_HOSTS=$(grep -iP '\[Drupal' "$DATADIR/live_all.txt" 2>/dev/null \
            | grep -oP 'https?://[^\s\[]+' | sort -u)

        if [ -n "$WP_HOSTS" ]; then
            echo "# WORDPRESS" >> "$DATADIR/tech_scan_results.txt"
            local host
            while IFS= read -r host; do
                [ -z "$host" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break
                if command -v wpscan &>/dev/null; then
                    local WPSCAN_CMD=(wpscan --url "$host" --no-update
                        --enumerate vp,u --random-user-agent --format cli-no-colour)
                    [ "$CFG_PROXY" = "true" ] && WPSCAN_CMD+=(--proxy "$PROXY_URL")
                    echo "## $host" >> "$DATADIR/tech_scan_results.txt"
                    # wpscan has its own timeout behaviour; cap externally too
                    skippable_timeout 120 "${WPSCAN_CMD[@]}" 2>/dev/null \
                        >> "$DATADIR/tech_scan_results.txt" || true
                else
                    echo "$host: WordPress -- install wpscan for full enum" \
                        >> "$DATADIR/tech_scan_results.txt"
                fi
            done <<< "$WP_HOSTS"
            STAGE_SKIPPED=false
        fi

        if [ -n "$TOMCAT_HOSTS" ]; then
            echo "" >> "$DATADIR/tech_scan_results.txt"
            echo "# TOMCAT MANAGER" >> "$DATADIR/tech_scan_results.txt"
            local host path STATUS
            while IFS= read -r host; do
                [ -z "$host" ] && continue
                for path in /manager/html /host-manager/html /manager/status; do
                    STATUS=$(curl -sk --max-time 8 -A "$CFG_UA" \
                        -o /dev/null -w "%{http_code}" "$host$path" 2>/dev/null)
                    [ "$STATUS" != "000" ] \
                        && echo "$host$path [$STATUS]" >> "$DATADIR/tech_scan_results.txt"
                done
            done <<< "$TOMCAT_HOSTS"
        fi

        if [ -n "$LARAVEL_HOSTS" ]; then
            echo "" >> "$DATADIR/tech_scan_results.txt"
            echo "# LARAVEL DEBUG" >> "$DATADIR/tech_scan_results.txt"
            local host CURL_BASE RESP
            while IFS= read -r host; do
                [ -z "$host" ] && continue
                CURL_BASE=(curl -sk --max-time 8 -A "$CFG_UA")
                [ "$CFG_PROXY" = "true" ] && CURL_BASE+=(--proxy "$PROXY_URL")
                RESP=$("${CURL_BASE[@]}" "$host/_ignition/health-check" 2>/dev/null)
                echo "$RESP" | grep -qi '"healthy"' \
                    && echo "[!] $host: Laravel Ignition exposed" \
                    >> "$DATADIR/tech_scan_results.txt"
            done <<< "$LARAVEL_HOSTS"
        fi

        if [ -n "$DRUPAL_HOSTS" ]; then
            echo "" >> "$DATADIR/tech_scan_results.txt"
            echo "# DRUPAL (consider droopescan, CVE-2018-7600)" \
                >> "$DATADIR/tech_scan_results.txt"
            echo "$DRUPAL_HOSTS" >> "$DATADIR/tech_scan_results.txt"
        fi

        TECH_SCAN_COUNT=$(grep -c '^\[!\]\|^##\|^\S.*\[200\]' \
            "$DATADIR/tech_scan_results.txt" 2>/dev/null || echo 0)
        _ok "$TECH_SCAN_COUNT tech-conditional findings"
        mark_checkpoint "tech_scan"
    fi

    {
        echo "# Tech-Conditional Scanning — $TARGET"
        echo ""
        echo "**Findings:** $TECH_SCAN_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/tech_scan_results.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/tech-scan.md"

    # ==========================================================================
    # STAGE 20: 403 BYPASS (skipped in quick mode)
    # byp4xx: header injection, path case, double slash, ..;/
    # ==========================================================================
    BYPASS_COUNT=0
    if quick_mode; then
        _stage 20 "403 bypass -- skipped (quick mode)"
        touch "$DATADIR/403_bypass.txt"
    elif check_checkpoint "bypass_403"; then
        _stage 20 "403 bypass -- done, loading"
        BYPASS_COUNT=$(wc -l < "$DATADIR/403_bypass.txt" 2>/dev/null | tr -d ' ')
    else
        _stage 20 "403 bypass (byp4xx)..."
        > "$DATADIR/403_bypass.txt"

        {
            grep -oP 'https?://[^\s\[]+(?=.*\[403\])' "$DATADIR/live_all.txt" 2>/dev/null
            grep -oP 'https?://[^\s,]+' "$DATADIR/directories.txt" 2>/dev/null \
                | grep '403'
        } | sort -u > "$DATADIR/403_targets.txt"

        if [ ! -s "$DATADIR/403_targets.txt" ]; then
            _info "No 403 targets -- skipping"
        elif ! command -v byp4xx &>/dev/null; then
            _info "byp4xx not found (go install github.com/lobuhi/byp4xx@latest)"
        else
            local url
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                [ "$STAGE_SKIPPED" = true ] && break
                _info "byp4xx: $url"
                skippable byp4xx "$url" 2>/dev/null >> "$DATADIR/403_bypass.txt" || true
            done < "$DATADIR/403_targets.txt"
            STAGE_SKIPPED=false

            BYPASS_COUNT=$(grep -c '200\|20[0-9]' "$DATADIR/403_bypass.txt" \
                2>/dev/null || echo 0)
            _ok "$BYPASS_COUNT bypasses"
        fi
        mark_checkpoint "bypass_403"
    fi

    {
        echo "# 403 Bypass — $TARGET"
        echo ""
        echo "**Bypasses (2xx):** $BYPASS_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/403_bypass.txt" 2>/dev/null
        echo '```'
    } > "$OUTDIR/403-bypass.md"

    # ==========================================================================
    # STAGE 21: NUCLEI + CORS
    # Quick mode: takeover + token only
    # Full mode:  exposure, misconfiguration, takeover, token, cors
    # nuclei is wrapped with skippable_timeout so Ctrl+C actually kills it.
    # ==========================================================================
    NUCLEI_COUNT=0; CORS_COUNT=0
    if check_checkpoint "nuclei_cors"; then
        _stage 21 "Nuclei + CORS -- done, loading"
        NUCLEI_COUNT=$(wc -l < "$DATADIR/nuclei_results.txt" 2>/dev/null | tr -d ' ')
        CORS_COUNT=$(grep -c 'CORS' "$DATADIR/cors_results.txt" 2>/dev/null || echo 0)
    else
        > "$DATADIR/nuclei_results.txt"
        > "$DATADIR/cors_results.txt"

        if [ "$CFG_NUCLEI" != "true" ]; then
            _stage 21 "Nuclei -- disabled (set nuclei true to enable)"
        else
            local NUCLEI_TAGS
            if quick_mode; then
                NUCLEI_TAGS="takeover,token"
                _stage 21 "Nuclei (quick: takeover + token)..."
            else
                NUCLEI_TAGS="exposure,misconfiguration,takeover,token,cors"
                _stage 21 "Nuclei + CORS (full)..."
            fi

            grep -viP '(cdn|static|assets|img\.|images\.|fonts\.|media\.)' \
                "$DATADIR/live_urls.txt" > "$DATADIR/nuclei_input.txt"
            [ ! -s "$DATADIR/nuclei_input.txt" ] \
                && cp "$DATADIR/live_urls.txt" "$DATADIR/nuclei_input.txt"

            local NUCLEI_CMD=(nuclei -l "$DATADIR/nuclei_input.txt"
                -tags "$NUCLEI_TAGS" -severity "medium,high,critical"
                -pt http -rate-limit "$CFG_RATE" -c "$CFG_THREADS"
                -bs 25 -timeout 5 -stats -o "$DATADIR/nuclei_results.txt")
            [ "$CFG_PROXY" = "true" ] && NUCLEI_CMD+=(-http-proxy "$PROXY_URL")
            append_headers NUCLEI_CMD -H

            if [ "${CFG_NUCLEI_TIMEOUT:-0}" -gt 0 ] 2>/dev/null; then
                skippable_timeout "$CFG_NUCLEI_TIMEOUT" "${NUCLEI_CMD[@]}" \
                    2>/tmp/nuclei_err.txt \
                    || _info "nuclei finished or timed out (${CFG_NUCLEI_TIMEOUT}s)"
            else
                skippable "${NUCLEI_CMD[@]}" 2>/tmp/nuclei_err.txt || true
            fi

            touch "$DATADIR/nuclei_results.txt"
            NUCLEI_COUNT=$(wc -l < "$DATADIR/nuclei_results.txt" | tr -d ' ')
            _ok "$NUCLEI_COUNT nuclei findings"

            if ! quick_mode && stage_ok && [ -f "$CORSY" ]; then
                local CORSY_CMD=(python3 "$CORSY" -i "$DATADIR/live_urls.txt"
                    -t "$CFG_THREADS" -q)
                skippable "${CORSY_CMD[@]}" 2>/dev/null \
                    > "$DATADIR/cors_results.txt" || true
                CORS_COUNT=$(grep -c 'CORS' "$DATADIR/cors_results.txt" 2>/dev/null || echo 0)
                _ok "corsy: $CORS_COUNT issues"
            fi
        fi
        STAGE_SKIPPED=false
        mark_checkpoint "nuclei_cors"
    fi

    {
        echo "# Nuclei + CORS — $TARGET"
        echo ""
        echo "**Nuclei:** $NUCLEI_COUNT  |  **Corsy:** $CORS_COUNT"
        echo ""
        echo "## Nuclei"
        echo '```'
        cat "$DATADIR/nuclei_results.txt"
        echo '```'
        echo ""
        echo "## Corsy"
        echo '```'
        cat "$DATADIR/cors_results.txt"
        echo '```'
    } > "$OUTDIR/nuclei.md"

    # ==========================================================================
    # STAGE 22: DIRECTORY BRUTEFORCE (skipped in quick mode)
    # Only runs against hosts returning 200/401/403.
    # Capped per-host at 120s to prevent a slow host from blocking the queue.
    # ==========================================================================
    DIR_COUNT=0
    if quick_mode; then
        _stage 22 "Directory bruteforce -- skipped (quick mode)"
        touch "$DATADIR/directories.txt"
    elif check_checkpoint "dir_brute"; then
        _stage 22 "Directory bruteforce -- done, loading"
        DIR_COUNT=$(grep -c '200\|401\|403' "$DATADIR/directories.txt" 2>/dev/null || echo 0)
    else
        _stage 22 "Directory bruteforce (ffuf)..."
        > "$DATADIR/directories.txt"

        if [ ! -f "$WL_COMMON" ]; then
            _warn "Wordlist not found: $WL_COMMON -- skipping"
        else
            grep -P '\[(200|401|403)\]' "$DATADIR/live_all.txt" 2>/dev/null \
                | grep -oP 'https?://[^\s\[]+' \
                | sort -u > "$DATADIR/ffuf_input.txt"

            if [ ! -s "$DATADIR/ffuf_input.txt" ]; then
                _info "No 200/401/403 hosts -- skipping"
            else
                local host
                while IFS= read -r host; do
                    [ -z "$host" ] && continue
                    [ "$STAGE_SKIPPED" = true ] && break
                    _info "ffuf: $host"

                    local FFUF_CMD=(ffuf -u "$host/FUZZ" -w "$WL_COMMON:FUZZ"
                        -mc "200,401,403" -rate "$CFG_RATE" -t "$CFG_THREADS"
                        -timeout 5 -H "User-Agent: $CFG_UA"
                        -of csv -o "/tmp/ffuf_tmp.csv" -s)
                    [ "$CFG_PROXY" = "true" ] && FFUF_CMD+=(-x "$PROXY_URL")
                    append_headers FFUF_CMD -H
                    # Per-host cap: 120s. Uses skippable_timeout so Ctrl+C kills ffuf.
                    skippable_timeout 120 "${FFUF_CMD[@]}" 2>/tmp/ffuf_err.txt || true

                    if [ -f "/tmp/ffuf_tmp.csv" ]; then
                        echo "# $host" >> "$DATADIR/directories.txt"
                        cat "/tmp/ffuf_tmp.csv" >> "$DATADIR/directories.txt"
                        rm -f "/tmp/ffuf_tmp.csv"
                    fi
                done < "$DATADIR/ffuf_input.txt"
                STAGE_SKIPPED=false
            fi
        fi

        DIR_COUNT=$(grep -c '200\|401\|403' "$DATADIR/directories.txt" 2>/dev/null || echo 0)
        _ok "$DIR_COUNT directory hits"
        mark_checkpoint "dir_brute"
    fi

    {
        echo "# Directories — $TARGET"
        echo ""
        echo "**Total hits:** $DIR_COUNT"
        echo ""
        echo '```'
        cat "$DATADIR/directories.txt"
        echo '```'
    } > "$OUTDIR/directories.md"

    # ==========================================================================
    # STAGE 23: XSS SCAN (exploit mode only)
    # ==========================================================================
    XSS_COUNT=0
    if [ "$CFG_EXPLOIT" = "true" ]; then
        if check_checkpoint "xss_scan"; then
            _stage 23 "XSS scan -- done, loading"
            XSS_COUNT=$(wc -l < "$DATADIR/xss_results.txt" 2>/dev/null | tr -d ' ')
        else
            _stage 23 "XSS scan (dalfox, exploit mode)..."
            if ! command -v dalfox &>/dev/null; then
                _info "dalfox not found -- skipping XSS scan"
                touch "$DATADIR/xss_results.txt"
            elif [ ! -s "$DATADIR/params_paramspider.txt" ]; then
                _info "No paramspider output -- skipping XSS scan"
                touch "$DATADIR/xss_results.txt"
            else
                local DALFOX_CMD=(dalfox file "$DATADIR/params_paramspider.txt"
                    --output "$DATADIR/xss_results.txt"
                    --user-agent "$CFG_UA")
                [ "$CFG_PROXY" = "true" ] && DALFOX_CMD+=(--proxy "$PROXY_URL")
                append_headers DALFOX_CMD --header
                skippable "${DALFOX_CMD[@]}" 2>/dev/null || true
            fi
            STAGE_SKIPPED=false
            XSS_COUNT=$(wc -l < "$DATADIR/xss_results.txt" 2>/dev/null | tr -d ' ')
            _ok "$XSS_COUNT XSS findings"
            mark_checkpoint "xss_scan"
        fi

        {
            echo "# XSS Findings — $TARGET"
            echo ""
            echo "**Total:** $XSS_COUNT"
            echo ""
            echo '```'
            cat "$DATADIR/xss_results.txt"
            echo '```'
        } > "$OUTDIR/xss.md"
    else
        _stage 23 "XSS scan -- skipped (set exploit true to enable)"
    fi

    # ==========================================================================
    # STAGE 24: OBSIDIAN SUMMARY
    # ==========================================================================
    _stage 24 "Writing Obsidian summary..."

    local RUN_END RUN_DURATION RUN_MINS RUN_SECS
    RUN_END=$(date +%s)
    RUN_DURATION=$(( RUN_END - RUN_START ))
    RUN_MINS=$(( RUN_DURATION / 60 ))
    RUN_SECS=$(( RUN_DURATION % 60 ))

    {
        echo "# $TARGET — Recon Summary"
        echo ""
        echo "**Date:** $(date)"
        echo "**Duration:** ${RUN_MINS}m ${RUN_SECS}s"
        [ -n "$ACTIVE_PROGRAM" ] && echo "**Program:** $ACTIVE_PROGRAM"
        echo "**Mode:** $CFG_MODE"
        echo "**Proxy:** $CFG_PROXY  |  **Exploit:** $CFG_EXPLOIT"
        echo "**Portscan:** $CFG_PORTSCAN  |  **Nuclei:** $CFG_NUCLEI"
        echo ""
        echo "---"
        echo ""
        echo "## Stats"
        echo ""
        echo "| Stage | Count |"
        echo "|-------|-------|"
        echo "| Subdomains (passive) | $COUNT |"
        echo "| Subdomains (bruteforce) | $BRUTE_COUNT |"
        echo "| Public IPs | $IP_COUNT |"
        [ "${IP_LEAKED:-0}" -gt 0 ] \
            && echo "| ⚠ Internal IPs in Public DNS | $IP_LEAKED |"
        echo "| CIDRs | $CIDR_COUNT |"
        echo "| Live Hosts | $LIVE |"
        echo "| VHost Hits | $VHOST_COUNT |"
        echo "| URLs | $URL_COUNT |"
        echo "| Interesting Extensions | $EXT_COUNT |"
        echo "| Exposure Hits | $EXPOSURE_COUNT |"
        echo "| Interesting Params | $INT_COUNT |"
        echo "| x8 Params | $X8_COUNT |"
        echo "| JS Files | $JS_COUNT |"
        echo "| JS Downloaded | $MANIFEST_COUNT |"
        echo "| JS Endpoints | $EP_COUNT |"
        echo "| Secrets (grep) | $SECRETS_COUNT |"
        echo "| Secrets (verified) | $TH_COUNT |"
        echo "| Tech Scan Findings | $TECH_SCAN_COUNT |"
        echo "| 403 Bypasses | $BYPASS_COUNT |"
        echo "| Nuclei Findings | $NUCLEI_COUNT |"
        echo "| CORS Issues | $CORS_COUNT |"
        echo "| Directory Hits | $DIR_COUNT |"
        [ "$CFG_EXPLOIT" = "true" ] && echo "| XSS Findings | $XSS_COUNT |"
        echo ""
        echo "---"
        echo ""
        echo "## Linked Notes"
        echo ""
        for note in subdomains dns-records dns-resolution asn-cidrs shodan \
                    portscan live-hosts quick-wins vhosts cloud-assets \
                    redirect-chains urls interesting-ext exposure parameters \
                    js-bundles secrets tech-scan 403-bypass nuclei directories; do
            echo "- [[$note]]"
        done
        [ "$CFG_EXPLOIT" = "true" ] && echo "- [[xss]]"
        echo ""
        echo "---"
        echo ""
        echo "## Notes"
        echo ""
        echo "<!-- your notes here -->"
    } > "$OUTDIR/$TARGET.md"

    mark_checkpoint "summary"

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${GREEN} COMPLETE: $TARGET${RESET}"
    [ -n "$ACTIVE_PROGRAM" ] && echo " Program:  $ACTIVE_PROGRAM"
    echo " Duration: ${RUN_MINS}m ${RUN_SECS}s"
    echo " Output:   $OUTDIR"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""

    notify_complete "$TARGET" "$RUN_DURATION"

    trap - EXIT
    return 0
}

# ==============================================================================
# HELP TEXT
# ==============================================================================

show_help() {
    echo ""
    echo -e "${BOLD}FOXHUNT v5.0${RESET} -- bug bounty recon shell"
    echo ""
    echo -e "${BOLD}Workflow:${RESET}"
    echo "  set program <name>              create/open a program"
    echo "  set scope <domains|file>        set scope (CSV, newline, or .txt file)"
    echo "  verify scope                    list current scope"
    echo "  set target <domain>             set target (warns if out of scope)"
    echo "  run                             run pipeline (resumes from checkpoint)"
    echo "  run fresh                       run pipeline from scratch"
    echo ""
    echo -e "${BOLD}Config (saved per-program):${RESET}"
    echo "  set mode <full|quick>           scan depth (default: full)"
    echo "  set proxy <true|false>          route through proxy"
    echo "  set proxy-port <port>           proxy port (default: 8080)"
    echo "  set exploit <true|false>        enable XSS stage"
    echo "  set portscan <true|false>       port scan (default: false, check scope)"
    echo "  set nuclei <true|false>         run nuclei (default: true)"
    echo "  set nuclei-timeout <sec>        hard cap (default: 300, 0=none)"
    echo "  set httpx-timeout <sec>         per-request timeout (default: 10)"
    echo "  set asnmap-timeout <sec>        asnmap cap (default: 90, 0=none)"
    echo "  set notify <true|false>         desktop notification on complete"
    echo "  set rate <n>                    req/sec (default: 50)"
    echo "  set threads <n>                 thread count (default: 10)"
    echo "  set dns <ip>                    resolver (default: 8.8.8.8)"
    echo "  set ua <string>                 user agent"
    echo "  set header \"Key: Value\"         add custom header (stacks)"
    echo "  unset header \"Key: Value\"       remove a header"
    echo "  unset headers                   clear all headers"
    echo "  unset scope                     clear scope"
    echo "  unset target                    clear active target"
    echo "  unset program                   leave program, enter no-program mode"
    echo ""
    echo -e "${BOLD}Info:${RESET}"
    echo "  show                            current session state"
    echo "  programs                        list all programs"
    echo "  check                           verify toolchain"
    echo "  help                            this screen"
    echo "  exit / quit                     leave foxhunt"
    echo ""
    echo -e "${BOLD}No-program mode:${RESET}"
    echo "  set target example.com"
    echo "  run"
    echo "  Output goes to: $BOUNTY_DIR/no-program/<target>/"
    echo ""
}

# ==============================================================================
# DISPATCH -- handles both interactive and single-shot CLI
# ==============================================================================

_dispatch() {
    local cmd="${1:-}"; shift 2>/dev/null || true


    case "$cmd" in
        set)
            local sub="${1:-}"; shift 2>/dev/null || true
            # "verify scope" is a two-word command
            if [ "$sub" = "verify" ] && [ "${1:-}" = "scope" ]; then
                cmd_verify_scope
            else
                cmd_set "$sub" "$@"
            fi
            ;;
        unset)    cmd_unset "$@" ;;
        verify)
            # Allow "verify scope" at top level too
            [ "${1:-}" = "scope" ] && cmd_verify_scope || _err "Unknown: verify $*"
            ;;
        show)     cmd_show ;;
        programs) cmd_programs ;;
        check)    cmd_check ;;
        run)      cmd_run "${1:-}" ;;
        clear)    cmd_clear ;;
        help|"?") show_help ;;
        exit|quit)
            echo "Goodbye."
            exit 0
            ;;
        "")       show_help ;;
        *)
            _err "Unknown command: $cmd"
            echo "  Type 'help' for usage."
            return 1
            ;;
    esac
}

# ==============================================================================
# ENTRYPOINT
# ==============================================================================

load_state

# Guard: if this script is being sourced (e.g. for testing), don't run the
# interactive loop. Only run when executed directly.
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && return 0

# ── Single-shot mode: foxhunt <cmd> [args] ────────────────────────────────────
if [ $# -gt 0 ]; then
    trap '_sigint_exit' INT
    _dispatch "$@"
    exit $?
fi

# ── Interactive shell mode ────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║  FOXHUNT v5.0  bug bounty recon      ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════╝${RESET}"
echo ""

# Show resume state if anything is active
if [ -n "$ACTIVE_PROGRAM" ]; then
    _ok "Resumed program: $ACTIVE_PROGRAM"
    [ -n "$ACTIVE_TARGET" ] && _ok "Active target:   $ACTIVE_TARGET"
elif [ -n "$ACTIVE_TARGET" ]; then
    _ok "Active target (no-program mode): $ACTIVE_TARGET"
fi

echo "  Type 'help' for usage, 'show' for current session."
echo ""

# Set up signals for interactive mode
trap '_sigint_exit' INT

start_foxhunt_shell() {
    while true; do
        # Build a prompt showing current context
        local PROMPT_PROG="${ACTIVE_PROGRAM:-}"
        local PROMPT_TARGET="${ACTIVE_TARGET:-}"
        local _PS_STR

        if [ -n "$PROMPT_PROG" ] && [ -n "$PROMPT_TARGET" ]; then
            _PS_STR="[foxhunt:${PROMPT_PROG}:${PROMPT_TARGET}]"
        elif [ -n "$PROMPT_PROG" ]; then
            _PS_STR="[foxhunt:${PROMPT_PROG}]"
        elif [ -n "$PROMPT_TARGET" ]; then
            _PS_STR="[foxhunt:${PROMPT_TARGET}]"
        else
            _PS_STR="[foxhunt]"
        fi

        # Define colors properly for the 'read' prompt
        local CYAN=$'\e[0;36m'
        local RESET=$'\e[0m'
        local FULL_PROMPT="${CYAN}${_PS_STR}${RESET}> "

        local line
        if ! IFS= read -r -e -p "$FULL_PROMPT" line; then
            echo -e "\nGoodbye."
            exit 0
        fi

        # EOF or blank
        [[ -z "$line" ]] && continue

        # Add to history
        history -s "$line" 2>/dev/null || true

        # Tokenise and dispatch
        local -a tokens
        read -ra tokens <<< "$line"

        # Re-set INT trap
        trap '_sigint_exit' INT

        _dispatch "${tokens[@]}"
    done
}

# Execute the function
start_foxhunt_shell