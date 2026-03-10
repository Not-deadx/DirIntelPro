#!/usr/bin/env bash
# =============================================================================
#  SecureDirInspector - Professional Directory Analysis Tool
#  Version : 1.0.0
#  Purpose : Authorized security testing — directory enumeration & analysis
# =============================================================================
#
#  LEGAL DISCLAIMER:
#  This tool is intended ONLY for use on systems you own or have explicit
#  written permission to test. Unauthorized use is ILLEGAL and UNETHICAL.
#  The author assumes NO liability for misuse of this tool.
#
#  "Use only on systems you own or have permission to test."
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
readonly VERSION="1.0.0"
readonly TOOL_NAME="SecureDirInspector"
readonly RESULTS_DIR="results"
readonly MAX_THREADS=10
readonly DEFAULT_DELAY=1
readonly REQUEST_TIMEOUT=10
readonly MAX_REDIRECTS=3

readonly SENSITIVE_DIRS=("admin" "backup" ".git" ".env" "config" "database" "debug" "test" "private" "uploads")
readonly SENSITIVE_EXTS=(".zip" ".sql" ".env" ".bak" ".tar" ".gz" ".log")
readonly DATA_KEYWORDS=("password" "token" "key" "secret" "DB_HOST" "API_KEY")

# Colors
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────
AUTHORIZED=false
DOMAIN_LIST=""
SINGLE_URL=""
WORDLIST=""
EXTENSIONS=()
DELAY=$DEFAULT_DELAY
THREADS=5
VERBOSE=false
SCAN_START_TIME=""

TOTAL_REQUESTS=0
TOTAL_200=0
TOTAL_403=0
TOTAL_REDIRECTS=0
TOTAL_HIGH_RISK=0
TOTAL_SENSITIVE=0
TOTAL_EXPOSURE=0

# ─────────────────────────────────────────────────────────────────────────────
# TRAP: Graceful Ctrl+C exit
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}[!] Scan interrupted by user (Ctrl+C).${RESET}"
    echo -e "${CYAN}[*] Partial results saved to: ${RESULTS_DIR}/${RESET}"
    exit 130
}
trap cleanup SIGINT SIGTERM

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log_info()     { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()       { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn()     { echo -e "${YELLOW}[!]${RESET} $*"; }
log_error()    { echo -e "${RED}[-]${RESET} $*" >&2; }
log_verbose()  { [[ "$VERBOSE" == true ]] && echo -e "${BLUE}[v]${RESET} $*" || true; }
log_high()     { echo -e "${RED}${BOLD}[HIGH RISK]${RESET} $*"; }
log_sensitive(){ echo -e "${MAGENTA}[SENSITIVE]${RESET} $*"; }

timestamp()    { date '+%Y-%m-%d %H:%M:%S'; }

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────
sanitize_domain() {
    local raw="$1"
    raw="${raw#http://}"
    raw="${raw#https://}"
    raw="${raw%%/*}"
    echo "$raw" | tr -d '[:space:]' | tr '/' '_' | tr ':' '_'
}

normalize_url() {
    local url="$1"
    [[ ! "$url" =~ ^https?:// ]] && url="http://${url}"
    url="${url%/}"
    echo "$url"
}

ensure_dir()    { mkdir -p "$1"; }
write_result()  { echo "$2" >> "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_dependencies() {
    local missing=()
    for dep in curl awk sed grep date wc; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi
    log_ok "All dependencies satisfied."
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║         SecureDirInspector v${VERSION}                          ║"
    echo "  ║       Professional Directory Analysis Tool                  ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}${BOLD}  ⚠  WARNING — AUTHORIZED USE ONLY  ⚠${RESET}"
    echo ""
    echo -e "${YELLOW}  ┌──────────────────────────────────────────────────────────┐"
    echo    "  │  This tool is for AUTHORIZED SECURITY TESTING ONLY.       │"
    echo    "  │  Unauthorized use is ILLEGAL and UNETHICAL.                │"
    echo    "  │  Use only on systems you OWN or have WRITTEN PERMISSION    │"
    echo    "  │  to test. The author assumes NO liability for misuse.      │"
    echo -e "  └──────────────────────────────────────────────────────────┘${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTHORIZATION GATE
# ─────────────────────────────────────────────────────────────────────────────
require_authorization() {
    if [[ "$AUTHORIZED" != true ]]; then
        echo -e "${RED}${BOLD}[BLOCKED]${RESET} This tool requires explicit authorization."
        echo ""
        echo -e "  Pass ${BOLD}--authorized${RESET} to confirm you have permission to test the target."
        echo ""
        echo -e "  ${CYAN}Example:${RESET}"
        echo    "    ./SecureDirInspector.sh --authorized --url https://example.com --wordlist wordlist.txt"
        echo ""
        echo -e "${YELLOW}  Use only on systems you own or have permission to test.${RESET}"
        echo ""
        exit 1
    fi
    echo -e "${GREEN}${BOLD}[✓] Authorization confirmed. Proceeding with scan.${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $0 --authorized [OPTIONS]"
    echo ""
    echo -e "${BOLD}Required:${RESET}"
    echo "  --authorized              Confirm you have permission to test the target"
    echo "  --wordlist <file>         Path to directory wordlist"
    echo ""
    echo -e "${BOLD}Target (one required):${RESET}"
    echo "  --url <url>               Single target URL"
    echo "  --domain-list <file>      File with one domain per line"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  --extensions <ext,...>    Comma-separated extensions (e.g. php,html,txt)"
    echo "  --delay <seconds>         Delay between requests (default: ${DEFAULT_DELAY}s, min: 0.5)"
    echo "  --threads <n>             Parallel threads (default: 5, max: ${MAX_THREADS})"
    echo "  --verbose                 Enable verbose output"
    echo "  --help                    Show this help"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 --authorized --url https://example.com --wordlist common.txt"
    echo "  $0 --authorized --domain-list targets.txt --wordlist dirs.txt --extensions php,html"
    echo "  $0 --authorized --url https://example.com --wordlist dirs.txt --delay 2 --threads 3"
    echo ""
    echo -e "${YELLOW}  Use only on systems you own or have permission to test.${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
parse_args() {
    if [[ $# -eq 0 ]]; then
        print_banner
        usage
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --authorized)
                AUTHORIZED=true
                shift ;;
            --url)
                SINGLE_URL="${2:-}"
                [[ -z "$SINGLE_URL" ]] && { log_error "--url requires a value"; exit 1; }
                shift 2 ;;
            --domain-list)
                DOMAIN_LIST="${2:-}"
                [[ -z "$DOMAIN_LIST" ]] && { log_error "--domain-list requires a file path"; exit 1; }
                [[ ! -f "$DOMAIN_LIST" ]] && { log_error "File not found: $DOMAIN_LIST"; exit 1; }
                shift 2 ;;
            --wordlist)
                WORDLIST="${2:-}"
                [[ -z "$WORDLIST" ]] && { log_error "--wordlist requires a file path"; exit 1; }
                [[ ! -f "$WORDLIST" ]] && { log_error "Wordlist not found: $WORDLIST"; exit 1; }
                shift 2 ;;
            --extensions)
                local ext_raw="${2:-}"
                [[ -z "$ext_raw" ]] && { log_error "--extensions requires a value"; exit 1; }
                IFS=',' read -ra EXTENSIONS <<< "$ext_raw"
                shift 2 ;;
            --delay)
                DELAY="${2:-$DEFAULT_DELAY}"
                if awk "BEGIN{exit !($DELAY < 0.5)}"; then
                    log_warn "Minimum delay is 0.5s (no aggressive traffic). Setting to 0.5s."
                    DELAY=0.5
                fi
                shift 2 ;;
            --threads)
                THREADS="${2:-5}"
                [[ "$THREADS" -gt "$MAX_THREADS" ]] && { log_warn "Capping threads at ${MAX_THREADS}."; THREADS=$MAX_THREADS; }
                [[ "$THREADS" -lt 1 ]] && THREADS=1
                shift 2 ;;
            --verbose)
                VERBOSE=true
                shift ;;
            --help|-h)
                print_banner
                usage
                exit 0 ;;
            *)
                log_error "Unknown argument: $1"
                usage
                exit 1 ;;
        esac
    done

    [[ -z "$WORDLIST" ]] && { log_error "Wordlist required. Use --wordlist <file>"; exit 1; }
    [[ -z "$SINGLE_URL" && -z "$DOMAIN_LIST" ]] && { log_error "Target required. Use --url or --domain-list"; exit 1; }
}

# ─────────────────────────────────────────────────────────────────────────────
# SETUP RESULT DIRECTORIES FOR A DOMAIN
# ─────────────────────────────────────────────────────────────────────────────
setup_results_dir() {
    local domain_safe="$1"
    local base="${RESULTS_DIR}/${domain_safe}"

    ensure_dir "${RESULTS_DIR}"
    ensure_dir "${base}"
    ensure_dir "${base}/categorized"

    : > "${base}/categorized/200_ok.txt"
    : > "${base}/categorized/403.txt"
    : > "${base}/categorized/redirects.txt"
    : > "${base}/categorized/other.txt"
    : > "${base}/high_risk_paths.txt"
    : > "${base}/sensitive_files.txt"
    : > "${base}/potential_data_exposure.txt"
    : > "${base}/logs.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 1: LIVE HOST DETECTION
# ─────────────────────────────────────────────────────────────────────────────
check_live_host() {
    local raw_url="$1"
    local url
    url=$(normalize_url "$raw_url")

    log_info "Checking host: ${url}"

    local http_code
    http_code=$(curl \
        --silent \
        --head \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs "$MAX_REDIRECTS" \
        --write-out "%{http_code}" \
        --output /dev/null \
        --user-agent "${TOOL_NAME}/${VERSION} (Security Audit)" \
        "$url" 2>/dev/null) || http_code="000"

    case "$http_code" in
        200)
            log_ok "LIVE [200 OK]        → ${url}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "${url} [200 OK]"
            echo "live" ;;
        301|302|303|307|308)
            log_ok "LIVE [${http_code} Redirect]  → ${url}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "${url} [${http_code} Redirect]"
            echo "live" ;;
        403)
            log_warn "LIVE [403 Forbidden] → ${url}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "${url} [403 Forbidden]"
            echo "live" ;;
        000|"")
            log_error "DEAD [No Response]   → ${url}"
            write_result "${RESULTS_DIR}/dead_hosts.txt" "${url} [No Response]"
            echo "dead" ;;
        *)
            log_warn "LIVE [${http_code}]           → ${url}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "${url} [${http_code}]"
            echo "live" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 4 HELPERS: Sensitivity Classification
# ─────────────────────────────────────────────────────────────────────────────
is_high_risk_path() {
    local path
    path=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    for keyword in "${SENSITIVE_DIRS[@]}"; do
        [[ "$path" == *"${keyword}"* ]] && return 0
    done
    return 1
}

is_sensitive_file() {
    local path
    path=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    for ext in "${SENSITIVE_EXTS[@]}"; do
        [[ "$path" == *"${ext}" ]] && return 0
    done
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 5: RESPONSE BODY ANALYSIS (data exposure detection)
# ─────────────────────────────────────────────────────────────────────────────
analyze_response_body() {
    local url="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"

    local body
    body=$(curl \
        --silent \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs "$MAX_REDIRECTS" \
        --user-agent "${TOOL_NAME}/${VERSION} (Security Audit)" \
        --output - \
        "$url" 2>/dev/null | head -n 20) || body=""

    [[ -z "$body" ]] && return

    local found_keywords=()
    for keyword in "${DATA_KEYWORDS[@]}"; do
        echo "$body" | grep -qi "$keyword" 2>/dev/null && found_keywords+=("$keyword")
    done

    if [[ ${#found_keywords[@]} -gt 0 ]]; then
        local kw_str
        kw_str=$(IFS=', '; echo "${found_keywords[*]}")
        local entry="[$(timestamp)] URL: ${url} | Keywords: ${kw_str}"
        write_result "${base}/potential_data_exposure.txt" "$entry"
        echo -e "  ${RED}${BOLD}[DATA EXPOSURE]${RESET} ${url} → ${kw_str}"
        ((TOTAL_EXPOSURE++)) || true
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 2 & 3: Probe a single path (enumeration + categorization)
# ─────────────────────────────────────────────────────────────────────────────
probe_path() {
    local base_url="$1"
    local path="$2"
    local domain_safe="$3"
    local result_base="${RESULTS_DIR}/${domain_safe}"
    local full_url="${base_url}/${path}"

    log_verbose "Probing: ${full_url}"

    local start_ns end_ns elapsed_ms http_code content_length
    start_ns=$(date +%s%N 2>/dev/null || echo "0")

    local curl_out
    curl_out=$(curl \
        --silent \
        --head \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs 0 \
        --write-out "\n%{http_code}\n%{size_download}" \
        --output /dev/null \
        --user-agent "${TOOL_NAME}/${VERSION} (Security Audit)" \
        "$full_url" 2>/dev/null) || curl_out="000"

    end_ns=$(date +%s%N 2>/dev/null || echo "0")

    http_code=$(echo "$curl_out" | tail -n 2 | head -n 1 | tr -d '[:space:]')
    content_length=$(echo "$curl_out" | tail -n 1 | tr -d '[:space:]')

    if [[ "$start_ns" != "0" && "$end_ns" != "0" ]]; then
        elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    else
        elapsed_ms="N/A"
    fi

    [[ -z "$http_code" || "$http_code" == "000" ]] && return

    ((TOTAL_REQUESTS++)) || true

    local log_entry="[$(timestamp)] ${http_code} | Size:${content_length}B | Time:${elapsed_ms}ms | ${full_url}"
    write_result "${result_base}/logs.txt" "$log_entry"

    local record="${full_url} [${http_code}] Size:${content_length}B Time:${elapsed_ms}ms"

    # ── Categorize by status code ────────────────────────────────────────────
    case "$http_code" in
        200)
            write_result "${result_base}/categorized/200_ok.txt" "$record"
            ((TOTAL_200++)) || true
            echo -e "  ${GREEN}[200]${RESET} ${full_url}  (${content_length}B, ${elapsed_ms}ms)"

            if is_high_risk_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$record"
                log_high "${full_url}"
                ((TOTAL_HIGH_RISK++)) || true
            fi
            if is_sensitive_file "$path"; then
                write_result "${result_base}/sensitive_files.txt" "$record"
                log_sensitive "${full_url}"
                ((TOTAL_SENSITIVE++)) || true
            fi

            # Body analysis — extra delay before fetching body
            sleep "$DELAY"
            analyze_response_body "$full_url" "$domain_safe"
            ;;

        301|302|303|307|308)
            write_result "${result_base}/categorized/redirects.txt" "$record"
            ((TOTAL_REDIRECTS++)) || true
            echo -e "  ${YELLOW}[${http_code}]${RESET} ${full_url}"

            if is_high_risk_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$record"
                log_high "${full_url}"
                ((TOTAL_HIGH_RISK++)) || true
            fi
            if is_sensitive_file "$path"; then
                write_result "${result_base}/sensitive_files.txt" "$record"
                log_sensitive "${full_url}"
                ((TOTAL_SENSITIVE++)) || true
            fi
            ;;

        403)
            write_result "${result_base}/categorized/403.txt" "$record"
            ((TOTAL_403++)) || true
            echo -e "  ${MAGENTA}[403]${RESET} ${full_url}"

            if is_high_risk_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$record"
                log_high "${full_url}"
                ((TOTAL_HIGH_RISK++)) || true
            fi
            ;;

        404|410)
            log_verbose "  [${http_code}] ${full_url} — not found"
            ;;

        *)
            write_result "${result_base}/categorized/other.txt" "$record"
            echo -e "  ${BLUE}[${http_code}]${RESET} ${full_url}"
            ;;
    esac

    # Rate limiting — mandatory delay between every request
    sleep "$DELAY"
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 2: DIRECTORY ENUMERATION (controlled, rate-limited)
# ─────────────────────────────────────────────────────────────────────────────
enumerate_target() {
    local base_url="$1"
    local domain_safe="$2"
    local wordlist="$3"

    local total_words
    total_words=$(wc -l < "$wordlist" | tr -d '[:space:]')

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    log_info "Enumerating: ${base_url}"
    log_info "Wordlist   : ${wordlist} (${total_words} words)"
    log_info "Extensions : ${EXTENSIONS[*]:-none}"
    log_info "Delay      : ${DELAY}s | Threads: ${THREADS}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""

    # Build full path list
    local -a paths_to_probe=()
    while IFS= read -r word || [[ -n "$word" ]]; do
        [[ -z "$word" || "$word" == \#* ]] && continue
        word=$(echo "$word" | tr -d '[:space:]')
        [[ -z "$word" ]] && continue

        paths_to_probe+=("$word")
        for ext in "${EXTENSIONS[@]}"; do
            ext="${ext#.}"
            paths_to_probe+=("${word}.${ext}")
        done
    done < "$wordlist"

    local total_paths=${#paths_to_probe[@]}
    log_info "Total paths to probe: ${total_paths}"
    echo ""

    local current=0
    local active_jobs=0

    for path in "${paths_to_probe[@]}"; do
        ((current++)) || true

        if (( current % 50 == 0 )); then
            local pct=$(( current * 100 / total_paths ))
            echo -e "${CYAN}  [Progress] ${current}/${total_paths} (${pct}%)${RESET}"
        fi

        if [[ "$THREADS" -gt 1 ]]; then
            probe_path "$base_url" "$path" "$domain_safe" &
            ((active_jobs++)) || true
            if [[ "$active_jobs" -ge "$THREADS" ]]; then
                wait
                active_jobs=0
            fi
        else
            probe_path "$base_url" "$path" "$domain_safe"
        fi
    done

    wait
    echo ""
    log_ok "Enumeration complete: ${base_url}"
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 7: REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
generate_report() {
    local domain="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"
    local report_file="${base}/report.md"
    local scan_end_time
    scan_end_time=$(timestamp)

    local c200 c403 credir cother chigh csens cexpose
    c200=$(wc -l < "${base}/categorized/200_ok.txt"   2>/dev/null | tr -d '[:space:]') || c200=0
    c403=$(wc -l < "${base}/categorized/403.txt"      2>/dev/null | tr -d '[:space:]') || c403=0
    credir=$(wc -l < "${base}/categorized/redirects.txt" 2>/dev/null | tr -d '[:space:]') || credir=0
    cother=$(wc -l < "${base}/categorized/other.txt"  2>/dev/null | tr -d '[:space:]') || cother=0
    chigh=$(wc -l < "${base}/high_risk_paths.txt"     2>/dev/null | tr -d '[:space:]') || chigh=0
    csens=$(wc -l < "${base}/sensitive_files.txt"     2>/dev/null | tr -d '[:space:]') || csens=0
    cexpose=$(wc -l < "${base}/potential_data_exposure.txt" 2>/dev/null | tr -d '[:space:]') || cexpose=0

    local total_domain=$(( c200 + c403 + credir + cother ))

    {
        cat << HEADER
# SecureDirInspector — Security Scan Report

---

## Scan Overview

| Field              | Value                        |
|--------------------|------------------------------|
| **Target**         | \`${domain}\`                |
| **Scan Started**   | ${SCAN_START_TIME}           |
| **Scan Completed** | ${scan_end_time}             |
| **Tool Version**   | ${VERSION}                   |
| **Wordlist**       | ${WORDLIST}                  |
| **Extensions**     | ${EXTENSIONS[*]:-none}       |
| **Delay**          | ${DELAY}s                    |
| **Threads**        | ${THREADS}                   |

---

## Request Summary

| Status          | Count              |
|-----------------|--------------------|
| Total Requests  | ${total_domain}    |
| 200 OK          | ${c200}            |
| 403 Forbidden   | ${c403}            |
| Redirects       | ${credir}          |
| Other           | ${cother}          |

---

## Security Findings

| Category                  | Count       |
|---------------------------|-------------|
| High Risk Paths           | ${chigh}    |
| Sensitive Files           | ${csens}    |
| Data Exposure Indicators  | ${cexpose}  |

---

## High Risk Paths

HEADER

        if [[ -s "${base}/high_risk_paths.txt" ]]; then
            echo '```'
            cat "${base}/high_risk_paths.txt"
            echo '```'
        else
            echo "_No high risk paths detected._"
        fi

        cat << SEC2

---

## Sensitive Files

SEC2

        if [[ -s "${base}/sensitive_files.txt" ]]; then
            echo '```'
            cat "${base}/sensitive_files.txt"
            echo '```'
        else
            echo "_No sensitive files detected._"
        fi

        cat << SEC3

---

## Potential Data Exposure

SEC3

        if [[ -s "${base}/potential_data_exposure.txt" ]]; then
            echo '```'
            cat "${base}/potential_data_exposure.txt"
            echo '```'
        else
            echo "_No data exposure indicators detected._"
        fi

        cat << SEC4

---

## 200 OK Paths

SEC4

        if [[ -s "${base}/categorized/200_ok.txt" ]]; then
            echo '```'
            cat "${base}/categorized/200_ok.txt"
            echo '```'
        else
            echo "_No accessible paths found._"
        fi

        cat << SEC5

---

## 403 Forbidden Paths

SEC5

        if [[ -s "${base}/categorized/403.txt" ]]; then
            echo '```'
            cat "${base}/categorized/403.txt"
            echo '```'
        else
            echo "_No forbidden paths found._"
        fi

        cat << SEC6

---

## Redirect Paths

SEC6

        if [[ -s "${base}/categorized/redirects.txt" ]]; then
            echo '```'
            cat "${base}/categorized/redirects.txt"
            echo '```'
        else
            echo "_No redirects found._"
        fi

        cat << RECS

---

## Security Recommendations

1. **Exposed Admin Panels** — If \`/admin\`, \`/dashboard\` return 200/403,
   protect them with strong authentication and IP whitelisting.

2. **Backup & Config Files** — Files like \`.env\`, \`.bak\`, \`.sql\`, \`config\`
   must NEVER be publicly accessible. Move them outside the web root.

3. **Git Repository Exposure** — If \`/.git\` is accessible, your source code
   may be fully downloadable. Block access immediately via server config.

4. **Sensitive Data in Responses** — If \`password\`, \`API_KEY\`, or \`token\`
   keywords were found, audit those endpoints immediately for data leakage.

5. **Upload Directories** — Publicly accessible \`/uploads\` may expose
   user files or allow directory listing. Restrict access.

6. **Debug/Test Endpoints** — Remove or restrict \`/debug\`, \`/test\` in production.

7. **HTTPS Enforcement** — Ensure all HTTP traffic redirects to HTTPS.

8. **403 Path Hardening** — Consider returning 404 for restricted paths
   to reduce information disclosure (path existence confirmation).

---

## Legal Notice

> This scan was performed with explicit authorization.
> Results are confidential and intended for the system owner only.
> Unauthorized disclosure of this report may be illegal.

---

*Generated by ${TOOL_NAME} v${VERSION} — $(timestamp)*
RECS

    } > "$report_file"

    log_ok "Report saved: ${report_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY PRINT
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SCAN COMPLETE — SUMMARY${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo -e "  ${CYAN}Total Requests  :${RESET} ${TOTAL_REQUESTS}"
    echo -e "  ${GREEN}200 OK          :${RESET} ${TOTAL_200}"
    echo -e "  ${MAGENTA}403 Forbidden   :${RESET} ${TOTAL_403}"
    echo -e "  ${YELLOW}Redirects       :${RESET} ${TOTAL_REDIRECTS}"
    echo -e "  ${RED}High Risk Paths :${RESET} ${TOTAL_HIGH_RISK}"
    echo -e "  ${MAGENTA}Sensitive Files :${RESET} ${TOTAL_SENSITIVE}"
    echo -e "  ${RED}Data Exposure   :${RESET} ${TOTAL_EXPOSURE}"
    echo ""
    echo -e "  ${CYAN}Results saved to: ${BOLD}./${RESULTS_DIR}/${RESET}"
    echo ""
    echo -e "${YELLOW}  Use only on systems you own or have permission to test.${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS A SINGLE TARGET
# ─────────────────────────────────────────────────────────────────────────────
process_target() {
    local raw_target="$1"
    local url
    url=$(normalize_url "$raw_target")
    local domain_safe
    domain_safe=$(sanitize_domain "$url")

    echo ""
    echo -e "${BOLD}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}│  Target: ${url}${RESET}"
    echo -e "${BOLD}└─────────────────────────────────────────────────────────────┘${RESET}"

    local status
    status=$(check_live_host "$url")

    if [[ "$status" != "live" ]]; then
        log_warn "Skipping dead host: ${url}"
        return
    fi

    setup_results_dir "$domain_safe"
    write_result "${RESULTS_DIR}/${domain_safe}/logs.txt" "[$(timestamp)] Scan started: ${url}"

    enumerate_target "$url" "$domain_safe" "$WORDLIST"
    generate_report "$url" "$domain_safe"

    write_result "${RESULTS_DIR}/${domain_safe}/logs.txt" "[$(timestamp)] Scan completed: ${url}"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
    print_banner
    parse_args "$@"
    require_authorization
    check_dependencies

    SCAN_START_TIME=$(timestamp)

    ensure_dir "${RESULTS_DIR}"
    : > "${RESULTS_DIR}/live_hosts.txt"
    : > "${RESULTS_DIR}/dead_hosts.txt"

    echo -e "${BOLD}  Scan started : ${SCAN_START_TIME}${RESET}"
    echo -e "  Delay: ${DELAY}s | Max Threads: ${THREADS} | Wordlist: ${WORDLIST}"
    echo ""

    if [[ -n "$SINGLE_URL" ]]; then
        process_target "$SINGLE_URL"
    elif [[ -n "$DOMAIN_LIST" ]]; then
        local count=0
        while IFS= read -r target || [[ -n "$target" ]]; do
            [[ -z "$target" || "$target" == \#* ]] && continue
            target=$(echo "$target" | tr -d '[:space:]')
            [[ -z "$target" ]] && continue
            ((count++)) || true
            process_target "$target"
        done < "$DOMAIN_LIST"
        log_info "Processed ${count} target(s)."
    fi

    print_summary
}

main "$@"
