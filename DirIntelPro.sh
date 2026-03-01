#!/usr/bin/env bash
# =============================================================================
#  DirIntel Pro — Advanced Directory Intelligence & Risk Analysis Framework
#  Version : 2.0.0
#  Author  : Security Research Tool
#  Purpose : Authorized directory intelligence, fingerprinting & risk analysis
# =============================================================================
#
#  LEGAL DISCLAIMER:
#  This tool is intended ONLY for use on systems you own or have explicit
#  written permission to test. Unauthorized use is ILLEGAL and UNETHICAL.
#  The author assumes NO liability for misuse of this tool.
#
#  "Authorized security testing only. Know before you scan."
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
readonly VERSION="2.0.0"
readonly TOOL_NAME="DirIntelPro"
readonly RESULTS_DIR="results"
readonly MAX_THREADS=10
readonly DEFAULT_DELAY=1
readonly REQUEST_TIMEOUT=10
readonly MAX_REDIRECTS=3

# Sensitive path keywords
readonly -a SENSITIVE_PATH_KEYWORDS=(
    "admin" "backup" "config" ".git" ".env" "debug"
    "database" "private" "internal" "secret" "uploads"
    "test" "dev" "staging" "api" "console" "panel"
)

# Sensitive extensions
readonly -a SENSITIVE_EXTS=(
    ".env" ".zip" ".sql" ".bak" ".tar" ".gz" ".log"
    ".key" ".pem" ".p12" ".pfx" ".crt" ".cer" ".der"
    ".conf" ".cfg" ".ini" ".xml" ".json" ".yaml" ".yml"
    ".sh" ".py" ".rb" ".php" ".asp" ".aspx"
)

# High-risk body keywords
readonly -a HIGH_RISK_KEYWORDS=(
    "password" "token" "secret" "api_key" "db_host"
    "private_key" "authorization" "bearer" "passwd"
    "credentials" "access_key" "auth_token" "session"
)

# Colors
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly DIM='\033[2m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# Risk level colors
readonly COLOR_LOW="${GREEN}"
readonly COLOR_MEDIUM="${YELLOW}"
readonly COLOR_HIGH="${RED}"
readonly COLOR_CRITICAL="${MAGENTA}${BOLD}"

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────
AUTHORIZED=false
DOMAIN_LIST=""
SINGLE_URL=""
WORDLIST=""
SUBDOMAIN_WORDLIST=""
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
TOTAL_CRITICAL=0
TOTAL_HIGH_SEV=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_SUBDOMAINS_FOUND=0

# Wildcard detection state (per domain, reset each target)
WILDCARD_BASELINE_HASH=""
WILDCARD_BASELINE_SIZE=""
WILDCARD_COUNT=0

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
log_info()      { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()        { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn()      { echo -e "${YELLOW}[!]${RESET} $*"; }
log_error()     { echo -e "${RED}[-]${RESET} $*" >&2; }
log_verbose()   { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[v]${RESET} $*" || true; }
log_critical()  { echo -e "${MAGENTA}${BOLD}[CRITICAL]${RESET} $*"; }
log_high_sev()  { echo -e "${RED}${BOLD}[HIGH]${RESET} $*"; }
log_medium()    { echo -e "${YELLOW}[MEDIUM]${RESET} $*"; }
log_low()       { echo -e "${GREEN}[LOW]${RESET} $*"; }

timestamp()     { date '+%Y-%m-%d %H:%M:%S'; }
tlog()          { echo "[$(timestamp)] $*"; }

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

ensure_dir()   { mkdir -p "$1"; }
write_result() { echo "$2" >> "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK & AUTO-INSTALL
# ─────────────────────────────────────────────────────────────────────────────

# Pure-bash SHA256 fallback (used if sha256sum binary is unavailable)
# Uses /dev/urandom-seeded approach — produces a stable hash via openssl if present,
# otherwise falls back to a length+content fingerprint for deduplication purposes.
builtin_sha256() {
    local input="$1"
    if command -v openssl &>/dev/null; then
        echo -n "$input" | openssl dgst -sha256 2>/dev/null | awk '{print $2}'
    elif command -v python3 &>/dev/null; then
        echo -n "$input" | python3 -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
    elif command -v python &>/dev/null; then
        echo -n "$input" | python -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())"
    else
        # Last resort: length + first 64 chars as pseudo-fingerprint
        local len="${#input}"
        local prefix="${input:0:64}"
        echo "nohash_len${len}_${prefix}" | tr -d '[:space:]'
    fi
}

# Wrapper: use sha256sum if available, else builtin fallback
compute_sha256() {
    local input="$1"
    if command -v sha256sum &>/dev/null; then
        echo -n "$input" | sha256sum | awk '{print $1}'
    else
        builtin_sha256 "$input"
    fi
}

check_dependencies() {
    echo ""
    log_info "Checking dependencies..."

    # Map: command → apt package name
    declare -A DEP_PKG=(
        [curl]="curl"
        [awk]="gawk"
        [sed]="sed"
        [grep]="grep"
        [wc]="coreutils"
        [date]="coreutils"
        [tr]="coreutils"
        [sha256sum]="coreutils"
    )

    local missing=()
    for dep in curl awk sed grep wc date tr sha256sum; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing tools: ${missing[*]}"

        # Auto-install on Debian/Ubuntu/Kali systems
        if command -v apt-get &>/dev/null; then
            log_info "Detected apt-get — attempting auto-install..."
            local pkgs=()
            for dep in "${missing[@]}"; do
                pkgs+=("${DEP_PKG[$dep]:-$dep}")
            done
            # Deduplicate package list
            local unique_pkgs
            unique_pkgs=$(printf '%s\n' "${pkgs[@]}" | sort -u | tr '\n' ' ')
            log_info "Running: sudo apt-get install -y ${unique_pkgs}"
            if sudo apt-get install -y $unique_pkgs 2>/dev/null; then
                log_ok "Dependencies installed successfully."
            else
                log_warn "Auto-install failed. Trying without sudo..."
                apt-get install -y $unique_pkgs 2>/dev/null || true
            fi
        elif command -v yum &>/dev/null; then
            log_info "Detected yum — attempting auto-install..."
            sudo yum install -y "${missing[@]}" 2>/dev/null || true
        elif command -v pacman &>/dev/null; then
            log_info "Detected pacman — attempting auto-install..."
            sudo pacman -S --noconfirm "${missing[@]}" 2>/dev/null || true
        else
            log_error "Cannot auto-install. Please manually install: ${missing[*]}"
            exit 1
        fi

        # Re-check after install attempt
        local still_missing=()
        for dep in "${missing[@]}"; do
            command -v "$dep" &>/dev/null || still_missing+=("$dep")
        done

        if [[ ${#still_missing[@]} -gt 0 ]]; then
            # sha256sum missing but we have fallback — warn but continue
            local critical_missing=()
            for dep in "${still_missing[@]}"; do
                [[ "$dep" == "sha256sum" ]] && continue
                critical_missing+=("$dep")
            done
            if [[ ${#critical_missing[@]} -gt 0 ]]; then
                log_error "Critical tools still missing: ${critical_missing[*]}"
                exit 1
            else
                log_warn "sha256sum not found — using built-in hash fallback (openssl/python3)"
            fi
        fi
    fi

    # curl is absolutely required — hard fail
    if ! command -v curl &>/dev/null; then
        log_error "curl is required and could not be installed. Exiting."
        exit 1
    fi

    log_ok "All dependencies ready."
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────────────────
draw_progress_bar() {
    local current="$1"
    local total="$2"
    local width=40

    [[ "$total" -eq 0 ]] && return

    local pct=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))

    local bar=""
    local i
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty;  i++ )); do bar+="░"; done

    printf "\r  ${CYAN}[${bar}]${RESET} ${WHITE}%3d%%${RESET} ${DIM}(%d/%d)${RESET}" \
        "$pct" "$current" "$total"
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║                                                                  ║"
    echo "  ║        ██████╗ ██╗██████╗     ██╗███╗   ██╗████████╗███████╗   ║"
    echo "  ║        ██╔══██╗██║██╔══██╗    ██║████╗  ██║╚══██╔══╝██╔════╝   ║"
    echo "  ║        ██║  ██║██║██████╔╝    ██║██╔██╗ ██║   ██║   █████╗     ║"
    echo "  ║        ██║  ██║██║██╔══██╗    ██║██║╚██╗██║   ██║   ██╔══╝     ║"
    echo "  ║        ██████╔╝██║██║  ██║    ██║██║ ╚████║   ██║   ███████╗   ║"
    echo "  ║        ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝   ║"
    echo "  ║                                                                  ║"
    echo "  ║          ██████╗ ██████╗  ██████╗                               ║"
    echo "  ║          ██╔══██╗██╔══██╗██╔═══██╗                              ║"
    echo "  ║          ██████╔╝██████╔╝██║   ██║                              ║"
    echo "  ║          ██╔═══╝ ██╔══██╗██║   ██║                              ║"
    echo "  ║          ██║     ██║  ██║╚██████╔╝                              ║"
    echo "  ║          ╚═╝     ╚═╝  ╚═╝ ╚═════╝                               ║"
    echo "  ║                                                                  ║"
    echo "  ║   Advanced Directory Intelligence & Risk Analysis Framework     ║"
    echo "  ║                        Version ${VERSION}                           ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║               ⚠  LEGAL WARNING — READ CAREFULLY  ⚠             ║"
    echo "  ╠══════════════════════════════════════════════════════════════════╣"
    echo "  ║                                                                  ║"
    echo "  ║  This tool is for AUTHORIZED SECURITY TESTING ONLY.             ║"
    echo "  ║                                                                  ║"
    echo "  ║  • Use ONLY on systems you OWN or have EXPLICIT WRITTEN          ║"
    echo "  ║    PERMISSION to test.                                           ║"
    echo "  ║  • Unauthorized use is ILLEGAL under computer fraud laws         ║"
    echo "  ║    including CFAA (US), Computer Misuse Act (UK), and            ║"
    echo "  ║    equivalent legislation worldwide.                             ║"
    echo "  ║  • The author assumes NO liability for misuse of this tool.      ║"
    echo "  ║  • All scan results are confidential — handle responsibly.       ║"
    echo "  ║                                                                  ║"
    echo "  ║  Pass --authorized to confirm you have permission to proceed.    ║"
    echo "  ║                                                                  ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTHORIZATION GATE
# ─────────────────────────────────────────────────────────────────────────────
require_authorization() {
    if [[ "$AUTHORIZED" != true ]]; then
        echo -e "${RED}${BOLD}[BLOCKED]${RESET} Explicit authorization is required to run this tool."
        echo ""
        echo -e "  Pass ${BOLD}--authorized${RESET} to confirm you have written permission to test the target."
        echo ""
        echo -e "  ${CYAN}Example:${RESET}"
        echo    "    ./DirIntelPro.sh --authorized --url https://example.com --wordlist wordlist.txt"
        echo ""
        echo -e "${YELLOW}  Use only on systems you own or have explicit written permission to test.${RESET}"
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
    echo "  --subdomain-scan <file>   Subdomain wordlist to enumerate subdomains"
    echo "  --delay <seconds>         Delay between requests (default: ${DEFAULT_DELAY}s, min: 0.5)"
    echo "  --threads <n>             Parallel threads (default: 5, max: ${MAX_THREADS})"
    echo "  --verbose                 Enable verbose output"
    echo "  --help                    Show this help"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 --authorized --url https://example.com --wordlist common.txt"
    echo "  $0 --authorized --url https://example.com --wordlist dirs.txt --subdomain-scan subdomains.txt"
    echo "  $0 --authorized --domain-list targets.txt --wordlist dirs.txt --extensions php,html"
    echo "  $0 --authorized --url https://example.com --wordlist dirs.txt --delay 2 --threads 3"
    echo ""
    echo -e "${BOLD}Output Structure:${RESET}"
    echo "  results/"
    echo "  ├── live_hosts.txt"
    echo "  ├── dead_hosts.txt"
    echo "  ├── subdomains/                    ← subdomain scan results"
    echo "  │   └── <domain>/"
    echo "  │       ├── live_subdomains.txt"
    echo "  │       ├── dead_subdomains.txt"
    echo "  │       ├── redirecting_subdomains.txt"
    echo "  │       ├── forbidden_subdomains.txt"
    echo "  │       ├── all_subdomains.txt"
    echo "  │       └── subdomain_report.md"
    echo "  └── <domain>/"
    echo "      ├── categorized/   (200.txt, 403.txt, redirects.txt)"
    echo "      ├── severity/critical/findings.txt   ← CRITICAL bugs"
    echo "      ├── severity/high/findings.txt       ← HIGH bugs"
    echo "      ├── severity/medium/findings.txt     ← MEDIUM bugs"
    echo "      ├── severity/low/findings.txt        ← LOW bugs"
    echo "      ├── fingerprint_analysis.txt"
    echo "      ├── sensitive_files.txt"
    echo "      ├── high_risk_paths.txt"
    echo "      ├── directory_listing_exposed.txt"
    echo "      ├── git_exposure.txt"
    echo "      ├── report.md"
    echo "      └── logs.txt"
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
                    log_warn "Minimum delay is 0.5s. Setting to 0.5s."
                    DELAY=0.5
                fi
                shift 2 ;;
            --threads)
                THREADS="${2:-5}"
                if [[ "$THREADS" -gt "$MAX_THREADS" ]]; then
                    log_warn "Capping threads at ${MAX_THREADS}."
                    THREADS=$MAX_THREADS
                fi
                [[ "$THREADS" -lt 1 ]] && THREADS=1
                shift 2 ;;
            --subdomain-scan)
                SUBDOMAIN_WORDLIST="${2:-}"
                [[ -z "$SUBDOMAIN_WORDLIST" ]] && { log_error "--subdomain-scan requires a file path"; exit 1; }
                [[ ! -f "$SUBDOMAIN_WORDLIST" ]] && { log_error "Subdomain wordlist not found: $SUBDOMAIN_WORDLIST"; exit 1; }
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
    [[ -z "$SINGLE_URL" && -z "$DOMAIN_LIST" ]] && {
        log_error "Target required. Use --url or --domain-list"
        exit 1
    }
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

    # Severity: each level gets its own dedicated folder
    ensure_dir "${base}/severity/critical"
    ensure_dir "${base}/severity/high"
    ensure_dir "${base}/severity/medium"
    ensure_dir "${base}/severity/low"

    # Initialize all output files
    for f in \
        "${base}/categorized/200.txt" \
        "${base}/categorized/403.txt" \
        "${base}/categorized/redirects.txt" \
        "${base}/categorized/other.txt" \
        "${base}/high_risk_paths.txt" \
        "${base}/sensitive_files.txt" \
        "${base}/fingerprint_analysis.txt" \
        "${base}/directory_listing_exposed.txt" \
        "${base}/git_exposure.txt" \
        "${base}/severity/critical/findings.txt" \
        "${base}/severity/high/findings.txt" \
        "${base}/severity/medium/findings.txt" \
        "${base}/severity/low/findings.txt" \
        "${base}/logs.txt" \
        "${base}/robots.txt" \
        "${base}/sitemap.xml"
    do
        : > "$f"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 1: SMART LIVE HOST DETECTION
# ─────────────────────────────────────────────────────────────────────────────
check_live_host() {
    local raw_url="$1"
    local url
    url=$(normalize_url "$raw_url")

    log_info "Checking host: ${url}"

    local curl_out http_code response_time server_header
    curl_out=$(curl \
        --silent \
        --head \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs "$MAX_REDIRECTS" \
        --write-out "\n%{http_code}\n%{time_total}\n%{size_download}" \
        --dump-header /tmp/dirintel_headers_$$.txt \
        --output /dev/null \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$url" 2>/dev/null) || curl_out="000"

    http_code=$(echo "$curl_out" | tail -n 3 | head -n 1 | tr -d '[:space:]')
    response_time=$(echo "$curl_out" | tail -n 2 | head -n 1 | tr -d '[:space:]')

    # Extract server header
    server_header="Unknown"
    if [[ -f /tmp/dirintel_headers_$$.txt ]]; then
        server_header=$(grep -i "^Server:" /tmp/dirintel_headers_$$.txt 2>/dev/null \
            | head -n1 | sed 's/^[Ss]erver: *//I' | tr -d '\r\n') || server_header="Unknown"
        [[ -z "$server_header" ]] && server_header="Unknown"
        rm -f /tmp/dirintel_headers_$$.txt
    fi

    local classification entry
    case "$http_code" in
        200)
            classification="LIVE"
            entry="${url} | Status: 200 OK | Server: ${server_header} | Time: ${response_time}s"
            log_ok "${GREEN}LIVE${RESET}        [200 OK]    → ${url}  ${DIM}(Server: ${server_header}, ${response_time}s)${RESET}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "$entry"
            echo "live" ;;
        301|302|303|307|308)
            classification="REDIRECTING"
            entry="${url} | Status: ${http_code} Redirect | Server: ${server_header} | Time: ${response_time}s"
            log_ok "${YELLOW}REDIRECTING${RESET} [${http_code}]       → ${url}  ${DIM}(Server: ${server_header})${RESET}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "$entry"
            echo "live" ;;
        403)
            classification="FORBIDDEN"
            entry="${url} | Status: 403 Forbidden | Server: ${server_header} | Time: ${response_time}s"
            log_warn "${MAGENTA}FORBIDDEN${RESET}   [403]       → ${url}  ${DIM}(Server: ${server_header})${RESET}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "$entry"
            echo "live" ;;
        000|"")
            classification="DEAD"
            entry="${url} | Status: No Response | Time: N/A"
            log_error "${RED}DEAD${RESET}        [No Response] → ${url}"
            write_result "${RESULTS_DIR}/dead_hosts.txt" "$entry"
            echo "dead" ;;
        *)
            classification="LIVE"
            entry="${url} | Status: ${http_code} | Server: ${server_header} | Time: ${response_time}s"
            log_warn "LIVE        [${http_code}]       → ${url}  ${DIM}(Server: ${server_header})${RESET}"
            write_result "${RESULTS_DIR}/live_hosts.txt" "$entry"
            echo "live" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 3: RESPONSE FINGERPRINTING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

# Fetch full response body for analysis
fetch_body() {
    local url="$1"
    curl \
        --silent \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs 0 \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        --output - \
        "$url" 2>/dev/null || true
}

fingerprint_response() {
    local url="$1"
    local domain_safe="$2"
    local body="$3"          # body passed in — no double-fetch
    local header_file="$4"   # optional: path to dumped headers file
    local base="${RESULTS_DIR}/${domain_safe}"

    [[ -z "$body" ]] && return 1

    local content_length word_count line_count body_hash page_title

    content_length=$(printf '%s' "$body" | wc -c | tr -d '[:space:]')
    word_count=$(printf '%s' "$body" | wc -w | tr -d '[:space:]')
    line_count=$(printf '%s' "$body" | wc -l | tr -d '[:space:]')
    body_hash=$(compute_sha256 "$body")

    # Extract page title
    page_title=$(printf '%s' "$body" | grep -oi '<title>[^<]*</title>' 2>/dev/null \
        | sed 's/<[^>]*>//g' | head -n1 | tr -d '\r\n') || page_title=""
    [[ -z "$page_title" ]] && page_title="(no title)"

    # Extract security-relevant response headers if header file provided
    local server_hdr xpowered csp xframe hsts
    server_hdr=""; xpowered=""; csp=""; xframe=""; hsts=""
    if [[ -n "$header_file" && -f "$header_file" ]]; then
        server_hdr=$(grep -i "^Server:"                    "$header_file" 2>/dev/null | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
        xpowered=$(grep -i "^X-Powered-By:"               "$header_file" 2>/dev/null | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
        csp=$(grep -i "^Content-Security-Policy:"         "$header_file" 2>/dev/null | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
        xframe=$(grep -i "^X-Frame-Options:"              "$header_file" 2>/dev/null | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
        hsts=$(grep -i "^Strict-Transport-Security:"      "$header_file" 2>/dev/null | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
    fi

    local fp_entry
    fp_entry="URL: ${url} | Size: ${content_length}B | Words: ${word_count} | Lines: ${line_count} | SHA256: ${body_hash} | Title: ${page_title}"
    [[ -n "$server_hdr" ]]  && fp_entry+=" | Server: ${server_hdr}"
    [[ -n "$xpowered" ]]    && fp_entry+=" | X-Powered-By: ${xpowered}"
    [[ -z "$csp" ]]         && fp_entry+=" | CSP: MISSING"
    [[ -z "$xframe" ]]      && fp_entry+=" | X-Frame-Options: MISSING"
    [[ -z "$hsts" ]]        && fp_entry+=" | HSTS: MISSING"

    write_result "${base}/fingerprint_analysis.txt" "$fp_entry"
    log_verbose "Fingerprint → ${url} | ${content_length}B | SHA256: ${body_hash:0:16}..."

    # Wildcard detection
    if [[ -z "$WILDCARD_BASELINE_HASH" ]]; then
        WILDCARD_BASELINE_HASH="$body_hash"
        WILDCARD_BASELINE_SIZE="$content_length"
    else
        if [[ "$body_hash" == "$WILDCARD_BASELINE_HASH" && \
              "$content_length" == "$WILDCARD_BASELINE_SIZE" ]]; then
            ((WILDCARD_COUNT++)) || true
            if (( WILDCARD_COUNT >= 3 )); then
                local wc_entry="[WILDCARD WARNING] Multiple paths return identical response (hash: ${body_hash:0:16}...) — possible wildcard/custom 404 behavior"
                grep -qF "$wc_entry" "${base}/fingerprint_analysis.txt" 2>/dev/null || \
                    write_result "${base}/fingerprint_analysis.txt" "$wc_entry"
                log_warn "Possible wildcard behavior detected on ${domain_safe}"
            fi
        fi
    fi

    echo "$body_hash $content_length $word_count $line_count $page_title"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 4: SENSITIVE PATTERN DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
is_sensitive_path() {
    local path
    path=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    for keyword in "${SENSITIVE_PATH_KEYWORDS[@]}"; do
        [[ "$path" == *"${keyword}"* ]] && return 0
    done
    return 1
}

is_sensitive_extension() {
    local path
    path=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    for ext in "${SENSITIVE_EXTS[@]}"; do
        [[ "$path" == *"${ext}" ]] && return 0
    done
    return 1
}

scan_body_for_keywords() {
    local url="$1"
    local body="$2"
    local domain_safe="$3"
    local base="${RESULTS_DIR}/${domain_safe}"

    [[ -z "$body" ]] && return 1

    local body_lower
    body_lower=$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')

    local found_keywords=()
    for keyword in "${HIGH_RISK_KEYWORDS[@]}"; do
        local kw_lower
        kw_lower=$(printf '%s' "$keyword" | tr '[:upper:]' '[:lower:]')
        [[ "$body_lower" == *"${kw_lower}"* ]] && found_keywords+=("$keyword")
    done

    if [[ ${#found_keywords[@]} -gt 0 ]]; then
        local kw_str
        kw_str=$(IFS=', '; echo "${found_keywords[*]}")
        local entry
        entry="$(tlog "URL: ${url} | Matched Keywords: ${kw_str}")"
        write_result "${base}/high_risk_paths.txt" "$entry"
        echo -e "  ${RED}${BOLD}[KEYWORD MATCH]${RESET} ${url} → ${kw_str}"
        ((TOTAL_EXPOSURE++)) || true
        return 0
    fi
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 5: RISK SCORING SYSTEM
# ─────────────────────────────────────────────────────────────────────────────
calculate_risk_score() {
    local path="$1"
    local http_code="$2"
    local body="$3"
    local score=0

    # Base score by status code
    case "$http_code" in
        200) (( score += 2 )) ;;
        403) (( score += 1 )) ;;
    esac

    # Sensitive keyword in path
    local path_lower
    path_lower=$(echo "$path" | tr '[:upper:]' '[:lower:]')
    for keyword in "${SENSITIVE_PATH_KEYWORDS[@]}"; do
        if [[ "$path_lower" == *"${keyword}"* ]]; then
            (( score += 5 ))
            break
        fi
    done

    # Admin path bonus
    if [[ "$path_lower" == *"admin"* || "$path_lower" == *"panel"* || \
          "$path_lower" == *"console"* || "$path_lower" == *"dashboard"* ]]; then
        (( score += 7 ))
    fi

    # Exposed config/sensitive file
    for ext in "${SENSITIVE_EXTS[@]}"; do
        if [[ "$path_lower" == *"${ext}" ]]; then
            (( score += 10 ))
            break
        fi
    done

    # Data exposure indicator (keyword in body) — pure bash, no subprocess
    if [[ -n "$body" ]]; then
        local body_lc
        body_lc=$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')
        for keyword in "${HIGH_RISK_KEYWORDS[@]}"; do
            local kw_lc
            kw_lc=$(printf '%s' "$keyword" | tr '[:upper:]' '[:lower:]')
            if [[ "$body_lc" == *"${kw_lc}"* ]]; then
                (( score += 15 ))
                break
            fi
        done
    fi

    echo "$score"
}

classify_severity() {
    local score="$1"
    if   (( score >= 21 )); then echo "critical"
    elif (( score >= 13 )); then echo "high"
    elif (( score >= 6  )); then echo "medium"
    else                         echo "low"
    fi
}

write_severity_entry() {
    local domain_safe="$1"
    local severity="$2"
    local entry="$3"
    local base="${RESULTS_DIR}/${domain_safe}"

    # Write to dedicated severity folder/findings.txt
    write_result "${base}/severity/${severity}/findings.txt" "$entry"

    # Terminal: print colored badge + entry
    case "$severity" in
        critical)
            echo -e "  ${MAGENTA}${BOLD}╔══ [CRITICAL] ══╗${RESET}"
            echo -e "  ${MAGENTA}${BOLD}║${RESET} ${entry}"
            echo -e "  ${MAGENTA}${BOLD}╚════════════════╝${RESET}"
            ((TOTAL_CRITICAL++)) || true ;;
        high)
            echo -e "  ${RED}${BOLD}┌─ [HIGH] ─────────${RESET}"
            echo -e "  ${RED}${BOLD}│${RESET} ${entry}"
            echo -e "  ${RED}${BOLD}└──────────────────${RESET}"
            ((TOTAL_HIGH_SEV++)) || true ;;
        medium)
            echo -e "  ${YELLOW}▶ [MEDIUM]${RESET} ${entry}"
            ((TOTAL_MEDIUM++)) || true ;;
        low)
            echo -e "  ${GREEN}· [LOW]${RESET}    ${entry}"
            ((TOTAL_LOW++)) || true ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 6: ADVANCED ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
detect_directory_listing() {
    local url="$1"
    local body="$2"
    local domain_safe="$3"
    local base="${RESULTS_DIR}/${domain_safe}"

    local body_lc
    body_lc=$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')
    if [[ "$body_lc" == *"index of /"* ]]; then
        local entry
        entry="$(tlog "[DIRECTORY LISTING EXPOSED] ${url}")"
        write_result "${base}/directory_listing_exposed.txt" "$entry"
        echo -e "  ${RED}${BOLD}[DIR LISTING]${RESET} Directory listing exposed at: ${url}"
        return 0
    fi
    return 1
}

detect_git_exposure() {
    local base_url="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"

    local git_url="${base_url}/.git/HEAD"
    log_verbose "Checking Git exposure: ${git_url}"

    local http_code body
    http_code=$(curl \
        --silent \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs 0 \
        --write-out "%{http_code}" \
        --output /tmp/dirintel_git_$$.txt \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$git_url" 2>/dev/null) || http_code="000"

    body=""
    [[ -f /tmp/dirintel_git_$$.txt ]] && body=$(cat /tmp/dirintel_git_$$.txt)
    rm -f /tmp/dirintel_git_$$.txt

    if [[ "$http_code" == "200" && "$body" == *"ref:"* ]]; then
        local entry
        entry="$(tlog "[GIT EXPOSURE] /.git/HEAD accessible at ${base_url} — Source code may be downloadable!")"
        write_result "${base}/git_exposure.txt" "$entry"
        echo -e "  ${RED}${BOLD}[GIT EXPOSED]${RESET} /.git/HEAD is accessible at ${base_url}"
        return 0
    fi
    return 1
}

fetch_robots_and_sitemap() {
    local base_url="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"

    log_info "Fetching robots.txt and sitemap.xml..."

    # robots.txt
    local robots_url="${base_url}/robots.txt"
    local robots_body robots_code
    robots_code=$(curl --silent --max-time "$REQUEST_TIMEOUT" --max-redirs 0 \
        --write-out "%{http_code}" --output /tmp/dirintel_robots_$$.txt \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$robots_url" 2>/dev/null) || robots_code="000"

    if [[ "$robots_code" == "200" && -f /tmp/dirintel_robots_$$.txt ]]; then
        robots_body=$(cat /tmp/dirintel_robots_$$.txt)
        echo "$robots_body" > "${base}/robots.txt"
        log_ok "robots.txt fetched → ${base}/robots.txt"

        # Extract Disallow paths from robots.txt and add to wordlist candidates
        local disallowed
        disallowed=$(grep -i "^Disallow:" /tmp/dirintel_robots_$$.txt 2>/dev/null \
            | sed 's/^[Dd]isallow: *//' | tr -d '\r' | grep -v '^$' | grep -v '^\*')
        if [[ -n "$disallowed" ]]; then
            echo ""
            echo -e "  ${YELLOW}[ROBOTS.TXT]${RESET} Disallowed paths found:"
            while IFS= read -r dpath; do
                echo -e "    ${DIM}→ ${dpath}${RESET}"
                # Write to high_risk_paths for review
                write_result "${base}/high_risk_paths.txt" \
                    "$(tlog "[ROBOTS DISALLOW] ${base_url}${dpath}")"
            done <<< "$disallowed"
        fi
    else
        log_verbose "robots.txt not found (${robots_code})"
    fi
    rm -f /tmp/dirintel_robots_$$.txt

    sleep "$DELAY"

    # sitemap.xml
    local sitemap_url="${base_url}/sitemap.xml"
    local sitemap_code
    sitemap_code=$(curl --silent --max-time "$REQUEST_TIMEOUT" --max-redirs 0 \
        --write-out "%{http_code}" --output /tmp/dirintel_sitemap_$$.txt \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$sitemap_url" 2>/dev/null) || sitemap_code="000"

    if [[ "$sitemap_code" == "200" && -f /tmp/dirintel_sitemap_$$.txt ]]; then
        cat /tmp/dirintel_sitemap_$$.txt > "${base}/sitemap.xml"
        log_ok "sitemap.xml fetched → ${base}/sitemap.xml"

        # Count URLs in sitemap
        local url_count
        url_count=$(grep -c "<loc>" /tmp/dirintel_sitemap_$$.txt 2>/dev/null) || url_count=0
        [[ "$url_count" -gt 0 ]] && echo -e "  ${DIM}↳ ${url_count} URLs found in sitemap${RESET}"
    else
        log_verbose "sitemap.xml not found (${sitemap_code})"
    fi
    rm -f /tmp/dirintel_sitemap_$$.txt

    sleep "$DELAY"
}

detect_backup_files() {
    local base_url="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"

    local -a backup_paths=(
        "backup.zip" "backup.tar.gz" "backup.sql" "backup.bak"
        "db.sql" "database.sql" "dump.sql"
        "site.zip" "www.zip" "web.zip"
        ".env.bak" ".env.old" "config.bak" "config.old"
        "wp-config.php.bak" "settings.php.bak"
    )

    log_info "Checking for common backup file exposure..."

    for bpath in "${backup_paths[@]}"; do
        local full_url="${base_url}/${bpath}"
        local http_code
        http_code=$(curl \
            --silent \
            --head \
            --max-time "$REQUEST_TIMEOUT" \
            --max-redirs 0 \
            --write-out "%{http_code}" \
            --output /dev/null \
            --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
            "$full_url" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "200" ]]; then
            local entry
            entry="$(tlog "[BACKUP EXPOSED] ${full_url} [200 OK]")"
            write_result "${base}/sensitive_files.txt" "$entry"
            echo -e "  ${RED}${BOLD}[BACKUP FILE]${RESET} Accessible: ${full_url}"
            ((TOTAL_SENSITIVE++)) || true
        fi
        sleep "$DELAY"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 2: PROBE A SINGLE PATH (Enumeration + Fingerprinting + Scoring)
# ─────────────────────────────────────────────────────────────────────────────
probe_path() {
    local base_url="$1"
    local path="$2"
    local domain_safe="$3"
    local result_base="${RESULTS_DIR}/${domain_safe}"
    local full_url="${base_url}/${path}"

    log_verbose "Probing: ${full_url}"

    # ── HEAD request for status, size, time ──────────────────────────────────
    local start_s end_s elapsed_ms http_code content_length content_type
    start_s=$(date +%s%N 2>/dev/null || echo "0")

    local head_out
    head_out=$(curl \
        --silent \
        --head \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs 0 \
        --write-out "\n%{http_code}\n%{size_download}\n%{content_type}" \
        --output /dev/null \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$full_url" 2>/dev/null) || head_out="000"

    end_s=$(date +%s%N 2>/dev/null || echo "0")

    http_code=$(echo "$head_out"    | tail -n 3 | head -n 1 | tr -d '[:space:]')
    content_length=$(echo "$head_out" | tail -n 2 | head -n 1 | tr -d '[:space:]')
    content_type=$(echo "$head_out"  | tail -n 1 | tr -d '\r\n')

    if [[ "$start_s" != "0" && "$end_s" != "0" ]]; then
        elapsed_ms=$(( (end_s - start_s) / 1000000 ))
    else
        elapsed_ms="N/A"
    fi

    [[ -z "$http_code" || "$http_code" == "000" ]] && return

    ((TOTAL_REQUESTS++)) || true

    local log_entry
    log_entry="$(tlog "${http_code} | Size:${content_length}B | Time:${elapsed_ms}ms | Type:${content_type} | ${full_url}")"
    write_result "${result_base}/logs.txt" "$log_entry"

    local record="${full_url} [${http_code}] Size:${content_length}B Time:${elapsed_ms}ms Type:${content_type}"

    # ── Categorize by status code ─────────────────────────────────────────────
    case "$http_code" in
        200)
            write_result "${result_base}/categorized/200.txt" "$record"
            ((TOTAL_200++)) || true

            # Single body + header fetch (no double-fetch)
            sleep "$DELAY"
            local hdr_tmp="/tmp/dirintel_hdr_${$}_${RANDOM}.txt"
            local body
            body=$(curl \
                --silent \
                --max-time "$REQUEST_TIMEOUT" \
                --max-redirs 0 \
                --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
                --dump-header "$hdr_tmp" \
                --output - \
                "$full_url" 2>/dev/null) || body=""

            # Page title extraction
            local page_title
            page_title=$(printf '%s' "$body" | grep -oi '<title>[^<]*</title>' 2>/dev/null \
                | sed 's/<[^>]*>//g' | head -n1 | tr -d '\r\n') || page_title=""

            # Fingerprint (pass body + headers — no re-fetch)
            fingerprint_response "$full_url" "$domain_safe" "$body" "$hdr_tmp" > /dev/null
            [[ -f "$hdr_tmp" ]] && rm -f "$hdr_tmp"

            # Directory listing detection
            detect_directory_listing "$full_url" "$body" "$domain_safe"

            # Sensitive path check
            if is_sensitive_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$(tlog "$record")"
                ((TOTAL_HIGH_RISK++)) || true
            fi

            # Sensitive extension check
            if is_sensitive_extension "$path"; then
                write_result "${result_base}/sensitive_files.txt" "$(tlog "$record")"
                ((TOTAL_SENSITIVE++)) || true
            fi

            # Keyword scan
            scan_body_for_keywords "$full_url" "$body" "$domain_safe"

            # Risk scoring
            local score severity
            score=$(calculate_risk_score "$path" "$http_code" "$body")
            severity=$(classify_severity "$score")

            # ── Terminal live output: status + severity badge together ──────
            local sev_badge sev_color
            case "$severity" in
                critical) sev_badge="[CRITICAL]" ; sev_color="${MAGENTA}${BOLD}" ;;
                high)     sev_badge="[HIGH]    " ; sev_color="${RED}${BOLD}"     ;;
                medium)   sev_badge="[MEDIUM]  " ; sev_color="${YELLOW}${BOLD}"  ;;
                low)      sev_badge="[LOW]     " ; sev_color="${GREEN}"          ;;
            esac
            echo -e "  ${GREEN}[200 OK]${RESET} ${sev_color}${sev_badge}${RESET} ${BOLD}${full_url}${RESET}  ${DIM}${content_length}B ${elapsed_ms}ms${RESET}"
            [[ -n "$page_title" ]] && echo -e "           ${DIM}↳ Title: ${page_title}${RESET}"

            write_severity_entry "$domain_safe" "$severity" \
                "[$(timestamp)] Score:${score} | Status:200 | ${full_url} | Size:${content_length}B | Time:${elapsed_ms}ms"
            ;;

        301|302|303|307|308)
            write_result "${result_base}/categorized/redirects.txt" "$record"
            ((TOTAL_REDIRECTS++)) || true

            if is_sensitive_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$(tlog "$record")"
                ((TOTAL_HIGH_RISK++)) || true
            fi
            if is_sensitive_extension "$path"; then
                write_result "${result_base}/sensitive_files.txt" "$(tlog "$record")"
                ((TOTAL_SENSITIVE++)) || true
            fi

            local score severity
            score=$(calculate_risk_score "$path" "$http_code" "")
            severity=$(classify_severity "$score")

            local sev_badge sev_color
            case "$severity" in
                critical) sev_badge="[CRITICAL]" ; sev_color="${MAGENTA}${BOLD}" ;;
                high)     sev_badge="[HIGH]    " ; sev_color="${RED}${BOLD}"     ;;
                medium)   sev_badge="[MEDIUM]  " ; sev_color="${YELLOW}${BOLD}"  ;;
                low)      sev_badge="[LOW]     " ; sev_color="${GREEN}"          ;;
            esac
            echo -e "  ${YELLOW}[${http_code}]${RESET}    ${sev_color}${sev_badge}${RESET} ${full_url}  ${DIM}→ redirect${RESET}"

            write_severity_entry "$domain_safe" "$severity" \
                "[$(timestamp)] Score:${score} | Status:${http_code} | ${full_url} | Redirect"
            ;;

        403)
            write_result "${result_base}/categorized/403.txt" "$record"
            ((TOTAL_403++)) || true

            if is_sensitive_path "$path"; then
                write_result "${result_base}/high_risk_paths.txt" "$(tlog "$record")"
                ((TOTAL_HIGH_RISK++)) || true
            fi

            local score severity
            score=$(calculate_risk_score "$path" "$http_code" "")
            severity=$(classify_severity "$score")

            local sev_badge sev_color
            case "$severity" in
                critical) sev_badge="[CRITICAL]" ; sev_color="${MAGENTA}${BOLD}" ;;
                high)     sev_badge="[HIGH]    " ; sev_color="${RED}${BOLD}"     ;;
                medium)   sev_badge="[MEDIUM]  " ; sev_color="${YELLOW}${BOLD}"  ;;
                low)      sev_badge="[LOW]     " ; sev_color="${GREEN}"          ;;
            esac
            echo -e "  ${MAGENTA}[403]${RESET}    ${sev_color}${sev_badge}${RESET} ${full_url}  ${DIM}→ forbidden${RESET}"

            write_severity_entry "$domain_safe" "$severity" \
                "[$(timestamp)] Score:${score} | Status:403 | ${full_url} | Forbidden"
            ;;

        404|410)
            log_verbose "  [${http_code}] ${full_url} — not found"
            ;;

        *)
            write_result "${result_base}/categorized/other.txt" "$record"
            echo -e "  ${BLUE}[${http_code}]${RESET}    ${DIM}[INFO]${RESET}     ${full_url}"
            ;;
    esac

    sleep "$DELAY"
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 2: DIRECTORY ENUMERATION (controlled, rate-limited, threaded)
# ─────────────────────────────────────────────────────────────────────────────
enumerate_target() {
    local base_url="$1"
    local domain_safe="$2"
    local wordlist="$3"

    local total_words
    total_words=$(wc -l < "$wordlist" | tr -d '[:space:]')

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  DIRECTORY ENUMERATION                                          ║${RESET}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${BOLD}║${RESET}  Target    : ${CYAN}${base_url}${RESET}"
    echo -e "${BOLD}║${RESET}  Wordlist  : ${wordlist} ${DIM}(${total_words} words)${RESET}"
    echo -e "${BOLD}║${RESET}  Extensions: ${EXTENSIONS[*]:-none}"
    echo -e "${BOLD}║${RESET}  Delay     : ${DELAY}s  │  Threads: ${THREADS}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${DIM}STATUS   SEVERITY    URL${RESET}"
    echo -e "  ${DIM}──────── ─────────── ──────────────────────────────────────────${RESET}"

    # Build full path list (word + word.ext for each extension)
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

        draw_progress_bar "$current" "$total_paths"

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
    echo ""
    log_ok "Enumeration complete: ${base_url}"
}

# ─────────────────────────────────────────────────────────────────────────────
# PART 8: REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
generate_report() {
    local domain="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/${domain_safe}"
    local report_file="${base}/report.md"
    local scan_end_time
    scan_end_time=$(timestamp)

    # Count results
    local c200 c403 credir cother chigh csens cexpose ccrit chigh_sev cmed clow cdir cgit
    c200=$(wc -l < "${base}/categorized/200.txt"          2>/dev/null | tr -d '[:space:]') || c200=0
    c403=$(wc -l < "${base}/categorized/403.txt"          2>/dev/null | tr -d '[:space:]') || c403=0
    credir=$(wc -l < "${base}/categorized/redirects.txt"  2>/dev/null | tr -d '[:space:]') || credir=0
    cother=$(wc -l < "${base}/categorized/other.txt"      2>/dev/null | tr -d '[:space:]') || cother=0
    chigh=$(wc -l < "${base}/high_risk_paths.txt"         2>/dev/null | tr -d '[:space:]') || chigh=0
    csens=$(wc -l < "${base}/sensitive_files.txt"         2>/dev/null | tr -d '[:space:]') || csens=0
    ccrit=$(wc -l < "${base}/severity/critical/findings.txt" 2>/dev/null | tr -d '[:space:]') || ccrit=0
    chigh_sev=$(wc -l < "${base}/severity/high/findings.txt" 2>/dev/null | tr -d '[:space:]') || chigh_sev=0
    cmed=$(wc -l < "${base}/severity/medium/findings.txt"    2>/dev/null | tr -d '[:space:]') || cmed=0
    clow=$(wc -l < "${base}/severity/low/findings.txt"       2>/dev/null | tr -d '[:space:]') || clow=0
    cdir=$(wc -l < "${base}/directory_listing_exposed.txt" 2>/dev/null | tr -d '[:space:]') || cdir=0
    cgit=$(wc -l < "${base}/git_exposure.txt"             2>/dev/null | tr -d '[:space:]') || cgit=0

    local total_domain=$(( c200 + c403 + credir + cother ))
    local total_severity=$(( ccrit + chigh_sev + cmed + clow ))

    # Build text-based risk distribution chart
    local chart_critical="" chart_high="" chart_medium="" chart_low=""
    local bar_width=30
    [[ "$total_severity" -gt 0 ]] && {
        local bc bh bm bl
        bc=$(( ccrit     * bar_width / total_severity )) || bc=0
        bh=$(( chigh_sev * bar_width / total_severity )) || bh=0
        bm=$(( cmed      * bar_width / total_severity )) || bm=0
        bl=$(( clow      * bar_width / total_severity )) || bl=0

        local i
        for (( i=0; i<bc; i++ )); do chart_critical+="█"; done
        for (( i=0; i<bh; i++ )); do chart_high+="█"; done
        for (( i=0; i<bm; i++ )); do chart_medium+="█"; done
        for (( i=0; i<bl; i++ )); do chart_low+="█"; done
    }

    {
        cat << HEADER
# DirIntel Pro — Security Intelligence Report

---

## Scan Overview

| Field              | Value                                     |
|--------------------|-------------------------------------------|
| **Target**         | \`${domain}\`                             |
| **Scan Started**   | ${SCAN_START_TIME}                        |
| **Scan Completed** | ${scan_end_time}                          |
| **Tool Version**   | DirIntel Pro v${VERSION}                  |
| **Wordlist**       | ${WORDLIST}                               |
| **Extensions**     | ${EXTENSIONS[*]:-none}                    |
| **Delay**          | ${DELAY}s                                 |
| **Threads**        | ${THREADS}                                |

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

| Category                      | Count          |
|-------------------------------|----------------|
| High Risk Paths               | ${chigh}       |
| Sensitive Files               | ${csens}       |
| Directory Listing Exposed     | ${cdir}        |
| Git Repository Exposed        | ${cgit}        |

---

## Risk Distribution Chart

\`\`\`
CRITICAL  [${chart_critical}] ${ccrit}
HIGH      [${chart_high}] ${chigh_sev}
MEDIUM    [${chart_medium}] ${cmed}
LOW       [${chart_low}] ${clow}
\`\`\`

---

## Severity Breakdown

### CRITICAL Findings

HEADER

        echo "> Saved to: \`severity/critical/findings.txt\`"
        echo ""
        if [[ -s "${base}/severity/critical/findings.txt" ]]; then
            echo '```'
            cat "${base}/severity/critical/findings.txt"
            echo '```'
        else
            echo "_No critical findings._"
        fi

        echo ""
        echo "### HIGH Findings"
        echo ""
        echo "> Saved to: \`severity/high/findings.txt\`"
        echo ""
        if [[ -s "${base}/severity/high/findings.txt" ]]; then
            echo '```'
            cat "${base}/severity/high/findings.txt"
            echo '```'
        else
            echo "_No high severity findings._"
        fi

        echo ""
        echo "### MEDIUM Findings"
        echo ""
        echo "> Saved to: \`severity/medium/findings.txt\`"
        echo ""
        if [[ -s "${base}/severity/medium/findings.txt" ]]; then
            echo '```'
            cat "${base}/severity/medium/findings.txt"
            echo '```'
        else
            echo "_No medium severity findings._"
        fi

        echo ""
        echo "### LOW Findings"
        echo ""
        echo "> Saved to: \`severity/low/findings.txt\`"
        echo ""
        if [[ -s "${base}/severity/low/findings.txt" ]]; then
            echo '```'
            cat "${base}/severity/low/findings.txt"
            echo '```'
        else
            echo "_No low severity findings._"
        fi

        echo ""
        echo "---"
        echo ""
        echo "## High Risk Paths"
        echo ""
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

## Directory Listing Exposure

SEC3

        if [[ -s "${base}/directory_listing_exposed.txt" ]]; then
            echo '```'
            cat "${base}/directory_listing_exposed.txt"
            echo '```'
        else
            echo "_No directory listing exposure detected._"
        fi

        cat << SEC4

---

## Git Repository Exposure

SEC4

        if [[ -s "${base}/git_exposure.txt" ]]; then
            echo '```'
            cat "${base}/git_exposure.txt"
            echo '```'
        else
            echo "_No Git repository exposure detected._"
        fi

        cat << SEC5

---

## Response Fingerprint Analysis

SEC5

        if [[ -s "${base}/fingerprint_analysis.txt" ]]; then
            echo '```'
            cat "${base}/fingerprint_analysis.txt"
            echo '```'
        else
            echo "_No fingerprint data collected._"
        fi

        cat << SEC6

---

## 200 OK Paths

SEC6

        if [[ -s "${base}/categorized/200.txt" ]]; then
            echo '```'
            cat "${base}/categorized/200.txt"
            echo '```'
        else
            echo "_No accessible paths found._"
        fi

        cat << SEC7

---

## 403 Forbidden Paths

SEC7

        if [[ -s "${base}/categorized/403.txt" ]]; then
            echo '```'
            cat "${base}/categorized/403.txt"
            echo '```'
        else
            echo "_No forbidden paths found._"
        fi

        cat << SEC8

---

## Redirect Paths

SEC8

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

### How Developers Can Prevent Exposure

1. **Restrict Admin Panels**
   If \`/admin\`, \`/dashboard\`, or \`/console\` return 200 or 403, protect them
   with strong multi-factor authentication and IP allowlisting. Never expose
   admin interfaces to the public internet without authentication.

2. **Remove Backup & Config Files from Web Root**
   Files like \`.env\`, \`.bak\`, \`.sql\`, \`config.yml\` must **never** be
   publicly accessible. Store them outside the web root or use server-level
   deny rules. Rotate any credentials that may have been exposed.

3. **Block Git Repository Access**
   If \`/.git\` is accessible, your entire source code history may be
   downloadable. Add the following to your web server config:
   \`\`\`nginx
   location ~ /\.git { deny all; return 404; }
   \`\`\`

4. **Disable Directory Listing**
   Ensure \`Options -Indexes\` (Apache) or \`autoindex off\` (Nginx) is set
   to prevent directory contents from being listed.

5. **Sanitize Sensitive Data in Responses**
   If keywords like \`password\`, \`api_key\`, or \`token\` were found in
   responses, audit those endpoints immediately. Never return credentials
   in HTTP responses.

6. **Secure Upload Directories**
   Restrict access to \`/uploads\`, \`/files\`, and similar directories.
   Validate file types server-side and never execute uploaded files.

7. **Remove Debug & Test Endpoints**
   Endpoints like \`/debug\`, \`/test\`, \`/phpinfo\`, \`/status\` must be
   disabled or removed in production environments.

8. **Enforce HTTPS**
   All HTTP traffic should redirect to HTTPS. Use HSTS headers:
   \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`

9. **Return 404 for Restricted Paths**
   Consider returning 404 instead of 403 for sensitive paths to avoid
   confirming their existence to potential attackers.

10. **Implement Security Headers**
    Add: \`X-Content-Type-Options\`, \`X-Frame-Options\`, \`Content-Security-Policy\`,
    \`Referrer-Policy\` to all responses.

---

## False Positive Disclaimer

> **Important:** This tool performs automated analysis and may produce false
> positives. All findings should be manually verified before taking action.
> A 200 response does not necessarily indicate a security vulnerability —
> context and content must be evaluated. Risk scores are indicative only
> and should be interpreted by a qualified security professional.

---

## Legal Notice

> This scan was performed with explicit authorization.
> Results are confidential and intended for the system owner only.
> Unauthorized disclosure of this report may violate applicable laws.

---

*Generated by DirIntel Pro v${VERSION} — $(timestamp)*
RECS

    } > "$report_file"

    log_ok "Report saved: ${report_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY PRINT
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    local total_found=$(( TOTAL_200 + TOTAL_403 + TOTAL_REDIRECTS ))

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║            SCAN COMPLETE — INTELLIGENCE SUMMARY                 ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    # ── Request stats ──────────────────────────────────────────────────────
    echo -e "  ${BOLD}${WHITE}REQUEST STATISTICS${RESET}"
    echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
    echo -e "  ${CYAN}  Total Requests  :${RESET}  ${BOLD}${TOTAL_REQUESTS}${RESET}"
    echo -e "  ${GREEN}  200 OK          :${RESET}  ${TOTAL_200}"
    echo -e "  ${MAGENTA}  403 Forbidden   :${RESET}  ${TOTAL_403}"
    echo -e "  ${YELLOW}  Redirects       :${RESET}  ${TOTAL_REDIRECTS}"
    echo ""

    # ── Security findings ──────────────────────────────────────────────────
    echo -e "  ${BOLD}${WHITE}SECURITY FINDINGS${RESET}"
    echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
    echo -e "  ${RED}  High Risk Paths :${RESET}  ${TOTAL_HIGH_RISK}"
    echo -e "  ${MAGENTA}  Sensitive Files :${RESET}  ${TOTAL_SENSITIVE}"
    echo -e "  ${RED}  Data Exposure   :${RESET}  ${TOTAL_EXPOSURE}"
    echo ""

    # ── Subdomain stats (if ran) ───────────────────────────────────────────
    if [[ -n "$SUBDOMAIN_WORDLIST" ]]; then
        echo -e "  ${BOLD}${WHITE}SUBDOMAIN SCAN${RESET}"
        echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
        echo -e "  ${CYAN}  Active Subdomains Found :${RESET}  ${TOTAL_SUBDOMAINS_FOUND}"
        echo -e "  ${DIM}  Saved → ./${RESULTS_DIR}/subdomains/${RESET}"
        echo ""
    fi

    # ── Severity breakdown table ───────────────────────────────────────────
    echo -e "  ${BOLD}${WHITE}RISK SEVERITY BREAKDOWN${RESET}"
    echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
    echo -e "  ${MAGENTA}${BOLD}  ● CRITICAL  :  ${TOTAL_CRITICAL}${RESET}   ${DIM}→ severity/critical/findings.txt${RESET}"
    echo -e "  ${RED}${BOLD}  ● HIGH      :  ${TOTAL_HIGH_SEV}${RESET}   ${DIM}→ severity/high/findings.txt${RESET}"
    echo -e "  ${YELLOW}${BOLD}  ● MEDIUM    :  ${TOTAL_MEDIUM}${RESET}   ${DIM}→ severity/medium/findings.txt${RESET}"
    echo -e "  ${GREEN}${BOLD}  ● LOW       :  ${TOTAL_LOW}${RESET}   ${DIM}→ severity/low/findings.txt${RESET}"
    echo ""

    # ── Visual bar chart ───────────────────────────────────────────────────
    local total_sev=$(( TOTAL_CRITICAL + TOTAL_HIGH_SEV + TOTAL_MEDIUM + TOTAL_LOW ))
    if [[ "$total_sev" -gt 0 ]]; then
        local bar_w=35
        local bc bh bm bl
        bc=$(( TOTAL_CRITICAL * bar_w / total_sev )) || bc=0
        bh=$(( TOTAL_HIGH_SEV * bar_w / total_sev )) || bh=0
        bm=$(( TOTAL_MEDIUM   * bar_w / total_sev )) || bm=0
        bl=$(( TOTAL_LOW      * bar_w / total_sev )) || bl=0

        local bar_c="" bar_h="" bar_m="" bar_l=""
        local i
        for (( i=0; i<bc; i++ )); do bar_c+="█"; done
        for (( i=0; i<bh; i++ )); do bar_h+="█"; done
        for (( i=0; i<bm; i++ )); do bar_m+="█"; done
        for (( i=0; i<bl; i++ )); do bar_l+="█"; done

        echo -e "  ${BOLD}${WHITE}RISK DISTRIBUTION CHART${RESET}"
        echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
        printf "  ${MAGENTA}${BOLD}  CRITICAL${RESET}  ${MAGENTA}%-35s${RESET}  %d\n" "$bar_c" "$TOTAL_CRITICAL"
        printf "  ${RED}${BOLD}  HIGH    ${RESET}  ${RED}%-35s${RESET}  %d\n"      "$bar_h" "$TOTAL_HIGH_SEV"
        printf "  ${YELLOW}  MEDIUM  ${RESET}  ${YELLOW}%-35s${RESET}  %d\n"       "$bar_m" "$TOTAL_MEDIUM"
        printf "  ${GREEN}  LOW     ${RESET}  ${GREEN}%-35s${RESET}  %d\n"         "$bar_l" "$TOTAL_LOW"
        echo ""
    fi

    # ── Output folder tree ─────────────────────────────────────────────────
    echo -e "  ${BOLD}${WHITE}OUTPUT FOLDER STRUCTURE${RESET}"
    echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
    echo -e "  ${CYAN}  ./${RESULTS_DIR}/${RESET}"
    echo -e "  ${DIM}  ├── live_hosts.txt${RESET}"
    echo -e "  ${DIM}  ├── dead_hosts.txt${RESET}"
    echo -e "  ${DIM}  └── <domain>/${RESET}"
    echo -e "  ${DIM}      ├── categorized/   (200.txt, 403.txt, redirects.txt)${RESET}"
    echo -e "  ${DIM}      ├── severity/${RESET}"
    echo -e "  ${MAGENTA}${BOLD}  │       ├── critical/findings.txt${RESET}"
    echo -e "  ${RED}${BOLD}  │       ├── high/findings.txt${RESET}"
    echo -e "  ${YELLOW}  │       ├── medium/findings.txt${RESET}"
    echo -e "  ${GREEN}  │       └── low/findings.txt${RESET}"
    echo -e "  ${DIM}      ├── high_risk_paths.txt${RESET}"
    echo -e "  ${DIM}      ├── sensitive_files.txt${RESET}"
    echo -e "  ${DIM}      ├── fingerprint_analysis.txt${RESET}"
    echo -e "  ${DIM}      ├── git_exposure.txt${RESET}"
    echo -e "  ${DIM}      ├── robots.txt${RESET}"
    echo -e "  ${DIM}      ├── sitemap.xml${RESET}"
    echo -e "  ${DIM}      ├── report.md${RESET}"
    echo -e "  ${DIM}      └── logs.txt${RESET}"
    echo ""

    echo -e "${YELLOW}  ⚠  Use only on systems you own or have explicit written permission to test.${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN ENUMERATION MODULE
# ─────────────────────────────────────────────────────────────────────────────

# Setup dedicated subdomain result directories
setup_subdomain_dir() {
    local domain_safe="$1"
    local base="${RESULTS_DIR}/subdomains/${domain_safe}"

    ensure_dir "${RESULTS_DIR}/subdomains"
    ensure_dir "${base}"

    for f in \
        "${base}/live_subdomains.txt" \
        "${base}/dead_subdomains.txt" \
        "${base}/redirecting_subdomains.txt" \
        "${base}/forbidden_subdomains.txt" \
        "${base}/all_subdomains.txt" \
        "${base}/subdomain_logs.txt"
    do
        : > "$f"
    done
}

# Probe a single subdomain via HEAD request
probe_subdomain() {
    local subdomain="$1"
    local base_domain="$2"
    local domain_safe="$3"
    local base="${RESULTS_DIR}/subdomains/${domain_safe}"

    # Build full subdomain URL (try https first, fallback to http)
    local full_host="${subdomain}.${base_domain}"
    local url="https://${full_host}"

    log_verbose "Probing subdomain: ${url}"

    local http_code response_time server_header
    http_code=$(curl \
        --silent \
        --head \
        --max-time "$REQUEST_TIMEOUT" \
        --max-redirs "$MAX_REDIRECTS" \
        --write-out "%{http_code}" \
        --dump-header /tmp/dirintel_sub_$$.txt \
        --output /dev/null \
        --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
        "$url" 2>/dev/null) || http_code="000"

    # If https fails (000), retry with http
    if [[ "$http_code" == "000" ]]; then
        url="http://${full_host}"
        http_code=$(curl \
            --silent \
            --head \
            --max-time "$REQUEST_TIMEOUT" \
            --max-redirs "$MAX_REDIRECTS" \
            --write-out "%{http_code}" \
            --dump-header /tmp/dirintel_sub_$$.txt \
            --output /dev/null \
            --user-agent "${TOOL_NAME}/${VERSION} (Authorized Security Audit)" \
            "$url" 2>/dev/null) || http_code="000"
    fi

    # Extract server header
    server_header="Unknown"
    if [[ -f /tmp/dirintel_sub_$$.txt ]]; then
        server_header=$(grep -i "^Server:" /tmp/dirintel_sub_$$.txt 2>/dev/null \
            | head -n1 | sed 's/^[Ss]erver: *//I' | tr -d '\r\n') || server_header="Unknown"
        [[ -z "$server_header" ]] && server_header="Unknown"
        rm -f /tmp/dirintel_sub_$$.txt
    fi

    local record="${full_host} | URL: ${url} | Status: ${http_code} | Server: ${server_header}"
    write_result "${base}/all_subdomains.txt" "$record"
    write_result "${base}/subdomain_logs.txt" "$(tlog "$record")"

    case "$http_code" in
        200)
            write_result "${base}/live_subdomains.txt" "$record"
            echo -e "  ${GREEN}[LIVE]${RESET}        ${BOLD}${full_host}${RESET}  ${DIM}[200 OK] Server: ${server_header}${RESET}"
            ((TOTAL_SUBDOMAINS_FOUND++)) || true ;;
        301|302|303|307|308)
            write_result "${base}/redirecting_subdomains.txt" "$record"
            echo -e "  ${YELLOW}[REDIRECT]${RESET}    ${full_host}  ${DIM}[${http_code}] Server: ${server_header}${RESET}"
            ((TOTAL_SUBDOMAINS_FOUND++)) || true ;;
        403)
            write_result "${base}/forbidden_subdomains.txt" "$record"
            echo -e "  ${MAGENTA}[FORBIDDEN]${RESET}   ${full_host}  ${DIM}[403] Server: ${server_header}${RESET}"
            ((TOTAL_SUBDOMAINS_FOUND++)) || true ;;
        000|"")
            write_result "${base}/dead_subdomains.txt" "${full_host} | DEAD | No Response"
            log_verbose "  [DEAD] ${full_host}" ;;
        *)
            write_result "${base}/live_subdomains.txt" "$record"
            echo -e "  ${CYAN}[${http_code}]${RESET}         ${full_host}  ${DIM}Server: ${server_header}${RESET}"
            ((TOTAL_SUBDOMAINS_FOUND++)) || true ;;
    esac

    sleep "$DELAY"
}

# Generate subdomain markdown report
generate_subdomain_report() {
    local domain="$1"
    local domain_safe="$2"
    local base="${RESULTS_DIR}/subdomains/${domain_safe}"
    local report_file="${base}/subdomain_report.md"
    local scan_end_time
    scan_end_time=$(timestamp)

    local clive cdead credir cforbid ctotal
    clive=$(wc -l < "${base}/live_subdomains.txt"        2>/dev/null | tr -d '[:space:]') || clive=0
    cdead=$(wc -l < "${base}/dead_subdomains.txt"        2>/dev/null | tr -d '[:space:]') || cdead=0
    credir=$(wc -l < "${base}/redirecting_subdomains.txt" 2>/dev/null | tr -d '[:space:]') || credir=0
    cforbid=$(wc -l < "${base}/forbidden_subdomains.txt" 2>/dev/null | tr -d '[:space:]') || cforbid=0
    ctotal=$(wc -l < "${base}/all_subdomains.txt"        2>/dev/null | tr -d '[:space:]') || ctotal=0

    {
        echo "# DirIntel Pro — Subdomain Intelligence Report"
        echo ""
        echo "---"
        echo ""
        echo "## Scan Overview"
        echo ""
        echo "| Field              | Value                              |"
        echo "|--------------------|-------------------------------------|"
        echo "| **Target Domain**  | \`${domain}\`                       |"
        echo "| **Scan Started**   | ${SCAN_START_TIME}                  |"
        echo "| **Scan Completed** | ${scan_end_time}                    |"
        echo "| **Tool Version**   | DirIntel Pro v${VERSION}            |"
        echo "| **Subdomain List** | ${SUBDOMAIN_WORDLIST}               |"
        echo "| **Delay**          | ${DELAY}s                           |"
        echo "| **Threads**        | ${THREADS}                          |"
        echo ""
        echo "---"
        echo ""
        echo "## Results Summary"
        echo ""
        echo "| Category              | Count        |"
        echo "|-----------------------|--------------|"
        echo "| Total Probed          | ${ctotal}    |"
        echo "| Live (200)            | ${clive}     |"
        echo "| Redirecting           | ${credir}    |"
        echo "| Forbidden (403)       | ${cforbid}   |"
        echo "| Dead / No Response    | ${cdead}     |"
        echo ""
        echo "---"
        echo ""
        echo "## Live Subdomains"
        echo ""
        if [[ -s "${base}/live_subdomains.txt" ]]; then
            echo '```'
            cat "${base}/live_subdomains.txt"
            echo '```'
        else
            echo "_No live subdomains found._"
        fi
        echo ""
        echo "---"
        echo ""
        echo "## Redirecting Subdomains"
        echo ""
        if [[ -s "${base}/redirecting_subdomains.txt" ]]; then
            echo '```'
            cat "${base}/redirecting_subdomains.txt"
            echo '```'
        else
            echo "_No redirecting subdomains found._"
        fi
        echo ""
        echo "---"
        echo ""
        echo "## Forbidden Subdomains (403)"
        echo ""
        if [[ -s "${base}/forbidden_subdomains.txt" ]]; then
            echo '```'
            cat "${base}/forbidden_subdomains.txt"
            echo '```'
        else
            echo "_No forbidden subdomains found._"
        fi
        echo ""
        echo "---"
        echo ""
        echo "## Dead Subdomains"
        echo ""
        if [[ -s "${base}/dead_subdomains.txt" ]]; then
            echo '```'
            cat "${base}/dead_subdomains.txt"
            echo '```'
        else
            echo "_No dead subdomains._"
        fi
        echo ""
        echo "---"
        echo ""
        echo "## All Probed Subdomains"
        echo ""
        if [[ -s "${base}/all_subdomains.txt" ]]; then
            echo '```'
            cat "${base}/all_subdomains.txt"
            echo '```'
        else
            echo "_No subdomains probed._"
        fi
        echo ""
        echo "---"
        echo ""
        echo "## Security Notes"
        echo ""
        echo "- **Forgotten subdomains** (dev, staging, test, old) are common attack vectors."
        echo "- **Admin subdomains** (admin, panel, cpanel) should require strong authentication."
        echo "- **Backup/internal subdomains** should never be publicly accessible."
        echo "- **Subdomain takeover**: If a subdomain returns CNAME to an unclaimed service,"
        echo "  it may be vulnerable to takeover. Verify DNS records for all live subdomains."
        echo ""
        echo "---"
        echo ""
        echo "## False Positive Disclaimer"
        echo ""
        echo "> Subdomain results are based on HTTP probing only. DNS-level verification"
        echo "> is recommended for accurate results. Some responses may be catch-all"
        echo "> wildcard DNS entries and not actual services."
        echo ""
        echo "---"
        echo ""
        echo "*Generated by DirIntel Pro v${VERSION} — $(timestamp)*"

    } > "$report_file"

    log_ok "Subdomain report saved: ${report_file}"
}

# Main subdomain scan runner
run_subdomain_scan() {
    local raw_target="$1"
    local url
    url=$(normalize_url "$raw_target")

    # Extract bare domain (strip protocol and path)
    local base_domain
    base_domain=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||' | sed 's|:[0-9]*$||')
    local domain_safe
    domain_safe=$(sanitize_domain "$base_domain")

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  SUBDOMAIN ENUMERATION — ${CYAN}${base_domain}${RESET}${BOLD}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    setup_subdomain_dir "$domain_safe"
    write_result "${RESULTS_DIR}/subdomains/${domain_safe}/subdomain_logs.txt" \
        "$(tlog "Subdomain scan started: ${base_domain}")"

    local total_subs
    total_subs=$(grep -v '^\s*#' "$SUBDOMAIN_WORDLIST" | grep -v '^\s*$' | wc -l | tr -d '[:space:]')
    log_info "Subdomain wordlist : ${SUBDOMAIN_WORDLIST} (${total_subs} entries)"
    log_info "Target domain      : ${base_domain}"
    log_info "Output folder      : ${RESULTS_DIR}/subdomains/${domain_safe}/"
    echo ""

    local current=0
    local active_jobs=0
    local -a subdomain_list=()

    while IFS= read -r sub || [[ -n "$sub" ]]; do
        [[ -z "$sub" || "$sub" == \#* ]] && continue
        sub=$(echo "$sub" | tr -d '[:space:]')
        [[ -z "$sub" ]] && continue
        subdomain_list+=("$sub")
    done < "$SUBDOMAIN_WORDLIST"

    local total_count=${#subdomain_list[@]}

    for sub in "${subdomain_list[@]}"; do
        ((current++)) || true
        draw_progress_bar "$current" "$total_count"

        if [[ "$THREADS" -gt 1 ]]; then
            probe_subdomain "$sub" "$base_domain" "$domain_safe" &
            ((active_jobs++)) || true
            if [[ "$active_jobs" -ge "$THREADS" ]]; then
                wait
                active_jobs=0
            fi
        else
            probe_subdomain "$sub" "$base_domain" "$domain_safe"
        fi
    done

    wait
    echo ""
    echo ""
    log_ok "Subdomain scan complete for: ${base_domain}"
    log_ok "Live/Active subdomains found: ${TOTAL_SUBDOMAINS_FOUND}"
    echo ""

    generate_subdomain_report "$base_domain" "$domain_safe"
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

    # Reset wildcard detection state for each target
    WILDCARD_BASELINE_HASH=""
    WILDCARD_BASELINE_SIZE=""
    WILDCARD_COUNT=0

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  TARGET SCAN                                                    ║${RESET}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${BOLD}║${RESET}  URL    : ${CYAN}${BOLD}${url}${RESET}"
    echo -e "${BOLD}║${RESET}  Time   : $(timestamp)"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"

    local status
    status=$(check_live_host "$url")

    if [[ "$status" != "live" ]]; then
        log_warn "Skipping dead host: ${url}"
        return
    fi

    setup_results_dir "$domain_safe"
    write_result "${RESULTS_DIR}/${domain_safe}/logs.txt" "$(tlog "Scan started: ${url}")"

    # Part 6: Advanced checks before enumeration
    echo ""
    log_info "Running advanced pre-scan checks..."
    fetch_robots_and_sitemap "$url" "$domain_safe"
    detect_git_exposure "$url" "$domain_safe"
    detect_backup_files "$url" "$domain_safe"

    # Part 2: Main enumeration
    enumerate_target "$url" "$domain_safe" "$WORDLIST"

    # Part 8: Report
    generate_report "$url" "$domain_safe"

    write_result "${RESULTS_DIR}/${domain_safe}/logs.txt" "$(tlog "Scan completed: ${url}")"
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

    echo -e "${BOLD}  Scan started  : ${SCAN_START_TIME}${RESET}"
    echo -e "  Delay: ${DELAY}s | Max Threads: ${THREADS} | Wordlist: ${WORDLIST}"
    [[ -n "$SUBDOMAIN_WORDLIST" ]] && \
        echo -e "  Subdomain List: ${SUBDOMAIN_WORDLIST}"
    echo ""

    if [[ -n "$SINGLE_URL" ]]; then
        # Run subdomain scan first if requested
        if [[ -n "$SUBDOMAIN_WORDLIST" ]]; then
            run_subdomain_scan "$SINGLE_URL"
        fi
        process_target "$SINGLE_URL"
    elif [[ -n "$DOMAIN_LIST" ]]; then
        local count=0
        while IFS= read -r target || [[ -n "$target" ]]; do
            [[ -z "$target" || "$target" == \#* ]] && continue
            target=$(echo "$target" | tr -d '[:space:]')
            [[ -z "$target" ]] && continue
            ((count++)) || true
            # Run subdomain scan first if requested
            if [[ -n "$SUBDOMAIN_WORDLIST" ]]; then
                run_subdomain_scan "$target"
            fi
            process_target "$target"
        done < "$DOMAIN_LIST"
        log_info "Processed ${count} target(s)."
    fi

    print_summary
}

main "$@"
