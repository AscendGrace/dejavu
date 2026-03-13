#!/usr/bin/env bash
# ============================================================
#  Dejavu Security Baseline Checker v2.0.0
#  License: MIT  |  https://github.com/your-org/dejavu
# ============================================================
# Note: -e is not used. It is normal behavior for grep and similar commands to return 1 when no matches are found.
# Using -e would cause the scan to exit early on the first grep with no matches, preventing report generation.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/color.sh"
source "${SCRIPT_DIR}/lib/score.sh"
source "${SCRIPT_DIR}/lib/report.sh"
source "${SCRIPT_DIR}/lib/openclaw_cli.sh"

VERSION="2.0.0"
REPORT_DIR="${SCRIPT_DIR}/output"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/dejavu_report_${TIMESTAMP}.md"

# ---- Default Values ----
OPENCLAW_DIR=""
CHECKS="all"
OUTPUT_FORMAT="json"
VERBOSE=false
FIX_MODE=false
RUNTIME_CHECK=false
OPENCLAW_GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
OPENCLAW_BROWSER_PORT="${OPENCLAW_BROWSER_PORT:-18791}"

usage() {
  cat <<EOF
${BOLD}Dejavu Security Baseline Checker v${VERSION}${RESET}

${BOLD}Usage:${RESET}
  dejavu.sh [options] --dir <openclaw-project-path>

${BOLD}Options:${RESET}
  --dir <path>        OpenClaw project/config directory path (required)
  --checks <list>     Check modules: config,skills,network,proxy,runtime,auth,deps,hostaudit,dlp
                      Default: all
  --output <format>   Output format: json|markdown  Default: json
  --report <file>     Save report to specified file
  --fix               Show fix commands (dry-run mode)
      --runtime       Enable live instance runtime checks (requires running openclaw)
      --port <port>   Override gateway port (default: 18789)
  --verbose           Verbose output
  --help              Show this help

${BOLD}Examples:${RESET}
  ./dejavu.sh --dir ~/.openclaw
  ./dejavu.sh --dir ~/.openclaw --runtime --fix --verbose
  ./dejavu.sh --dir ~/.openclaw --checks network,auth --output json
  ./dejavu.sh --dir ~/.openclaw --output markdown --report /tmp/report.md

${BOLD}Check Modules:${RESET}
  config      Configuration files (openclaw.json, SOUL.md, AGENTS.md...)
  skills      Skills supply chain & security
  network     Network exposure (ports, TLS, auth)
  proxy       Proxy/reverse proxy configuration
  runtime     Live instance state checks   ★ New Feature ★
  auth        Authentication strength deep check  ★ New Feature ★
  deps        Dependency vulnerability scan       ★ New Feature ★
  hostaudit   Host-level audit (SlowMist #3-6,8-9) ★ New Feature ★
  dlp         DLP + Integrity baseline + backup  ★ New Feature ★

${BOLD}Exit Codes:${RESET}
  0  No MEDIUM/HIGH/CRITICAL level issues
  1  MEDIUM level issues present
  2  HIGH level issues present
  3  CRITICAL level issues present
EOF
  exit 0
}

# ---- Parameter Parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)          OPENCLAW_DIR="$2";           shift 2 ;;
    --checks)       CHECKS="$2";                 shift 2 ;;
    --output)       OUTPUT_FORMAT="$2";          shift 2 ;;
    --report)       REPORT_FILE="$2";            shift 2 ;;
    --fix)          FIX_MODE=true;               shift ;;
       --runtime)   RUNTIME_CHECK=true;          shift ;;
       --port)      OPENCLAW_GATEWAY_PORT="$2";  shift 2 ;;
    --verbose)      VERBOSE=true;                shift ;;
    --help)         usage ;;
    *) echo_error "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$OPENCLAW_DIR" ]] && { echo_error "Required parameter: --dir"; usage; }
[[ ! -d "$OPENCLAW_DIR" ]] && { echo_error "Directory not found: $OPENCLAW_DIR"; exit 1; }

mkdir -p "$REPORT_DIR"
export OPENCLAW_DIR VERBOSE FIX_MODE OUTPUT_FORMAT REPORT_FILE SCRIPT_DIR
export OPENCLAW_GATEWAY_PORT OPENCLAW_BROWSER_PORT RUNTIME_CHECK

print_banner() {
  echo -e "${CYAN}${BOLD}"
  cat <<'BANNER'
 ██████╗ ███████╗     ██╗ █████╗ ██╗   ██╗██╗   ██╗
 ██╔══██╗██╔════╝     ██║██╔══██╗██║   ██║██║   ██║
 ██║  ██║█████╗       ██║███████║██║   ██║██║   ██║
 ██║  ██║██╔══╝  ██   ██║██╔══██║╚██╗ ██╔╝██║   ██║
 ██████╔╝███████╗╚█████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝
 ╚═════╝ ╚══════╝ ╚════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ 
  Dejavu Security Baseline Checker v2.0.0
BANNER
  echo -e "${RESET}"
  echo_info "Target Directory:  ${BOLD}${OPENCLAW_DIR}${RESET}"
  echo_info "Check Modules:  ${BOLD}${CHECKS}${RESET}"
  echo_info "Runtime Checks: ${BOLD}${RUNTIME_CHECK}${RESET}"
  echo_info "Start Time: $(date +"%Y-%m-%d %H:%M:%S %Z")"
  echo ""
}

run_checks() {
  local checks_to_run=()
  if [[ "$CHECKS" == "all" ]]; then
    checks_to_run=(config skills network proxy runtime auth deps hostaudit dlp)
  else
    IFS=',' read -ra checks_to_run <<< "$CHECKS"
  fi

  for check in "${checks_to_run[@]}"; do
    check=$(echo "$check" | tr -d '[:space:]')
    # runtime module only runs with --runtime flag
    if [[ "$check" == "runtime" && "$RUNTIME_CHECK" == "false" ]]; then
      echo_skip "[runtime] Skipped — use --runtime parameter to enable live instance checks"
      continue
    fi
    local idx
    idx=$(get_check_index "$check")
    local check_script="${SCRIPT_DIR}/checks/${idx}_${check}.sh"
    if [[ -f "$check_script" ]]; then
      echo_section "[$check] $(get_check_title "$check")"
      # shellcheck source=/dev/null
      source "$check_script"
      "run_${check}_checks"
    else
      echo_warn "Check module not found: ${check_script}"
    fi
  done
}

get_check_index() {
  case "$1" in
    config)    echo "01" ;;
    skills)    echo "02" ;;
    network)   echo "03" ;;
    proxy)     echo "04" ;;
    runtime)   echo "05" ;;
    auth)      echo "06" ;;
    deps)      echo "07" ;;
    hostaudit) echo "08" ;;
    dlp)       echo "09" ;;
    *)         echo "00" ;;
  esac
}

get_check_title() {
  case "$1" in
    config)    echo "Configuration File Security" ;;
    skills)    echo "Skills Supply Chain & Safety" ;;
    network)   echo "Network Exposure Analysis" ;;
    proxy)     echo "Proxy & Reverse Proxy Security" ;;
    runtime)   echo "Live Instance Runtime State" ;;
    auth)      echo "Authentication Strength" ;;
    deps)      echo "Dependency Vulnerability Scan" ;;
    hostaudit) echo "Host Runtime Audit (SlowMist #3-6,8-9)" ;;
    dlp)       echo "DLP / Integrity Baseline / Backup" ;;
    *)         echo "Unknown Check" ;;
  esac
}

print_banner
init_score
run_checks
finalize_report
