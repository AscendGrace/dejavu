#!/usr/bin/env bash
# ============================================================
#  lib/color.sh — Terminal color / output helpers
# ============================================================

# ANSI escape codes — 使用 $'...' 语法存储真正的 ESC 字符（\033），
# 从而在 cat heredoc / printf / echo 等任意上下文中都能正确渲染颜色，
# 而不是输出字面字符串 \033[1m。
export RED=$'\033[0;31m'
export GREEN=$'\033[0;32m'
export YELLOW=$'\033[1;33m'
export BLUE=$'\033[0;34m'
export CYAN=$'\033[0;36m'
export GRAY=$'\033[0;90m'
export BOLD=$'\033[1m'
export RESET=$'\033[0m'

# Section header
echo_section() {
  echo ""
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${CYAN}${BOLD}  $*${RESET}"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# Status output helpers
echo_info()  { echo -e "${BLUE}  [INFO]${RESET} $*"; }
echo_warn()  { echo -e "${YELLOW}  [WARN]${RESET} $*"; }
echo_error() { echo -e "${RED}  [ERROR]${RESET} $*" >&2; }
echo_skip()  { echo -e "${GRAY}  [SKIP]${RESET} $*"; }
echo_pass()  { echo -e "${GREEN}  [PASS]${RESET} $*"; }

# Finding printer: echo_finding <SEVERITY> <CHECK_ID> <DESCRIPTION> [detail]
echo_finding() {
  local severity="$1" check_id="$2" description="$3" detail="${4:-}"
  local icon color

  case "$severity" in
    CRITICAL) icon="[CRIT]"; color="${RED}${BOLD}" ;;
    HIGH)     icon="[HIGH]"; color="${RED}" ;;
    MEDIUM)   icon="[MEDI]"; color="${YELLOW}" ;;
    LOW)      icon="[LOW] "; color="${BLUE}" ;;
    PASS)     icon="[PASS]"; color="${GREEN}" ;;
    SKIP)     icon="[SKIP]"; color="${GRAY}" ;;
    INFO)     icon="[INFO]"; color="${CYAN}" ;;
    *)        icon="[????]"; color="${RESET}" ;;
  esac

  echo -e "  ${color}${icon}${RESET} ${BOLD}[${check_id}]${RESET} ${description}"
  if [[ -n "$detail" && "${VERBOSE:-false}" == "true" ]]; then
    echo -e "         ${GRAY}↳ ${detail}${RESET}"
  fi
}

# section_header is an alias for echo_section (used in sourced modules)
section_header() { echo_section "$@"; }

# finding is an alias for echo_finding (used in sourced modules)
finding() { echo_finding "$@"; }

# log_info is an alias for echo_info
log_info() { echo_info "$@"; }
