#!/usr/bin/env bash
# ============================================================
#  lib/report.sh — 增强版报告引擎（分类维度评分 + 多格式输出）
# ============================================================

finalize_report() {
  local score
  score=$(get_score)
  local risk_level
  risk_level=$(get_risk_level)
  local risk_color
  risk_color=$(get_risk_color)

  # ---- 分类统计 ----
  local crit=0 high=0 med=0 low=0
  for key in "${!FINDINGS[@]}"; do
    IFS='|' read -ra parts <<< "${FINDINGS[$key]}"
    case "${parts[0]}" in
      CRITICAL) crit=$((crit+1)) ;;
      HIGH)     high=$((high+1)) ;;
      MEDIUM)   med=$((med+1))   ;;
      LOW)      low=$((low+1))   ;;
    esac
  done

  echo ""
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${CYAN}${BOLD}  SECURITY BASELINE REPORT SUMMARY${RESET}"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  printf "  %-14s %s\n"   "Project:"    "${BOLD}${OPENCLAW_DIR}${RESET}"
  printf "  %-14s %s\n"   "Scan Time:"  "$(date +"%Y-%m-%d %H:%M:%S %Z")"
  printf "  %-14s %s\n"   "Tool:"       "Dejavu v2.0.0"
  printf "  %-14s ${BOLD}%s${RESET}\n"  "Total Checks:" "${TOTAL_CHECKS}"
  printf "  %-14s ${GREEN}${BOLD}%s${RESET}\n" "Passed:"  "${PASSED_CHECKS}"
  printf "  %-14s ${RED}${BOLD}%s${RESET}\n"   "Issues:"  "$((TOTAL_CHECKS - PASSED_CHECKS))"
  echo ""

  local bar
  bar=$(render_score_bar "$score")
  echo -e "  Overall Score:  ${risk_color}${BOLD}${score}/100${RESET}  ${risk_color}[${bar}]${RESET}"
  echo -e "  Risk Level:     ${risk_color}${BOLD}${risk_level}${RESET}"
  echo ""

  echo -e "  ${BOLD}Module Scores:${RESET}"
  echo -e "  ${GRAY}──────────────────────────────────────────────────${RESET}"
  local modules=(config skills network proxy runtime auth deps hostaudit dlp)
  for module in "${modules[@]}"; do
    local ms
    ms=$(get_module_score "$module")
    local mbar
    mbar=$(render_score_bar "$ms")
    local mcolor
    if   [[ $ms -ge 90 ]]; then mcolor="$GREEN"
    elif [[ $ms -ge 70 ]]; then mcolor="$YELLOW"
    elif [[ $ms -ge 50 ]]; then mcolor="$RED"
    else                        mcolor="${RED}${BOLD}"
    fi
    printf "  %-12s ${mcolor}%3d/100${RESET}  ${mcolor}[%s]${RESET}\n" \
      "${module^}" "$ms" "$mbar"
  done
  echo ""

  echo -e "  ${RED}${BOLD}  CRITICAL: ${crit}${RESET}"
  echo -e "  ${RED}      HIGH: ${high}${RESET}"
  echo -e "  ${YELLOW}    MEDIUM: ${med}${RESET}"
  echo -e "  ${BLUE}       LOW: ${low}${RESET}"
  echo ""

  case "$OUTPUT_FORMAT" in
    markdown) _generate_markdown_report ;;
    json)     _generate_json_report     ;;
    terminal) _generate_markdown_report ;;
  esac

  if [[ -f "$REPORT_FILE" ]]; then
    echo_info "Report saved: ${BOLD}${REPORT_FILE}${RESET}"
  fi

  # Bug Fix #40: 退出码与 dejavu.ps1 对齐：CRITICAL=3 / HIGH=2 / MEDIUM=1 / clean=0
  # 原始框架口: exit 2=CRIT / exit 1=HIGH / exit 0=其余，MEDIUM 被静默当成通过
  [[ $crit -gt 0 ]] && exit 3
  [[ $high -gt 0 ]] && exit 2
  [[ $med  -gt 0 ]] && exit 1
  exit 0
}

_generate_markdown_report() {
  local score
  score=$(get_score)
  local risk_level
  risk_level=$(get_risk_level)

  local module_table=""
  for module in config skills network proxy runtime auth deps hostaudit dlp; do
    local ms
    ms=$(get_module_score "$module")
    local risk_icon
    if   [[ $ms -ge 90 ]]; then risk_icon="🟢"
    elif [[ $ms -ge 70 ]]; then risk_icon="🟡"
    elif [[ $ms -ge 50 ]]; then risk_icon="🟠"
    else                        risk_icon="🔴"
    fi
    module_table+="| ${module^} | ${ms}/100 | ${risk_icon} |\n"
  done

  mkdir -p "$(dirname "$REPORT_FILE")"
  cat > "$REPORT_FILE" <<MDEOF
# Dejavu Security Baseline Report

| Field | Value |
|-------|-------|
| **Project** | \`${OPENCLAW_DIR}\` |
| **Scan Date** | $(date) |
| **Tool Version** | Dejavu v2.0.0 |
| **Overall Score** | **${score}/100** |
| **Risk Level** | **${risk_level}** |

---

## Module Scores

| Module | Score | Risk |
|--------|-------|------|
$(printf "%b" "$module_table")

---

## Findings

MDEOF

  for severity in CRITICAL HIGH MEDIUM LOW PASS; do
    local section_header=false
    for key in "${!FINDINGS[@]}"; do
      IFS='|' read -ra parts <<< "${FINDINGS[$key]}"
      [[ "${parts[0]}" != "$severity" ]] && continue

      if [[ "$section_header" == "false" ]]; then
        local icon
        case "$severity" in
          CRITICAL) icon="🔴" ;;
          HIGH)     icon="🟠" ;;
          MEDIUM)   icon="🟡" ;;
          LOW)      icon="🔵" ;;
          PASS)     icon="✅" ;;
        esac
        echo "### ${icon} ${severity}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "| Check ID | Module | Description | Remediation |" >> "$REPORT_FILE"
        echo "|----------|--------|-------------|-------------|" >> "$REPORT_FILE"
        section_header=true
      fi
      echo "| \`${key}\` | ${parts[3]:-—} | ${parts[1]} | ${parts[2]} |" >> "$REPORT_FILE"
    done
    [[ "$section_header" == "true" ]] && echo "" >> "$REPORT_FILE"
  done

  cat >> "$REPORT_FILE" <<MDEOF
---

## Remediation Priority

| Priority | Action | Timeframe |
|----------|--------|-----------|
| P1 | Fix all CRITICAL findings (auth, exposed ports, hardcoded secrets, toxic skills) | **Immediately** |
| P2 | Address HIGH findings (SOUL.md injection, supply chain, SSRF, weak token) | **Within 24h** |
| P3 | Resolve MEDIUM findings (TLS, CORS, version pinning, rate limiting) | **This Sprint** |
| P4 | LOW findings (VPN, session TTL, token rotation) | **Backlog** |

---

## Quick Fix Commands

\`\`\`bash
# Rotate auth token (run immediately if CRITICAL auth findings)
openssl rand -hex 32

# Fix world-writable config files
find ${OPENCLAW_DIR} -name "*.md" -perm -o+w -exec chmod o-w {} \\;

# Fix npm vulnerabilities
cd ${OPENCLAW_DIR} && npm audit fix
\`\`\`

---

*Generated by Dejavu v2.0.0 — $(date)*
*Scan duration: ${SECONDS}s*
MDEOF
}

_generate_json_report() {
  local score
  score=$(get_score)

  local json_findings="{"
  local first=true
  for key in "${!FINDINGS[@]}"; do
    IFS='|' read -ra parts <<< "${FINDINGS[$key]}"
    [[ "$first" == "false" ]] && json_findings+=","
    local desc="${parts[1]//\"/\\\"}"
    local rem="${parts[2]//\"/\\\"}"
    json_findings+=$(printf '"%s":{"severity":"%s","description":"%s","remediation":"%s","module":"%s"}' \
      "$key" "${parts[0]}" "$desc" "$rem" "${parts[3]:-unknown}")
    first=false
  done
  json_findings+="}"

  # Bug Fix #45: 补入 hostaudit 和 dlp，与 get_score() 的 9 模块保持一致
  local module_scores="{"
  local mfirst=true
  for module in config skills network proxy runtime auth deps hostaudit dlp; do
    local ms; ms=$(get_module_score "$module")
    [[ "$mfirst" == "false" ]] && module_scores+=","
    module_scores+="\"${module}\":${ms}"
    mfirst=false
  done
  module_scores+="}"

  # Fix filename duplication: only append .json if no extension is provided
  local json_report_file
  if [[ "$REPORT_FILE" == *.* ]]; then
    # User provided extension, use as-is but ensure it's .json
    json_report_file="${REPORT_FILE%.*}.json"
  else
    # No extension provided, add .json
    json_report_file="${REPORT_FILE}.json"
  fi

  mkdir -p "$(dirname "$json_report_file")"

  # Use jq for pretty formatting if available, otherwise use basic formatting
  if command -v jq &>/dev/null; then
    # Create formatted JSON using jq
    jq -n \
      --arg version "2.0.0" \
      --arg scan_date "$(date -Iseconds 2>/dev/null || date)" \
      --arg project "$OPENCLAW_DIR" \
      --argjson score "$score" \
      --arg risk_level "$(get_risk_level)" \
      --argjson total_checks "$TOTAL_CHECKS" \
      --argjson passed "$PASSED_CHECKS" \
      --argjson module_scores "$module_scores" \
      --argjson findings "$json_findings" \
      '{
        "dejavu_version": $version,
        "scan_date": $scan_date,
        "project": $project,
        "overall_score": $score,
        "risk_level": $risk_level,
        "total_checks": $total_checks,
        "passed": $passed,
        "module_scores": $module_scores,
        "findings": $findings
      }' > "$json_report_file"
  else
    # Fallback to basic formatting without jq
    cat > "$json_report_file" <<JSONEOF
{
  "dejavu_version": "2.0.0",
  "scan_date": "$(date -Iseconds 2>/dev/null || date)",
  "project": "${OPENCLAW_DIR}",
  "overall_score": ${score},
  "risk_level": "$(get_risk_level)",
  "total_checks": ${TOTAL_CHECKS},
  "passed": ${PASSED_CHECKS},
  "module_scores": ${module_scores},
  "findings": ${json_findings}
}
JSONEOF
  fi
}
