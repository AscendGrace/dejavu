#!/usr/bin/env bash
# ============================================================
#  lib/score.sh — 分类维度评分引擎 v2
#  支持按模块独立评分 + 整体加权汇总
# ============================================================

# 模块权重（总和100）
# Bug Fix #35+#36: 补入 deps=10，与 dejavu.ps1 保持一致；调整 hostaudit=3/dlp=2
declare -gA MODULE_WEIGHTS=(
  [config]=15
  [skills]=20
  [network]=20
  [proxy]=15
  [runtime]=10
  [auth]=5
  [deps]=10
  [hostaudit]=3
  [dlp]=2
)

# 各模块扣分累计
declare -gA MODULE_DEDUCTIONS=(
  [config]=0 [skills]=0 [network]=0
  [proxy]=0  [runtime]=0 [auth]=0 [deps]=0
  [hostaudit]=0 [dlp]=0
)
declare -g CURRENT_MODULE="unknown"

declare -g TOTAL_CHECKS=0
declare -g PASSED_CHECKS=0
declare -gA FINDINGS=()

init_score() {
  TOTAL_CHECKS=0
  PASSED_CHECKS=0
  FINDINGS=()
  for m in config skills network proxy runtime auth deps hostaudit dlp; do
    MODULE_DEDUCTIONS[$m]=0
  done
}

set_current_module() { CURRENT_MODULE="$1"; }

record_finding() {
  local check_id="$1" severity="$2" description="$3" remediation="${4:-N/A}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FINDINGS["${check_id}"]="${severity}|${description}|${remediation}|${CURRENT_MODULE}"

  if [[ "$severity" == "PASS" ]]; then
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
  else
    local weight=0
    case "$severity" in
      CRITICAL) weight=10 ;;
      HIGH)     weight=5  ;;
      MEDIUM)   weight=2  ;;
      LOW)      weight=1  ;;
    esac
    MODULE_DEDUCTIONS[$CURRENT_MODULE]=$(( ${MODULE_DEDUCTIONS[$CURRENT_MODULE]:-0} + weight ))
  fi
}

# 计算单模块分数（满分100）
get_module_score() {
  local module="$1"
  local deduction="${MODULE_DEDUCTIONS[$module]:-0}"
  local score=$((100 - deduction * 3))
  [[ $score -lt 0 ]] && score=0
  echo "$score"
}

# 计算整体加权分数
# Bug Fix #35: 补入 deps 模块，使其扣分纳入总分计算
get_score() {
  local total=0
  for module in config skills network proxy runtime auth deps hostaudit dlp; do
    local ms weight
    ms=$(get_module_score "$module")
    weight="${MODULE_WEIGHTS[$module]:-0}"
    total=$(( total + ms * weight ))
  done
  echo $(( total / 100 ))
}

get_risk_level() {
  local s; s=$(get_score)
  if   [[ $s -ge 90 ]]; then echo "LOW RISK"
  elif [[ $s -ge 70 ]]; then echo "MEDIUM RISK"
  elif [[ $s -ge 50 ]]; then echo "HIGH RISK"
  else                        echo "CRITICAL RISK"
  fi
}

get_risk_color() {
  local s; s=$(get_score)
  if   [[ $s -ge 90 ]]; then echo "$GREEN"
  elif [[ $s -ge 70 ]]; then echo "$YELLOW"
  elif [[ $s -ge 50 ]]; then echo "$RED"
  else                        echo "${RED}${BOLD}"
  fi
}

# 生成彩色评分条
render_score_bar() {
  local score="$1" width=20
  local filled=$(( score * width / 100 ))
  local empty=$(( width - filled ))
  local bar=""
  for ((i=0; i<filled; i++)); do bar+="█"; done
  for ((i=0; i<empty;  i++)); do bar+="░"; done
  echo "$bar"
}
