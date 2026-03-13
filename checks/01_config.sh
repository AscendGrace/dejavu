#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 1: 配置文件安全基线检查
#  C1.1-C1.7: 文件存在性、内容安全、权限、Schema 校验
# ============================================================

run_config_checks() {
  set_current_module "config"
  echo_info "Checking configuration file security..."

  local config_json
  config_json=$(read_openclaw_config)

  _check_config_exists
  _check_config_parseable "$config_json"
  _check_config_hardcoded_secrets
  _check_config_soul_injection
  _check_config_file_permissions
  _check_config_dangerous_flags "$config_json"
  _check_config_agents_md
}

# C1.1 openclaw.json 存在且可读
_check_config_exists() {
  local check_id="C1.1"
  local config_path="${OPENCLAW_CONFIG_PATH:-}"

  # Bug Fix #41: 移除 $HOME/.openclaw 回退路径，避免扫描器静默切换至用户主目录配置
  # （与 openclaw_cli.sh Bug #37 / dejavu.ps1 Bug #6 保持一致）
  local candidates=(
    "${OPENCLAW_DIR}/openclaw.json"
    "${OPENCLAW_DIR}/config/openclaw.json"
  )

  local found_path=""
  for p in "${candidates[@]}"; do
    [[ -f "$p" ]] && found_path="$p" && break
  done

  if [[ -z "$found_path" ]]; then
    echo_finding "HIGH" "$check_id" \
      "openclaw.json not found in expected locations" \
      "Searched: ${OPENCLAW_DIR}/openclaw.json and ${OPENCLAW_DIR}/config/openclaw.json"
    record_finding "$check_id" "HIGH" \
      "openclaw.json missing" \
      "Run 'openclaw init' to create default config, or check OPENCLAW_DIR path"
  else
    export OPENCLAW_CONFIG_PATH="$found_path"
    echo_finding "PASS" "$check_id" "openclaw.json found: ${found_path} ✓"
    record_finding "$check_id" "PASS" "Config file exists" ""
  fi
}

# C1.2 配置文件可解析（JSON 有效）
_check_config_parseable() {
  local check_id="C1.2"
  local cfg="$1"

  if echo "$cfg" | grep -q '"parseError"\|"error"'; then
    local err
    err=$(echo "$cfg" | grep -oP '"parseError":\s*"\K[^"]+' | head -1 || echo "unknown parse error")
    echo_finding "HIGH" "$check_id" \
      "openclaw.json has parse errors: ${err}" \
      "Config file is malformed — some settings may be silently ignored"
    record_finding "$check_id" "HIGH" \
      "openclaw.json parse error" \
      "Fix JSON syntax errors in openclaw.json (check for trailing commas, unquoted keys)"
  else
    echo_finding "PASS" "$check_id" "openclaw.json parses successfully ✓"
    record_finding "$check_id" "PASS" "Config parseable" ""
  fi
}

# C1.3 硬编码凭证检测
_check_config_hardcoded_secrets() {
  local check_id="C1.3"

  local secret_patterns=(
    'sk-[a-zA-Z0-9]{20,}'
    'sk-ant-[a-zA-Z0-9\-]{20,}'
    'sk-proj-[a-zA-Z0-9\-]{20,}'
    'AIza[0-9A-Za-z\-_]{35}'
    'ghp_[a-zA-Z0-9]{36}'
    'ghs_[a-zA-Z0-9]{36}'
    'Bearer [a-zA-Z0-9\-_\.]{40,}'
    'AKIA[0-9A-Z]{16}'
  )

  local check_files=()
  mapfile -t check_files < <(find "$OPENCLAW_DIR" \
    \( -name "*.json" -o -name "*.md" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" \
    -maxdepth 4 2>/dev/null)

  local found_secrets=0
  for f in "${check_files[@]}"; do
    [[ ! -f "$f" ]] && continue
    local content
    content=$(cat "$f" 2>/dev/null || continue)
    for pattern in "${secret_patterns[@]}"; do
      if echo "$content" | grep -qP "$pattern"; then
        echo_finding "CRITICAL" "$check_id" \
          "Possible API key/secret in: ${f#$OPENCLAW_DIR/}" \
          "Pattern: ${pattern:0:30}..."
        record_finding "${check_id}_${found_secrets}" "CRITICAL" \
          "Hardcoded secret in ${f##*/}" \
          "Move to environment variable or secrets manager"
        found_secrets=$((found_secrets + 1))
        break
      fi
    done
  done

  if [[ $found_secrets -eq 0 ]]; then
    echo_finding "PASS" "$check_id" "No hardcoded API keys or secrets detected ✓"
    record_finding "$check_id" "PASS" "No hardcoded secrets" ""
  fi
}

# C1.4 SOUL.md 提示注入检测
_check_config_soul_injection() {
  local check_id="C1.4"

  local soul_files=()
  mapfile -t soul_files < <(find "$OPENCLAW_DIR" \
    -name "SOUL.md" -not -path "*/node_modules/*" \
    -maxdepth 5 2>/dev/null)

  if [[ ${#soul_files[@]} -eq 0 ]]; then
    echo_skip "[${check_id}] No SOUL.md found — skipping"
    return
  fi

  local danger_patterns=(
    'ignore.*previous.*instruction'
    'disregard.*safety'
    'you are now'
    'jailbreak'
    'DAN mode'
    'no restriction'
    'sudo mode'
    'bypass.*security'
    'admin.*privilege'
    'unrestricted access'
    'forget.*guidelines'
    'override.*policy'
  )

  local injection_found=false
  for soul_file in "${soul_files[@]}"; do
    local content
    content=$(cat "$soul_file" 2>/dev/null || continue)
    for pat in "${danger_patterns[@]}"; do
      if echo "$content" | grep -qiP "$pat"; then
        echo_finding "HIGH" "$check_id" \
          "Privilege escalation/injection pattern in: ${soul_file#$OPENCLAW_DIR/}" \
          "Matched pattern: '${pat}'"
        record_finding "$check_id" "HIGH" \
          "Prompt injection in SOUL.md" \
          "Remove instructions attempting to bypass agent safety constraints"
        injection_found=true
        break 2
      fi
    done
  done

  if [[ "$injection_found" == "false" ]]; then
    echo_finding "PASS" "$check_id" "SOUL.md has no privilege escalation patterns ✓"
    record_finding "$check_id" "PASS" "SOUL.md clean" ""
  fi
}

# C1.5 配置文件权限检查（仅 Unix）
_check_config_file_permissions() {
  local check_id="C1.5"

  # 在 Windows/WSL 环境下可能不适用
  if ! command -v stat &>/dev/null; then
    echo_skip "[${check_id}] stat not available — skipping permission check"
    return
  fi

  # Bug Fix #46: 移除 $HOME/.openclaw 回退路径（与 C1.1 Bug #41 / A6.2 保持一致）
  local cfg_path="${OPENCLAW_CONFIG_PATH:-}"
  if [[ -z "$cfg_path" || ! -f "$cfg_path" ]]; then
    echo_skip "[${check_id}] Config path not resolved — skipping permission check"
    return
  fi

  local perms
  perms=$(stat -c "%a" "$cfg_path" 2>/dev/null || stat -f "%OLp" "$cfg_path" 2>/dev/null || echo "")

  if [[ -z "$perms" ]]; then
    echo_skip "[${check_id}] Cannot determine file permissions"
    return
  fi

  # 检查是否对 group/other 可读
  if [[ "${perms: -1}" != "0" || "${perms: -2:1}" != "0" ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "openclaw.json permissions: ${perms} — readable by group/others" \
      "Token and API keys may be accessible by other system users"
    record_finding "$check_id" "MEDIUM" \
      "Insecure config file permissions: ${perms}" \
      "Run: chmod 600 ${cfg_path}"
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      chmod 600 "$cfg_path" && echo_info "Fixed: chmod 600 ${cfg_path}"
  else
    echo_finding "PASS" "$check_id" "openclaw.json permissions: ${perms} (owner-only) ✓"
    record_finding "$check_id" "PASS" "Config file permissions OK" ""
  fi

  # 检查 world-writable 的配置文件
  local ww_files
  ww_files=$(find "$OPENCLAW_DIR" -maxdepth 3 \
    \( -name "*.json" -o -name "*.md" \) \
    -perm -o+w ! -path "*/node_modules/*" 2>/dev/null)

  if [[ -n "$ww_files" ]]; then
    echo_finding "MEDIUM" "${check_id}a" \
      "World-writable config/agent files detected:" \
      "$(echo "$ww_files" | head -5 | sed 's|'"$OPENCLAW_DIR"'/||')"
    record_finding "${check_id}a" "MEDIUM" \
      "World-writable config files" \
      "Run: find ${OPENCLAW_DIR} -name '*.md' -perm -o+w -exec chmod o-w {} \\;"
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      find "$OPENCLAW_DIR" -name "*.md" -perm -o+w -exec chmod o-w {} \;
  fi
}

# C1.6 危险配置标志检测
_check_config_dangerous_flags() {
  local check_id="C1.6"
  local cfg="$1"

  local dangerous_flags=(
    "allowAll"
    "disableSafety"
    "skipVerification"
    "bypassAuth"
    "devMode"
    "insecure"
    "allowUnsafe"
  )

  local flag_found=false
  for flag in "${dangerous_flags[@]}"; do
    if echo "$cfg" | grep -qiP "\"${flag}\"\s*:\s*true"; then
      echo_finding "HIGH" "$check_id" \
        "Dangerous flag enabled: ${flag}=true" \
        "This flag may disable security controls"
      record_finding "${check_id}_${flag}" "HIGH" \
        "Dangerous flag: ${flag}=true" \
        "Set ${flag} to false or remove from config"
      flag_found=true
    fi
  done

  if [[ "$flag_found" == "false" ]]; then
    echo_finding "PASS" "$check_id" "No dangerous configuration flags detected ✓"
    record_finding "$check_id" "PASS" "No dangerous flags" ""
  fi
}

# C1.7 AGENTS.md 安全审查
_check_config_agents_md() {
  local check_id="C1.7"

  local agents_files=()
  mapfile -t agents_files < <(find "$OPENCLAW_DIR" -name "AGENTS.md" \
    ! -path "*/node_modules/*" -maxdepth 5 2>/dev/null)

  if [[ ${#agents_files[@]} -eq 0 ]]; then
    echo_skip "[${check_id}] No AGENTS.md found — skipping"
    return
  fi

  local high_risk_patterns=(
    'run.*as.*root'
    'sudo\s'
    'chmod\s+777'
    'curl.*\|\s*bash'
    'wget.*\|\s*sh'
    'rm\s+-rf'
    'disable.*firewall'
    'iptables.*-F'
  )

  local risk_found=false
  for agents_file in "${agents_files[@]}"; do
    local content
    content=$(cat "$agents_file" 2>/dev/null || continue)
    for pat in "${high_risk_patterns[@]}"; do
      if echo "$content" | grep -qiP "$pat"; then
        echo_finding "HIGH" "$check_id" \
          "High-risk instruction in AGENTS.md: '${pat}'" \
          "File: ${agents_file#$OPENCLAW_DIR/}"
        record_finding "$check_id" "HIGH" \
          "Dangerous agent instruction in AGENTS.md" \
          "Review and remove high-risk shell commands from AGENTS.md"
        risk_found=true
        break 2
      fi
    done
  done

  if [[ "$risk_found" == "false" ]]; then
    echo_finding "PASS" "$check_id" "AGENTS.md has no high-risk instructions ✓"
    record_finding "$check_id" "PASS" "AGENTS.md clean" ""
  fi
}
