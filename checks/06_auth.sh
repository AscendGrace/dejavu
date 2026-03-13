#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 6: 认证强度深度检查
# ============================================================

run_auth_checks() {
  set_current_module "auth"
  echo_info "Analyzing authentication strength..."

  local config_json
  config_json=$(read_openclaw_config)

  _check_auth_token_strength "$config_json"
  _check_auth_token_in_env
  _check_auth_weak_patterns "$config_json"
  _check_auth_rotation_policy
  _check_auth_rate_limiting "$config_json"
  _check_auth_control_ui "$config_json"
}

_check_auth_token_strength() {
  local check_id="A6.1"
  local cfg="$1"

  local token=""
  token=$(json_get "$cfg" "gateway.auth.token" 2>/dev/null || echo "")
  [[ -z "$token" || "$token" == "__UNDEFINED__" ]] && \
    token=$(json_get "$cfg" "gateway.token" 2>/dev/null || echo "")
  token="${token//\"/}"

  if [[ -z "$token" || "$token" == "__UNDEFINED__" ]]; then
    token="${OPENCLAW_AUTH_TOKEN:-${OPENCLAW_TOKEN:-}}"
  fi

  if [[ -z "$token" ]]; then
    echo_finding "HIGH" "$check_id" \
      "Cannot locate auth token — may be unset or passed only at runtime"
    record_finding "$check_id" "HIGH" \
      "Token not found in config" \
      "Ensure token is set and verify with: openclaw security audit"
    return
  fi

  local token_len="${#token}"
  if [[ $token_len -lt 32 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "Auth token is only ${token_len} chars — insufficient entropy (need ≥32)" \
      "Short tokens are vulnerable to brute force"
    record_finding "$check_id" "CRITICAL" \
      "Auth token too short" \
      "Generate: openssl rand -hex 32  (64-char token = 256-bit entropy)"
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}openssl rand -hex 32${RESET}"
  elif [[ $token_len -lt 40 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Auth token length: ${token_len} chars (acceptable but recommended ≥40)"
    record_finding "$check_id" "MEDIUM" \
      "Auth token length borderline" \
      "Increase to ≥40 chars for better security"
  else
    echo_finding "PASS" "$check_id" "Auth token length: ${token_len} chars ✓"
    record_finding "$check_id" "PASS" "Token length OK" ""
  fi

  if [[ $token_len -ge 32 ]]; then
    if echo "$token" | grep -qP '^[0-9a-fA-F]+$'; then
      echo_finding "PASS" "${check_id}.entropy" "Token appears to be high-entropy hex ✓"
      record_finding "${check_id}_entropy" "PASS" "Token entropy OK" ""
    else
      echo_finding "LOW" "${check_id}.entropy" \
        "Token is not pure hex — ensure it was generated cryptographically"
      record_finding "${check_id}_entropy" "LOW" \
        "Token may be low entropy" \
        "Regenerate with: openssl rand -hex 32"
    fi
  fi
}

_check_auth_token_in_env() {
  local check_id="A6.2"

  local raw_config_path="${OPENCLAW_CONFIG_PATH:-}"
  if [[ -z "$raw_config_path" ]]; then
    echo_skip "[${check_id}] Config path not resolved, skipping"
    return
  fi

  if grep -qP '"token"\s*:\s*"[0-9a-fA-F]{20,}"' "$raw_config_path" 2>/dev/null; then
    echo_finding "MEDIUM" "$check_id" \
      "Auth token appears to be hardcoded in openclaw.json" \
      "If this file is synced/shared, the token is exposed"
    record_finding "$check_id" "MEDIUM" \
      "Hardcoded token in config file" \
      "Use env var: export OPENCLAW_TOKEN=<token> and reference it in config"
  else
    echo_finding "PASS" "$check_id" "Token not found hardcoded in config file ✓"
    record_finding "$check_id" "PASS" "Token not hardcoded" ""
  fi
}

_check_auth_weak_patterns() {
  local check_id="A6.3"
  local cfg="$1"
  local token=""
  token=$(json_get "$cfg" "gateway.auth.token" 2>/dev/null || echo "")
  token="${token//\"/}"
  [[ -z "$token" || "$token" == "__UNDEFINED__" ]] && return

  local weak_patterns=(
    "^(admin|test|demo|dev|password|secret|openclaw|changeme|123456|abcdef)$"
    "^0{32,}$"
    "^1{32,}$"
    "^(.)\1{15,}$"
  )

  # Also check hostname
  local hostname_lc
  hostname_lc=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "")
  [[ -n "$hostname_lc" ]] && weak_patterns+=("^${hostname_lc}$")

  for pattern in "${weak_patterns[@]}"; do
    if [[ "$token" =~ $pattern ]]; then
      echo_finding "CRITICAL" "$check_id" \
        "Auth token matches a known-weak pattern!" \
        "Token appears predictable — matches: '${pattern}'"
      record_finding "$check_id" "CRITICAL" \
        "Weak/default auth token" \
        "Immediately rotate: openssl rand -hex 32"
      return
    fi
  done

  echo_finding "PASS" "$check_id" "Token does not match known weak patterns ✓"
  record_finding "$check_id" "PASS" "Token not weak" ""
}

_check_auth_rotation_policy() {
  local check_id="A6.4"
  local rotation_found=false

  crontab -l 2>/dev/null | grep -qi "openclaw.*token\|rotate.*token" && rotation_found=true
  [[ -f "/etc/cron.d/openclaw" ]] && rotation_found=true

  if find "$OPENCLAW_DIR" -maxdepth 3 \
       \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | \
     xargs grep -ql "rotate.*token\|token.*rotate" 2>/dev/null; then
    rotation_found=true
  fi

  if [[ "$rotation_found" == "false" ]]; then
    echo_finding "LOW" "$check_id" \
      "No token rotation policy detected" \
      "Long-lived static tokens increase exposure window"
    record_finding "$check_id" "LOW" \
      "No token rotation" \
      "Set up periodic token rotation (monthly recommended)"
  else
    echo_finding "PASS" "$check_id" "Token rotation policy detected ✓"
    record_finding "$check_id" "PASS" "Token rotation OK" ""
  fi
}

_check_auth_rate_limiting() {
  local check_id="A6.5"
  local cfg="$1"

  local rate_limit
  rate_limit=$(json_get "$cfg" "gateway.rateLimit" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$rate_limit" == "__UNDEFINED__" || "$rate_limit" == "false" || -z "$rate_limit" ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "No rate limiting configured on gateway" \
      "Without rate limiting, auth tokens are vulnerable to brute force"
    record_finding "$check_id" "MEDIUM" \
      "No rate limiting" \
      "Enable rateLimit in gateway config or use nginx rate limiting upstream"
  else
    echo_finding "PASS" "$check_id" "Rate limiting is configured ✓"
    record_finding "$check_id" "PASS" "Rate limiting OK" ""
  fi
}

_check_auth_control_ui() {
  local check_id="A6.6"
  local cfg="$1"

  local ui_auth
  ui_auth=$(json_get "$cfg" "controlUI.auth" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$ui_auth" == "__UNDEFINED__" ]]; then
    echo_finding "LOW" "$check_id" \
      "Control UI has no dedicated auth config — inherits gateway auth only" \
      "Consider adding a separate Control UI access restriction"
    record_finding "$check_id" "LOW" \
      "Control UI uses gateway auth only" \
      "Add controlUI.allowedIPs or separate password for additional protection"
  else
    echo_finding "PASS" "$check_id" "Control UI has dedicated auth configuration ✓"
    record_finding "$check_id" "PASS" "Control UI auth OK" ""
  fi
}
