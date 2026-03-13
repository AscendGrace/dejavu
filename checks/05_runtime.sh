#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 5: 运行时实例状态检查
#  直连本地运行的 openclaw 实例，检查真实配置
# ============================================================

run_runtime_checks() {
  set_current_module "runtime"
  echo_info "Connecting to local OpenClaw instance..."

  local config_json
  config_json=$(read_openclaw_config)

  if echo "$config_json" | grep -q '"error"'; then
    echo_warn "openclaw.json not found or unreadable — skipping runtime module"
    echo_skip "[R5.x] Runtime checks require openclaw.json to be accessible"
    return
  fi

  _check_runtime_auth_mode        "$config_json"
  _check_runtime_bind_interface   "$config_json"
  _check_runtime_deny_commands    "$config_json"
  _check_runtime_trusted_proxies  "$config_json"
  _check_runtime_auth_profiles    "$config_json"
  _check_runtime_paired_devices
  _check_runtime_memory_plugins   "$config_json"
  _check_runtime_session_ttl      "$config_json"
  _check_runtime_cli_audit
}

_check_runtime_auth_mode() {
  local check_id="R5.1"
  local cfg="$1"
  local auth_mode
  auth_mode=$(json_get "$cfg" "gateway.auth.mode" 2>/dev/null || echo "")
  auth_mode="${auth_mode//\"/}"

  case "$auth_mode" in
    "none"|"")
      echo_finding "CRITICAL" "$check_id" \
        "gateway.auth.mode is '${auth_mode:-unset}' — instance has NO authentication" \
        "Any process with network access can control this OpenClaw instance"
      record_finding "$check_id" "CRITICAL" \
        "Auth mode=none: unauthenticated access to gateway" \
        "Set gateway.auth.mode to 'token' or 'password' in openclaw.json"
      [[ "${FIX_MODE:-false}" == "true" ]] && \
        echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}openclaw.json → \"auth\": {\"mode\": \"token\"}${RESET}"
      ;;
    "token"|"password"|"trusted-proxy")
      echo_finding "PASS" "$check_id" "gateway.auth.mode = '${auth_mode}' ✓"
      record_finding "$check_id" "PASS" "Auth mode configured" ""
      ;;
    *)
      echo_finding "HIGH" "$check_id" \
        "Unrecognized auth mode: '${auth_mode}' — behavior is undefined"
      record_finding "$check_id" "HIGH" \
        "Unknown auth mode" \
        "Use one of: token / password / trusted-proxy"
      ;;
  esac
}

_check_runtime_bind_interface() {
  local check_id="R5.2"
  local cfg="$1"
  local bind_val
  bind_val=$(json_get "$cfg" "gateway.bind" 2>/dev/null || echo "")
  bind_val="${bind_val//\"/}"

  case "$bind_val" in
    "loopback"|"localhost"|"127.0.0.1")
      echo_finding "PASS" "$check_id" "gateway.bind = '${bind_val}' — restricted to loopback ✓"
      record_finding "$check_id" "PASS" "Bind=loopback" ""
      ;;
    "lan"|"all"|"0.0.0.0"|"")
      echo_finding "CRITICAL" "$check_id" \
        "gateway.bind = '${bind_val:-unset/default}' — EXPOSED TO LOCAL NETWORK OR INTERNET" \
        "Ports 18789/18791 may be reachable by other hosts"
      record_finding "$check_id" "CRITICAL" \
        "Gateway bound to all interfaces" \
        'Set "bind": "loopback" in openclaw.json gateway config'
      [[ "${FIX_MODE:-false}" == "true" ]] && \
        echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}openclaw.json → \"gateway\": {\"bind\": \"loopback\"}${RESET}"
      ;;
    *)
      echo_finding "MEDIUM" "$check_id" \
        "gateway.bind = '${bind_val}' — non-standard value, verify manually"
      record_finding "$check_id" "MEDIUM" \
        "Non-standard bind value" \
        "Explicitly set to 'loopback' unless LAN access is intentional and secured"
      ;;
  esac
}

_check_runtime_deny_commands() {
  local check_id="R5.3"
  local cfg="$1"
  local deny_cmds
  deny_cmds=$(json_get "$cfg" "gateway.nodes.denyCommands" 2>/dev/null || echo "")

  if [[ "$deny_cmds" == "__UNDEFINED__" || "$deny_cmds" == "[]" || -z "$deny_cmds" ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "gateway.nodes.denyCommands is empty — no shell commands are blocked" \
      "Agent can execute arbitrary commands via node tools"
    record_finding "$check_id" "MEDIUM" \
      "denyCommands not configured" \
      "Add high-risk commands to denyCommands: rm, dd, mkfs, format, fdisk, shred"
    return
  fi

  # 检查高危命令是否在拒绝列表中
  local critical_cmds=("rm" "dd" "mkfs" "format" "fdisk" "shred" "shutdown" "reboot")
  local missing_cmds=()
  for cmd in "${critical_cmds[@]}"; do
    if ! echo "$deny_cmds" | grep -q "\"${cmd}\""; then
      missing_cmds+=("$cmd")
    fi
  done

  echo_finding "LOW" "$check_id" \
    "⚠ denyCommands uses exact command-name matching — NOT shell content filtering" \
    "Commands like 'bash -c \"rm -rf /\"' will NOT be blocked"
  record_finding "${check_id}_warn" "LOW" \
    "denyCommands limitation: exact match only" \
    "Supplement with OS-level sandboxing (seccomp/AppArmor) for comprehensive protection"

  if [[ ${#missing_cmds[@]} -gt 0 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "High-risk commands missing from denyCommands: ${missing_cmds[*]}"
    record_finding "$check_id" "MEDIUM" \
      "Missing high-risk commands in denyCommands" \
      "Add to denyCommands: ${missing_cmds[*]}"
  else
    echo_finding "PASS" "$check_id" "Core high-risk commands present in denyCommands ✓"
    record_finding "$check_id" "PASS" "denyCommands OK" ""
  fi
}

_check_runtime_trusted_proxies() {
  local check_id="R5.4"
  local cfg="$1"
  local proxies
  proxies=$(json_get "$cfg" "gateway.trustedProxies" 2>/dev/null || echo "")

  if [[ "$proxies" == "__UNDEFINED__" || "$proxies" == "[]" || -z "$proxies" ]]; then
    echo_finding "LOW" "$check_id" \
      "trustedProxies not configured — safe only if NOT behind a reverse proxy" \
      "If using nginx/Caddy, configure trustedProxies to prevent IP spoofing"
    record_finding "$check_id" "LOW" \
      "trustedProxies empty" \
      "Set trustedProxies to your reverse proxy IP if applicable"
    return
  fi

  if echo "$proxies" | grep -qP '"(\*|all|0\.0\.0\.0)"'; then
    echo_finding "HIGH" "$check_id" \
      "trustedProxies contains wildcard '*' or '0.0.0.0' — X-Forwarded-For can be spoofed" \
      "Attackers can forge IP addresses, bypassing IP-based access controls"
    record_finding "$check_id" "HIGH" \
      "trustedProxies wildcard allows IP spoofing" \
      "Restrict trustedProxies to specific proxy IPs, e.g. [\"127.0.0.1\"]"
  else
    echo_finding "PASS" "$check_id" "trustedProxies configured with specific IPs ✓"
    record_finding "$check_id" "PASS" "trustedProxies OK" ""
  fi
}

_check_runtime_auth_profiles() {
  local check_id="R5.5"
  local candidates=(
    "${OPENCLAW_DIR}/agents/main/agent/auth-profiles.json"
    "$HOME/.openclaw/auth-profiles.json"
    "${OPENCLAW_DIR}/auth-profiles.json"
  )

  local found_path=""
  for p in "${candidates[@]}"; do
    [[ -f "$p" ]] && found_path="$p" && break
  done

  if [[ -z "$found_path" ]]; then
    echo_skip "[${check_id}] auth-profiles.json not found, skipping"
    return
  fi

  local profiles_json
  profiles_json=$(cat "$found_path" 2>/dev/null || echo "{}")

  if echo "$profiles_json" | grep -qiP '"(admin|superuser|root)"'; then
    if ! echo "$profiles_json" | grep -qP '"allowedIPs?"\s*:'; then
      echo_finding "HIGH" "$check_id" \
        "Admin auth-profile found without IP restriction in: ${found_path#$HOME/}"
      record_finding "$check_id" "HIGH" \
        "Admin profile without IP allowlist" \
        "Add 'allowedIPs' restriction to admin auth profiles"
    else
      echo_finding "PASS" "$check_id" "Admin auth-profile has IP restriction ✓"
      record_finding "$check_id" "PASS" "Auth profiles OK" ""
    fi
  else
    echo_finding "PASS" "$check_id" "No unrestricted admin auth-profiles found"
    record_finding "$check_id" "PASS" "Auth profiles OK" ""
  fi
}

_check_runtime_paired_devices() {
  local check_id="R5.6"
  local paired_path="${OPENCLAW_DIR}/devices/paired.json"
  [[ ! -f "$paired_path" ]] && paired_path="$HOME/.openclaw/devices/paired.json"

  if [[ ! -f "$paired_path" ]]; then
    echo_skip "[${check_id}] No paired devices file found"
    return
  fi

  local device_count
  device_count=$(grep -c '"id"' "$paired_path" 2>/dev/null || echo "0")
  echo_info "[${check_id}] Found ${device_count} paired device(s) — please verify manually"

  if command -v node &>/dev/null; then
    node -e "
      const d = require('$paired_path');
      const devices = Array.isArray(d) ? d : Object.values(d);
      devices.forEach(dev => {
        console.log('  Device: ' + (dev.name||'unknown') +
                    ' | Added: ' + (dev.pairedAt||'unknown') +
                    ' | ID: ' + (dev.id||'unknown'));
      });
    " 2>/dev/null || cat "$paired_path" | head -20
  fi

  echo_finding "LOW" "$check_id" \
    "Review ${device_count} paired device(s) — remove any unrecognized entries"
  record_finding "$check_id" "LOW" \
    "Paired devices require manual review" \
    "Remove unrecognized devices from paired.json"
}

_check_runtime_memory_plugins() {
  local check_id="R5.7"
  local cfg="$1"
  local plugins
  plugins=$(json_get "$cfg" "plugins" 2>/dev/null || echo "")

  if [[ "$plugins" == "__UNDEFINED__" || -z "$plugins" ]]; then
    echo_skip "[${check_id}] No plugins configuration found"
    return
  fi

  local memory_issues=false

  if echo "$plugins" | grep -q "memory-lancedb"; then
    if ! echo "$plugins" | grep -qP '"encrypt(ion)?"\s*:\s*true'; then
      echo_finding "MEDIUM" "$check_id" \
        "memory-lancedb plugin found without encryption enabled" \
        "Vector memory stored in plaintext at rest"
      record_finding "$check_id" "MEDIUM" \
        "Memory plugin encryption disabled" \
        "Enable encryption in memory-lancedb plugin config"
      memory_issues=true
    fi
  fi

  [[ "$memory_issues" == "false" ]] && {
    echo_finding "PASS" "$check_id" "Memory plugin configuration appears secure ✓"
    record_finding "$check_id" "PASS" "Memory plugins OK" ""
  }
}

_check_runtime_session_ttl() {
  local check_id="R5.8"
  local cfg="$1"
  local ttl
  ttl=$(json_get "$cfg" "gateway.sessionTTL" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$ttl" == "__UNDEFINED__" || -z "$ttl" ]]; then
    echo_finding "LOW" "$check_id" \
      "gateway.sessionTTL not configured — sessions may never expire"
    record_finding "$check_id" "LOW" \
      "No session TTL configured" \
      "Set sessionTTL in seconds (e.g. 86400 = 24 hours)"
    return
  fi

  local ttl_num="${ttl//\"/}"
  if [[ "$ttl_num" =~ ^[0-9]+$ ]] && [[ "$ttl_num" -gt 604800 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "sessionTTL = ${ttl_num}s ($(( ttl_num / 86400 )) days) — excessively long"
    record_finding "$check_id" "MEDIUM" \
      "Excessive session TTL" \
      "Reduce sessionTTL to ≤ 86400 (24h)"
  else
    echo_finding "PASS" "$check_id" "sessionTTL = ${ttl_num}s ✓"
    record_finding "$check_id" "PASS" "Session TTL OK" ""
  fi
}

_check_runtime_cli_audit() {
  local check_id="R5.9"
  echo_info "[${check_id}] Attempting openclaw CLI security audit..."

  local audit_result
  audit_result=$(invoke_openclaw_audit 2>/dev/null || echo '{"error":"unavailable"}')

  if echo "$audit_result" | grep -q '"error"'; then
    echo_skip "[${check_id}] openclaw CLI audit unavailable — run manually: openclaw security audit --deep"
    return
  fi

  local critical_count high_count
  critical_count=$(echo "$audit_result" | grep -c '"severity":"CRITICAL"' 2>/dev/null || echo "0")
  high_count=$(echo "$audit_result" | grep -c '"severity":"HIGH"' 2>/dev/null || echo "0")
  critical_count="${critical_count:-0}"; high_count="${high_count:-0}"

  if [[ "$critical_count" -gt 0 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "openclaw security audit: ${critical_count} CRITICAL issue(s)"
    record_finding "$check_id" "CRITICAL" \
      "Native audit found critical issues" \
      "Run 'openclaw security audit --deep' and address all critical findings"
  elif [[ "$high_count" -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "openclaw security audit: ${high_count} HIGH issue(s)"
    record_finding "$check_id" "HIGH" \
      "Native audit found high issues" \
      "Run 'openclaw security audit --deep' for details"
  else
    echo_finding "PASS" "$check_id" "openclaw native security audit passed ✓"
    record_finding "$check_id" "PASS" "Native audit OK" ""
  fi
}
