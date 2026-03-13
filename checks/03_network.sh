#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 3: 网络暴露检查
#  N3.1-N3.7: 端口绑定、TLS、防火墙、CORS、速率限制
# ============================================================

run_network_checks() {
  set_current_module "network"
  echo_info "Analyzing network exposure..."

  local config_json
  config_json=$(read_openclaw_config)

  _check_network_gateway_port
  _check_network_browser_port
  _check_network_all_interfaces
  _check_network_tls_config "$config_json"
  _check_network_cors_config "$config_json"
  _check_network_firewall_rules
  _check_network_rate_limit "$config_json"
}

# N3.1 Gateway 端口绑定检查
_check_network_gateway_port() {
  local check_id="N3.1"
  # Bug Fix #44: 使用 OPENCLAW_GATEWAY_PORT，与 dejavu.sh 导出的变量名保持一致
  local port="${OPENCLAW_GATEWAY_PORT:-18789}"

  local bind_result=""

  # Linux: ss 优先，netstat 备选
  if command -v ss &>/dev/null; then
    bind_result=$(ss -tlnp 2>/dev/null | grep ":${port}" | head -3)
  elif command -v netstat &>/dev/null; then
    bind_result=$(netstat -tlnp 2>/dev/null | grep ":${port}" | head -3)
  fi

  if [[ -z "$bind_result" ]]; then
    echo_finding "PASS" "$check_id" "Gateway port ${port} is not currently listening"
    record_finding "$check_id" "PASS" "Gateway port not active" ""
    return
  fi

  if echo "$bind_result" | grep -qP "0\.0\.0\.0|::(?!1)"; then
    echo_finding "CRITICAL" "$check_id" \
      "Gateway port ${port} bound to ALL interfaces (0.0.0.0)" \
      "Anyone on your network/internet can connect to the OpenClaw gateway"
    record_finding "$check_id" "CRITICAL" \
      "Gateway port exposed on all interfaces" \
      'Set "bind": "loopback" in openclaw.json and restart openclaw'
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}iptables -I INPUT -p tcp --dport ${port} -j DROP${RESET}"
  elif echo "$bind_result" | grep -qP "127\.0\.0\.1|::1"; then
    echo_finding "PASS" "$check_id" "Gateway port ${port} bound to loopback only ✓"
    record_finding "$check_id" "PASS" "Gateway port loopback only" ""
  else
    echo_finding "MEDIUM" "$check_id" \
      "Gateway port ${port} has non-standard binding: ${bind_result}" \
      "Verify this is intentional"
    record_finding "$check_id" "MEDIUM" \
      "Non-standard gateway port binding" \
      "Verify port ${port} is only accessible from trusted hosts"
  fi
}

# N3.2 Browser Control 端口检查
_check_network_browser_port() {
  local check_id="N3.2"
  # Bug Fix #44: 使用 OPENCLAW_BROWSER_PORT，与 dejavu.sh 导出的变量名保持一致
  local port="${OPENCLAW_BROWSER_PORT:-18791}"

  local bind_result=""
  if command -v ss &>/dev/null; then
    bind_result=$(ss -tlnp 2>/dev/null | grep ":${port}" | head -3)
  elif command -v netstat &>/dev/null; then
    bind_result=$(netstat -tlnp 2>/dev/null | grep ":${port}" | head -3)
  fi

  if [[ -z "$bind_result" ]]; then
    echo_finding "PASS" "$check_id" "Browser control port ${port} is not currently listening"
    record_finding "$check_id" "PASS" "Browser port not active" ""
    return
  fi

  if echo "$bind_result" | grep -qP "0\.0\.0\.0|::(?!1)"; then
    echo_finding "CRITICAL" "$check_id" \
      "Browser control port ${port} exposed on ALL interfaces" \
      "Remote screen capture and browser control accessible from network"
    record_finding "$check_id" "CRITICAL" \
      "Browser control port publicly exposed" \
      "Bind browser control to 127.0.0.1 only (openclaw --browser-bind=localhost)"
  elif echo "$bind_result" | grep -qP "127\.0\.0\.1|::1"; then
    echo_finding "PASS" "$check_id" "Browser control port ${port} loopback only ✓"
    record_finding "$check_id" "PASS" "Browser port loopback only" ""
  fi
}

# N3.3 全网接口扫描（检查除 openclaw 端口外的其他可疑暴露）
_check_network_all_interfaces() {
  local check_id="N3.3"

  local exposed_services=()
  local openclaw_ports=("18789" "18791" "18792" "18793" "18794" "18795")

  local listen_output=""
  if command -v ss &>/dev/null; then
    listen_output=$(ss -tlnp 2>/dev/null | grep "0\.0\.0\.0" | grep -v "127\.")
  elif command -v netstat &>/dev/null; then
    listen_output=$(netstat -tlnp 2>/dev/null | grep "0\.0\.0\.0" | grep -v "127\.")
  fi

  if [[ -z "$listen_output" ]]; then
    echo_finding "PASS" "$check_id" "No unexpected services exposed on all interfaces ✓"
    record_finding "$check_id" "PASS" "No additional exposed services" ""
    return
  fi

  while IFS= read -r line; do
    local port
    port=$(echo "$line" | grep -oP '0\.0\.0\.0:\K[0-9]+' | head -1)
    # 过滤掉 openclaw 已检查的端口和常见系统端口(22,80,443)
    if [[ -n "$port" ]] && ! printf '%s\n' "${openclaw_ports[@]}" | grep -q "^${port}$"; then
      [[ "$port" -lt 1024 ]] && continue  # 跳过知名端口
      exposed_services+=("Port ${port}")
    fi
  done <<< "$listen_output"

  if [[ ${#exposed_services[@]} -gt 0 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Additional services exposed on all interfaces: ${exposed_services[*]}" \
      "Review whether these are intentional — reduce attack surface"
    record_finding "$check_id" "MEDIUM" \
      "Additional exposed services: ${exposed_services[*]}" \
      "Bind unneeded services to loopback or firewall them"
  else
    echo_finding "PASS" "$check_id" "No unexpected exposed high-number ports ✓"
    record_finding "$check_id" "PASS" "Additional ports OK" ""
  fi
}

# N3.4 TLS 配置检查
_check_network_tls_config() {
  local check_id="N3.4"
  local cfg="$1"

  local tls_enabled
  tls_enabled=$(json_get "$cfg" "gateway.tls.enabled" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$tls_enabled" == "true" ]]; then
    # 检查证书是否是自签名
    local cert_path
    cert_path=$(json_get "$cfg" "gateway.tls.cert" 2>/dev/null || echo "")
    cert_path="${cert_path//\"/}"

    if [[ -f "$cert_path" ]] && command -v openssl &>/dev/null; then
      local issuer subject
      issuer=$(openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null || echo "")
      subject=$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null || echo "")
      # 自签名：issuer == subject
      if [[ "$issuer" == "$subject" ]]; then
        echo_finding "MEDIUM" "$check_id" \
          "TLS is enabled but using a self-signed certificate" \
          "Clients may reject or accept this without proper chain validation"
        record_finding "$check_id" "MEDIUM" \
          "Self-signed TLS certificate" \
          "Use a certificate from a trusted CA (e.g., Let's Encrypt)"
      else
        echo_finding "PASS" "$check_id" "TLS enabled with valid certificate ✓"
        record_finding "$check_id" "PASS" "TLS configured" ""
      fi
    else
      echo_finding "PASS" "$check_id" "TLS is enabled ✓"
      record_finding "$check_id" "PASS" "TLS enabled" ""
    fi

  elif [[ "$tls_enabled" == "false" || "$tls_enabled" == "__UNDEFINED__" ]]; then
    # 检查是否仅在 loopback — 若是则 TLS 不必须
    local bind_val
    bind_val=$(json_get "$cfg" "gateway.bind" 2>/dev/null || echo "loopback")
    bind_val="${bind_val//\"/}"

    if [[ "$bind_val" == "loopback" || "$bind_val" == "localhost" || "$bind_val" == "127.0.0.1" ]]; then
      echo_finding "LOW" "$check_id" \
        "TLS not configured — acceptable for loopback-only deployments" \
        "If exposing over LAN/WAN, TLS is required to prevent token interception"
      record_finding "$check_id" "LOW" \
        "TLS not configured (loopback only)" \
        "Consider TLS even for loopback to prevent local interception"
    else
      echo_finding "HIGH" "$check_id" \
        "TLS not configured while gateway is exposed beyond loopback" \
        "Auth tokens transmitted in plaintext — subject to network sniffing"
      record_finding "$check_id" "HIGH" \
        "No TLS on non-loopback gateway" \
        "Enable TLS in gateway config or place behind HTTPS reverse proxy"
    fi
  fi
}

# N3.5 CORS 配置检查
_check_network_cors_config() {
  local check_id="N3.5"
  local cfg="$1"

  local cors_origins
  cors_origins=$(json_get "$cfg" "gateway.cors.origins" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$cors_origins" == "__UNDEFINED__" || -z "$cors_origins" ]]; then
    echo_finding "LOW" "$check_id" \
      "CORS not explicitly configured — using browser defaults"
    record_finding "$check_id" "LOW" \
      "CORS not configured" \
      "Explicitly configure CORS origins to restrict cross-origin requests"
    return
  fi

  if echo "$cors_origins" | grep -qP '"(\*|all)"'; then
    echo_finding "HIGH" "$check_id" \
      "CORS configured with wildcard '*' — any website can make requests to gateway" \
      "Risk: malicious websites can interact with your AI agent via CSRF"
    record_finding "$check_id" "HIGH" \
      "CORS wildcard allows all origins" \
      "Restrict CORS origins to specific trusted domains"
  else
    echo_finding "PASS" "$check_id" "CORS configured with specific origins ✓"
    record_finding "$check_id" "PASS" "CORS config OK" ""
  fi
}

# N3.6 防火墙规则审计
_check_network_firewall_rules() {
  local check_id="N3.6"
  # Bug Fix #44: 使用 OPENCLAW_GATEWAY_PORT
  local port="${OPENCLAW_GATEWAY_PORT:-18789}"

  if command -v iptables &>/dev/null && [[ $EUID -eq 0 ]]; then
    local iptables_result
    iptables_result=$(iptables -L INPUT -n 2>/dev/null | grep "$port" || echo "")

    if [[ -z "$iptables_result" ]]; then
      echo_finding "MEDIUM" "$check_id" \
        "No explicit iptables rule for port ${port}" \
        "If the gateway is on a LAN-facing address, it may be unprotected"
      record_finding "$check_id" "MEDIUM" \
        "No firewall rule for gateway port" \
        "Add: iptables -I INPUT -p tcp --dport ${port} -j DROP if port is loopback-only"
    else
      echo_finding "PASS" "$check_id" "iptables rule exists for port ${port} ✓"
      record_finding "$check_id" "PASS" "Firewall rule OK" ""
    fi

  elif command -v ufw &>/dev/null; then
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null | grep "$port" || echo "")
    if [[ -z "$ufw_status" ]]; then
      echo_finding "LOW" "$check_id" \
        "No UFW rule found for port ${port}"
      record_finding "$check_id" "LOW" \
        "No UFW rule for gateway port" \
        "Run: ufw deny ${port}/tcp (if loopback-only)"
    else
      echo_finding "PASS" "$check_id" "UFW rule exists for port ${port} ✓"
      record_finding "$check_id" "PASS" "UFW rule OK" ""
    fi

  else
    echo_skip "[${check_id}] No firewall tool found (iptables/ufw) — verify manually"
  fi
}

# N3.7 速率限制验证
_check_network_rate_limit() {
  local check_id="N3.7"
  local cfg="$1"

  local rate_limit_max
  rate_limit_max=$(json_get "$cfg" "gateway.rateLimit.maxRequests" 2>/dev/null || echo "__UNDEFINED__")
  local rate_limit_window
  rate_limit_window=$(json_get "$cfg" "gateway.rateLimit.windowMs" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$rate_limit_max" == "__UNDEFINED__" || -z "$rate_limit_max" ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "No gateway-side rate limiting configured" \
      "Auth token brute force is unlimited — consider adding rate limiting"
    record_finding "$check_id" "MEDIUM" \
      "No API rate limiting" \
      "Configure rateLimit in openclaw.json or use nginx rate limiting upstream"
  else
    local max_val="${rate_limit_max//\"/}"
    if [[ "$max_val" =~ ^[0-9]+$ ]] && [[ "$max_val" -gt 1000 ]]; then
      echo_finding "LOW" "$check_id" \
        "Rate limit is high: ${max_val} req/window — may not prevent brute force"
      record_finding "$check_id" "LOW" \
        "Rate limit may be too permissive" \
        "Reduce rateLimit.maxRequests to ≤ 100 for auth endpoints"
    else
      echo_finding "PASS" "$check_id" "Rate limiting configured: ${max_val} req/window ✓"
      record_finding "$check_id" "PASS" "Rate limiting OK" ""
    fi
  fi
}
