#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 4: 反向代理配置安全检查
#  P4.1-P4.6: trustedProxies、Header安全、SSL卸载、认证绕过、超时
# ============================================================

run_proxy_checks() {
  set_current_module "proxy"
  echo_info "Checking reverse proxy configuration..."

  local config_json
  config_json=$(read_openclaw_config)

  _check_proxy_trusted_proxies "$config_json"
  _check_proxy_forwarded_header "$config_json"
  _check_proxy_security_headers
  _check_proxy_ssl_termination "$config_json"
  _check_proxy_auth_bypass "$config_json"
  _check_proxy_timeout_config "$config_json"
}

# P4.1 trustedProxies 配置安全性
_check_proxy_trusted_proxies() {
  local check_id="P4.1"
  local cfg="$1"
  local proxies
  proxies=$(json_get "$cfg" "gateway.trustedProxies" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$proxies" == "__UNDEFINED__" || "$proxies" == "null" || "$proxies" == "[]" ]]; then
    echo_finding "LOW" "$check_id" \
      "trustedProxies not configured" \
      "If behind reverse proxy, real client IPs cannot be tracked for rate limiting/auth"
    record_finding "$check_id" "LOW" \
      "trustedProxies not set" \
      "Set to reverse proxy IP(s) if applicable; leave empty if no proxy"
    return
  fi

  # 检查通配符配置（高危）
  if echo "$proxies" | grep -qP '"(\*|0\.0\.0\.0)"'; then
    echo_finding "CRITICAL" "$check_id" \
      "trustedProxies = '*' or '0.0.0.0' — ANY host can spoof X-Forwarded-For headers" \
      "IP-based access controls, rate limiting, and geoblocking are ALL bypassable"
    record_finding "$check_id" "CRITICAL" \
      "trustedProxies wildcard: IP spoofing possible" \
      "Restrict to specific reverse proxy IPs: [\"127.0.0.1\", \"10.0.0.1\"]"
    return
  fi

  # 检查是否包含公网 IP 段
  if echo "$proxies" | grep -qP '"(0\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+/[0-8])"'; then
    echo_finding "HIGH" "$check_id" \
      "trustedProxies includes broad IP range — IP spoofing may be possible"
    record_finding "$check_id" "HIGH" \
      "trustedProxies too broad" \
      "Narrow down to specific proxy server IPs"
  else
    echo_finding "PASS" "$check_id" "trustedProxies configured with specific IPs ✓"
    record_finding "$check_id" "PASS" "trustedProxies OK" ""
  fi
}

# P4.2 X-Forwarded-For 注入风险
_check_proxy_forwarded_header() {
  local check_id="P4.2"
  local cfg="$1"

  local proxies
  proxies=$(json_get "$cfg" "gateway.trustedProxies" 2>/dev/null || echo "__UNDEFINED__")
  local auth_mode
  auth_mode=$(json_get "$cfg" "gateway.auth.mode" 2>/dev/null || echo "")
  auth_mode="${auth_mode//\"/}"

  # 如果 auth.mode 是 trusted-proxy，则 X-Forwarded-For 是认证关键路径
  if [[ "$auth_mode" == "trusted-proxy" ]]; then
    if [[ "$proxies" == "__UNDEFINED__" || "$proxies" == "[]" ]]; then
      echo_finding "CRITICAL" "$check_id" \
        "auth.mode='trusted-proxy' but trustedProxies is empty" \
        "X-Forwarded-For header is used for auth but ANY client can forge it"
      record_finding "$check_id" "CRITICAL" \
        "trusted-proxy auth without proxy whitelist" \
        "Configure trustedProxies with specific proxy server IPs immediately"
    else
      echo_finding "PASS" "$check_id" \
        "trusted-proxy mode with trustedProxies configured ✓"
      record_finding "$check_id" "PASS" "X-Forwarded-For auth OK" ""
    fi
  else
    echo_finding "PASS" "$check_id" \
      "auth.mode='${auth_mode:-token}' does not rely on X-Forwarded-For ✓"
    record_finding "$check_id" "PASS" "Forwarded header not auth-critical" ""
  fi
}

# P4.3 反向代理安全 Header
_check_proxy_security_headers() {
  local check_id="P4.3"
  # Bug Fix #44: 使用 OPENCLAW_GATEWAY_PORT
  local port="${OPENCLAW_GATEWAY_PORT:-18789}"

  if ! command -v curl &>/dev/null; then
    echo_skip "[${check_id}] curl not available — cannot check security headers"
    return
  fi

  # 尝试获取响应 header（不发送认证，只看 headers）
  local headers
  headers=$(curl -sI --max-time 3 "http://127.0.0.1:${port}/" 2>/dev/null | tr -d '\r')

  if [[ -z "$headers" ]]; then
    echo_skip "[${check_id}] Gateway not responding on port ${port} — skip header check"
    return
  fi

  local missing_headers=()
  local required_headers=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
  )

  for header in "${required_headers[@]}"; do
    if ! echo "$headers" | grep -qi "^${header}:"; then
      missing_headers+=("$header")
    fi
  done

  if [[ ${#missing_headers[@]} -gt 0 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Security response headers missing: ${missing_headers[*]}" \
      "These headers protect against clickjacking, MIME sniffing, and XSS"
    record_finding "$check_id" "MEDIUM" \
      "Missing security headers: ${missing_headers[*]}" \
      "Configure security headers in reverse proxy (nginx/Caddy) or gateway middleware"
  else
    echo_finding "PASS" "$check_id" "Required security headers present ✓"
    record_finding "$check_id" "PASS" "Security headers OK" ""
  fi
}

# P4.4 SSL 卸载配置检查
_check_proxy_ssl_termination() {
  local check_id="P4.4"
  local cfg="$1"

  # 检查是否配置了 SSL 卸载后的内部通信安全
  local tls_enabled
  tls_enabled=$(json_get "$cfg" "gateway.tls.enabled" 2>/dev/null || echo "__UNDEFINED__")
  local bind_val
  bind_val=$(json_get "$cfg" "gateway.bind" 2>/dev/null || echo "")
  bind_val="${bind_val//\"/}"

  # 如果没有 TLS 但不是 loopback — 可能依赖代理 SSL 卸载
  if [[ "$tls_enabled" != "true" ]] && \
     [[ "$bind_val" != "loopback" && "$bind_val" != "localhost" && "$bind_val" != "127.0.0.1" ]]; then

    # 检查是否有代理配置文件（nginx/caddy/apache）
    local proxy_configs=()
    mapfile -t proxy_configs < <(find /etc \
      \( -name "nginx.conf" -o -name "Caddyfile" \
         -o -name "httpd.conf" -o -name "apache2.conf" \) \
      -maxdepth 4 2>/dev/null)

    if [[ ${#proxy_configs[@]} -gt 0 ]]; then
      echo_finding "LOW" "$check_id" \
        "No TLS on gateway but proxy config found — ensure SSL is terminated at proxy" \
        "Verify internal traffic (proxy→gateway) runs over loopback, not plaintext LAN"
      record_finding "$check_id" "LOW" \
        "SSL termination at proxy — verify internal routing" \
        "Ensure proxy→gateway communication is on loopback interface"
    else
      echo_finding "MEDIUM" "$check_id" \
        "No TLS and gateway not on loopback — auth tokens may traverse network in plaintext"
      record_finding "$check_id" "MEDIUM" \
        "Potential plaintext token transmission" \
        "Either enable gateway TLS or configure HTTPS reverse proxy"
    fi
  else
    echo_finding "PASS" "$check_id" "SSL/TLS configuration appears appropriate for deployment ✓"
    record_finding "$check_id" "PASS" "SSL termination OK" ""
  fi
}

# P4.5 认证绕过风险检查
_check_proxy_auth_bypass() {
  local check_id="P4.5"
  local cfg="$1"

  # 检查是否有 bypass 路径（公开访问的端点）
  local public_paths
  public_paths=$(json_get "$cfg" "gateway.auth.excludePaths" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$public_paths" == "__UNDEFINED__" || "$public_paths" == "[]" ]]; then
    echo_finding "PASS" "$check_id" "No auth-bypass paths configured ✓"
    record_finding "$check_id" "PASS" "No auth bypass paths" ""
    return
  fi

  # 检查公开路径中是否有危险端点
  local dangerous_public=(
    '/api'
    '/admin'
    '/v1/'
    '/agent'
    '/execute'
    '/run'
    '/tunnel'
  )

  local bypass_risks=()
  for path in "${dangerous_public[@]}"; do
    if echo "$public_paths" | grep -q "\"${path}"; then
      bypass_risks+=("${path}")
    fi
  done

  if [[ ${#bypass_risks[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Sensitive paths excluded from auth check: ${bypass_risks[*]}" \
      "These endpoints are accessible without token authentication"
    record_finding "$check_id" "HIGH" \
      "Auth bypass on sensitive paths: ${bypass_risks[*]}" \
      "Remove sensitive paths from auth exclusion list"
  else
    echo_finding "PASS" "$check_id" "Auth exclusion paths appear non-critical ✓"
    record_finding "$check_id" "PASS" "Auth bypass paths OK" ""
  fi
}

# P4.6 代理超时配置
_check_proxy_timeout_config() {
  local check_id="P4.6"
  local cfg="$1"

  local timeout_val
  timeout_val=$(json_get "$cfg" "gateway.timeout" 2>/dev/null || echo "__UNDEFINED__")

  if [[ "$timeout_val" == "__UNDEFINED__" || -z "$timeout_val" ]]; then
    echo_finding "LOW" "$check_id" \
      "No gateway timeout configured — long-running requests could tie up resources" \
      "Lack of timeout can enable slowloris-style DoS on local instance"
    record_finding "$check_id" "LOW" \
      "No gateway request timeout" \
      "Configure timeout in gateway settings (recommended: 300000ms = 5 minutes)"
    return
  fi

  local timeout_num="${timeout_val//\"/}"
  if [[ "$timeout_num" =~ ^[0-9]+$ ]]; then
    if [[ "$timeout_num" -gt 600000 ]]; then
      echo_finding "LOW" "$check_id" \
        "Gateway timeout is very long: ${timeout_num}ms ($(( timeout_num / 60000 )) minutes)" \
        "Long timeout increases resource consumption from stalled requests"
      record_finding "$check_id" "LOW" \
        "Excessively long timeout: ${timeout_num}ms" \
        "Reduce timeout to ≤ 300000ms (5 minutes)"
    else
      echo_finding "PASS" "$check_id" "Gateway timeout: ${timeout_num}ms ✓"
      record_finding "$check_id" "PASS" "Timeout configured" ""
    fi
  else
    echo_finding "PASS" "$check_id" "Timeout configured ✓"
    record_finding "$check_id" "PASS" "Timeout OK" ""
  fi
}
