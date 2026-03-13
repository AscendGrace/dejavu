#!/usr/bin/env bash
# =============================================================
#  CHECK MODULE 8: 主机运行时审计
#  对标 SlowMist v2.7 nightly check items: 3/4/5/6/8/9
#  H8.1 敏感目录变更  H8.2/H8.3 定时任务  H8.4/H8.5 登录审计
#  H8.6 黄线验证     H8.7/H8.8 磁盘      H8.9 出站连接
# =============================================================

# Bug Fix #42: 函数名修正为 run_hostaudit_checks，与 dejavu.sh dispatch 约定 "run_${check}_checks" 保持一致
# 原名 run_host_audit 导致 hostaudit 模块在 bash 下永远无法被调度执行
run_hostaudit_checks() {
  set_current_module "hostaudit"
  echo_info "Running host runtime audit (SlowMist checks 3/4/5/6/8/9)..."

  local OC="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"

  _check_hostaudit_sensitive_dir_changes "$OC"
  _check_hostaudit_cron_jobs
  _check_hostaudit_openclaw_cron "$OC"
  _check_hostaudit_login_audit
  _check_hostaudit_ssh_failures
  _check_hostaudit_sudo_crosscheck "$OC"
  _check_hostaudit_disk_usage
  _check_hostaudit_large_files
  _check_hostaudit_outbound_connections
}

# H8.1 敏感目录 24h 变更扫描
_check_hostaudit_sensitive_dir_changes() {
  local check_id="H8.1"
  local OC="$1"
  local sensitive_dirs=("$OC" "/etc" "$HOME/.ssh" "$HOME/.gnupg" "/usr/local/bin")
  local mod_count=0
  for d in "${sensitive_dirs[@]}"; do
    if [[ -d "$d" ]]; then
      local n
      n=$(find "$d" -type f -mtime -1 2>/dev/null | wc -l)
      n=${n:-0}
      mod_count=$((mod_count + n))
    fi
  done

  if [[ "$mod_count" -gt 50 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Large number of sensitive directory files changed in last 24h: ${mod_count} files" \
      "Manual review for unauthorized writes: find \$OC /etc ~/.ssh -mtime -1 -ls"
    record_finding "$check_id" "HIGH" \
      "Sensitive directory 24h changes: ${mod_count} files" \
      "Run: find $OC /etc ~/.ssh -mtime -1 -ls"
  elif [[ "$mod_count" -gt 10 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Sensitive directory has ${mod_count} file changes in last 24h, please review"
    record_finding "$check_id" "MEDIUM" \
      "Sensitive directory changes: ${mod_count} files" \
      "Review recently modified files: find \$OC /etc -mtime -1 -ls"
  else
    echo_finding "PASS" "$check_id" \
      "Sensitive directory file changes normal in last 24h: ${mod_count} files ✓"
    record_finding "$check_id" "PASS" "Sensitive directory changes normal" ""
  fi
}

# H8.2 系统定时任务检查
_check_hostaudit_cron_jobs() {
  local check_id="H8.2"
  local cron_entries
  cron_entries=$(crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
  local cron_d_count=0
  [[ -d /etc/cron.d ]] && cron_d_count=$(ls /etc/cron.d 2>/dev/null | wc -l)
  cron_d_count=${cron_d_count:-0}

  local timer_count=0
  if command -v systemctl &>/dev/null; then
    timer_count=$(systemctl list-timers --all 2>/dev/null | grep -c '\.timer' 2>/dev/null || true)
    timer_count=${timer_count:-0}
  fi

  if [[ -n "$cron_entries" ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Current user crontab has active tasks, please verify all are expected"
    while IFS= read -r line; do
      echo_info "    cron: ${line}"
    done <<< "$cron_entries"
    record_finding "$check_id" "MEDIUM" \
      "User crontab tasks found" \
      "Audit: crontab -l — verify all tasks are expected"
  else
    echo_finding "PASS" "$check_id" "User crontab has no active tasks ✓"
    record_finding "$check_id" "PASS" "crontab clean" ""
  fi
  echo_info "[${check_id}] /etc/cron.d: ${cron_d_count} entries | systemd-timers: ${timer_count} timers"
}

# H8.3 OpenClaw 内置 Cron Jobs
_check_hostaudit_openclaw_cron() {
  local check_id="H8.3"
  local OC="$1"
  local openclaw_bin=""
  [[ -f "$OC/openclaw.mjs" ]] && openclaw_bin="node $OC/openclaw.mjs"
  command -v openclaw &>/dev/null && openclaw_bin="openclaw"

  if [[ -z "$openclaw_bin" ]]; then
    echo_skip "[${check_id}] openclaw command not in PATH, skipping Cron Jobs check"
    return
  fi

  local cron_list
  cron_list=$(eval "$openclaw_bin cron list" 2>/dev/null || echo "UNAVAILABLE")
  if [[ "$cron_list" == "UNAVAILABLE" ]]; then
    echo_skip "[${check_id}] openclaw cron list unavailable (process not running)"
    return
  fi

  local cron_lines
  cron_lines=$(echo "$cron_list" | grep -c '.' 2>/dev/null || true)
  cron_lines=${cron_lines:-0}
  echo_info "[${check_id}] OpenClaw built-in Cron Jobs: ${cron_lines} entries (please verify they match expected)"
  echo "$cron_list" | head -20
  record_finding "$check_id" "PASS" "OpenClaw cron audit completed" ""
}

# H8.4 登录审计
_check_hostaudit_login_audit() {
  local check_id="H8.4"
  local last_output
  last_output=$(last -a -n 5 2>/dev/null || echo "UNAVAILABLE")

  if [[ "$last_output" == "UNAVAILABLE" ]]; then
    echo_skip "[${check_id}] last/lastlog commands unavailable"
    return
  fi

  echo_info "[${check_id}] Recent login records (for reference only):"
  echo "$last_output" | head -10
  record_finding "$check_id" "PASS" "Login records audited" ""
}

# H8.5 SSH 失败尝试统计
_check_hostaudit_ssh_failures() {
  local check_id="H8.5"
  local failed_ssh=0

  if command -v journalctl &>/dev/null; then
    failed_ssh=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null \
      | grep -Ei "Failed|Invalid" | wc -l)
    failed_ssh=${failed_ssh:-0}
  fi

  if [[ "$failed_ssh" -eq 0 ]]; then
    for logf in /var/log/auth.log /var/log/secure /var/log/messages; do
      if [[ -f "$logf" ]]; then
        failed_ssh=$(grep -Ei "sshd.*(Failed|Invalid)" "$logf" 2>/dev/null \
          | tail -n 1000 | wc -l)
        failed_ssh=${failed_ssh:-0}
        break
      fi
    done
  fi

  if [[ "$failed_ssh" -gt 100 ]]; then
    echo_finding "HIGH" "$check_id" \
      "SSH failed attempts in last 24h abnormal: ${failed_ssh} times (possible brute force attack)" \
      "Check source IPs: grep 'Failed' /var/log/auth.log | awk '{print \$11}' | sort | uniq -c | sort -rn"
    record_finding "$check_id" "HIGH" \
      "SSH brute force attack indicators: ${failed_ssh} failures" \
      "Block attacker IPs: fail2ban or iptables -I INPUT -s <IP> -j DROP"
  elif [[ "$failed_ssh" -gt 20 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "SSH failed attempts in last 24h: ${failed_ssh} times"
    record_finding "$check_id" "MEDIUM" \
      "High SSH failure count: ${failed_ssh} failures" \
      "Monitor with: journalctl -u sshd --since '24h ago' | grep Failed"
  else
    echo_finding "PASS" "$check_id" \
      "SSH failed attempts in last 24h within normal range: ${failed_ssh} times ✓"
    record_finding "$check_id" "PASS" "SSH failed attempts normal" ""
  fi
}

# H8.6 黄线操作交叉验证（sudo log vs memory日志）
_check_hostaudit_sudo_crosscheck() {
  local check_id="H8.6"
  local OC="$1"
  local sudo_count=0

  for logf in /var/log/auth.log /var/log/secure /var/log/messages; do
    if [[ -f "$logf" ]]; then
      sudo_count=$(grep -Ei "sudo.*COMMAND" "$logf" 2>/dev/null | tail -n 2000 | wc -l)
      sudo_count=${sudo_count:-0}
      break
    fi
  done

  local today
  today=$(date +%F)
  local mem_file="$OC/workspace/memory/${today}.md"
  local mem_count=0
  if [[ -f "$mem_file" ]]; then
    mem_count=$(grep -i "sudo" "$mem_file" 2>/dev/null | wc -l)
    mem_count=${mem_count:-0}
  fi

  if [[ "$sudo_count" -gt 0 && "$mem_count" -eq 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Sudo cross-validation anomaly: sudo execution records=${sudo_count} times, but no corresponding records in memory/${today}.md" \
      "Unrecorded sudo operations detected, manual review required: /var/log/auth.log"
    record_finding "$check_id" "HIGH" \
      "Sudo operations not recorded in memory" \
      "Human: review auth.log sudo entries and memory log discrepancy"
  elif [[ "$sudo_count" -eq 0 ]]; then
    echo_finding "PASS" "$check_id" "No sudo execution records today ✓"
    record_finding "$check_id" "PASS" "sudo cross-validation passed" ""
  else
    echo_finding "PASS" "$check_id" \
      "Sudo cross-validation passed: sudo records=${sudo_count}, memory records=${mem_count} ✓"
    record_finding "$check_id" "PASS" "sudo cross-validation passed" ""
  fi
}

# H8.7 磁盘使用率
_check_hostaudit_disk_usage() {
  local check_id="H8.7"
  local disk_usage
  disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")

  if [[ "$disk_usage" =~ ^[0-9]+$ ]]; then
    if [[ "$disk_usage" -ge 95 ]]; then
      echo_finding "CRITICAL" "$check_id" \
        "Root partition disk usage critically low: ${disk_usage}%" \
        "Clean up immediately: du -sh /* 2>/dev/null | sort -rh | head -20"
      record_finding "$check_id" "CRITICAL" \
        "Disk usage critical: ${disk_usage}%" \
        "Immediately free disk space: journalctl --vacuum-size=500M"
    elif [[ "$disk_usage" -ge 85 ]]; then
      echo_finding "HIGH" "$check_id" \
        "Root partition disk usage exceeds 85%: ${disk_usage}%" \
        "Cleanup suggestions: journalctl --vacuum-size=500M ; docker system prune"
      record_finding "$check_id" "HIGH" \
        "Disk usage high: ${disk_usage}%" \
        "Clean up: journalctl --vacuum-size=500M ; npm cache clean --force"
    else
      echo_finding "PASS" "$check_id" "Disk usage normal: ${disk_usage}% ✓"
      record_finding "$check_id" "PASS" "Disk usage normal" ""
    fi
  else
    echo_skip "[${check_id}] Unable to get disk usage"
  fi
}

# H8.8 24h 新增大文件（>100MB）
_check_hostaudit_large_files() {
  local check_id="H8.8"
  local large_files
  large_files=$(find / -xdev -type f -size +100M -mtime -1 2>/dev/null | head -20 || true)
  local large_count
  large_count=$(echo "$large_files" | grep -c '.' 2>/dev/null || true)
  large_count=${large_count:-0}

  if [[ "$large_count" -gt 5 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Found ${large_count} large files (>100MB) in last 24h, please verify if expected"
    echo "$large_files" | head -10
    record_finding "$check_id" "MEDIUM" \
      "Found ${large_count} new large files" \
      "Verify these files are expected: find / -size +100M -mtime -1"
  elif [[ "$large_count" -gt 0 ]]; then
    echo_finding "LOW" "$check_id" \
      "Found ${large_count} large files (>100MB) in last 24h"
    echo "$large_files" | head -5
    record_finding "$check_id" "LOW" \
      "Found ${large_count} new large files" \
      "Review: find / -size +100M -mtime -1"
  else
    echo_finding "PASS" "$check_id" "No large files found in last 24h ✓"
    record_finding "$check_id" "PASS" "No large file anomalies" ""
  fi
}

# H8.9 异常出站连接检测
_check_hostaudit_outbound_connections() {
  local check_id="H8.9"

  if ! command -v ss &>/dev/null; then
    echo_skip "[${check_id}] ss not available — skipping outbound connection check"
    return
  fi

  local outbound_count=0
  outbound_count=$(ss -tnp state established 2>/dev/null \
    | awk 'NR>1 {print $5}' \
    | grep -vE '^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
    | grep -v ':443$' | grep -v ':80$' \
    | wc -l)
  outbound_count=${outbound_count:-0}

  if [[ "$outbound_count" -gt 20 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Abnormal outbound TCP connection count: ${outbound_count} connections (excluding 80/443 and internal networks)" \
      "Investigate: ss -tnp state established | grep -v ':443\\|:80'"
    record_finding "$check_id" "HIGH" \
      "Abnormal outbound connections: ${outbound_count} connections" \
      "Investigate non-standard outbound connections: ss -tnp state established"
  elif [[ "$outbound_count" -gt 5 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "High outbound connections: ${outbound_count} connections, please monitor"
    record_finding "$check_id" "MEDIUM" \
      "High outbound connections: ${outbound_count} connections" \
      "Review: ss -tnp state established | grep -v ':443|:80'"
  else
    echo_finding "PASS" "$check_id" \
      "Outbound connections normal: ${outbound_count} ✓"
    record_finding "$check_id" "PASS" "Outbound connections normal" ""
  fi
}
