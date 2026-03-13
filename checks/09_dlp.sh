#!/usr/bin/env bash
# =============================================================
#  CHECK MODULE 9: DLP + 完整性基线 + 大脑灾备
#  对标 SlowMist v2.7 nightly check items: 10/11/12/13
#  I9.1 环境变量泄露  I9.2 明文私钥DLP  I9.3 文件哈希基线
#  I9.4 Skill/MCP指纹基线  I9.5 大脑灾备
# =============================================================

run_dlp_checks() {
  set_current_module "dlp"
  echo_info "Running DLP / Integrity / Backup checks (SlowMist checks 10/11/12/13)..."

  local OC="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
  local HASH_DIR="${OC}/security-baselines"
  mkdir -p "$HASH_DIR" 2>/dev/null || true

  _check_dlp_gateway_env_vars "$OC"
  _check_dlp_plaintext_private_keys "$OC"
  _check_dlp_file_hash_baseline "$OC" "$HASH_DIR"
  _check_dlp_skill_mcp_fingerprint "$OC" "$HASH_DIR"
  _check_dlp_brain_backup "$OC"
}

# I9.1 Gateway 进程环境变量泄露扫描
_check_dlp_gateway_env_vars() {
  local check_id="I9.1"
  local OC="$1"

  local gw_pid=""
  gw_pid=$(pgrep -f "openclaw-gateway\|openclaw.*gateway" 2>/dev/null | head -1 || true)

  # macOS fallback: lsof
  if [[ -z "$gw_pid" ]] && command -v lsof &>/dev/null; then
    # Bug Fix #44: 使用 OPENCLAW_GATEWAY_PORT
    local port="${OPENCLAW_GATEWAY_PORT:-18789}"
    gw_pid=$(lsof -i ":${port}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $2}' || true)
  fi

  if [[ -z "$gw_pid" ]]; then
    echo_skip "[${check_id}] No running openclaw-gateway process detected"
    return
  fi

  local env_proc="/proc/${gw_pid}/environ"
  if [[ ! -r "$env_proc" ]]; then
    echo_skip "[${check_id}] Gateway process PID=${gw_pid} found, but ${env_proc} is not readable (permission denied)"
    return
  fi

  local env_hits
  env_hits=$(strings "$env_proc" 2>/dev/null \
    | grep -iE 'SECRET|TOKEN|PASSWORD|KEY|PRIVATE|CREDENTIAL|API' \
    | awk -F= '{print $1"=(Hidden)"}' || true)

  if [[ -n "$env_hits" ]]; then
    echo_finding "HIGH" "$check_id" \
      "Gateway process environment contains sensitive variable names (values sanitized):"
    echo "$env_hits" | head -20
    record_finding "$check_id" "HIGH" \
      "Sensitive variables in Gateway environment" \
      "Verify these env vars are intentionally set and not over-exposed"
  else
    echo_finding "PASS" "$check_id" "No suspicious sensitive variable names in Gateway environment ✓"
    record_finding "$check_id" "PASS" "Gateway environment variables clean" ""
  fi
}

# I9.2 Plaintext Ethereum/Bitcoin private key scan (DLP)
_check_dlp_plaintext_private_keys() {
  local check_id="I9.2"
  local OC="$1"
  local scan_root="${OC}/workspace"

  if [[ ! -d "$scan_root" ]]; then
    # 如果没有 workspace，扫描整个 OC 目录
    scan_root="$OC"
  fi

  local dlp_eth_files dlp_btc_files dlp_mnemonic_files dlp_pem_files
  local dlp_eth=0
  local dlp_btc=0
  local dlp_mnemonic=0

  # ETH 私钥: 0x + 64 hex chars
  dlp_eth_files=$(grep -RIlE --include='*.txt' --include='*.md' --include='*.json' --include='*.log' \
    '\b0x[a-fA-F0-9]{64}\b' "$scan_root" 2>/dev/null || true)
  [[ -n "$dlp_eth_files" ]] && dlp_eth=$(echo "$dlp_eth_files" | wc -l | tr -d '[:space:]')

  # BTC WIF 私钥：5/K/L 开头的 51/52 char Base58
  dlp_btc_files=$(grep -RIlE --include='*.txt' --include='*.md' --include='*.json' --include='*.log' \
    '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$scan_root" 2>/dev/null || true)
  [[ -n "$dlp_btc_files" ]] && dlp_btc=$(echo "$dlp_btc_files" | wc -l | tr -d '[:space:]')

  # 12/24 词助记词（启发式）
  dlp_mnemonic_files=$(grep -RIlE --include='*.txt' --include='*.md' --include='*.json' \
    '\b([a-z]{3,12}\s+){11}[a-z]{3,12}\b' "$scan_root" 2>/dev/null || true)
  [[ -n "$dlp_mnemonic_files" ]] && dlp_mnemonic=$(echo "$dlp_mnemonic_files" | wc -l | tr -d '[:space:]')

  # PEM 私钥
  local dlp_pem=0
  dlp_pem_files=$(grep -RIlE --include='*.pem' --include='*.key' \
    'PRIVATE KEY' "$scan_root" 2>/dev/null || true)
  [[ -n "$dlp_pem_files" ]] && dlp_pem=$(echo "$dlp_pem_files" | wc -l | tr -d '[:space:]')

  local dlp_total=$((dlp_eth + dlp_btc + dlp_mnemonic + dlp_pem))

  if [[ "$dlp_total" -gt 0 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "DLP scan detected potential plaintext private key/mnemonic!" \
      "ETH=${dlp_eth} BTC=${dlp_btc} mnemonic≈${dlp_mnemonic} PEM_files=${dlp_pem}"
    # 输出命中文件路径
    if [[ -n "$dlp_eth_files" ]]; then
      echo -e "         ${RED}[ETH Private Key]${RESET}"
      echo "$dlp_eth_files" | head -10 | while IFS= read -r p; do
        echo -e "           ${YELLOW}-> ${p}${RESET}"
      done
    fi
    if [[ -n "$dlp_btc_files" ]]; then
      echo -e "         ${RED}[BTC WIF Key]${RESET}"
      echo "$dlp_btc_files" | head -10 | while IFS= read -r p; do
        echo -e "           ${YELLOW}-> ${p}${RESET}"
      done
    fi
    if [[ -n "$dlp_mnemonic_files" ]]; then
      echo -e "         ${RED}[Mnemonic Phrase]${RESET}"
      echo "$dlp_mnemonic_files" | head -10 | while IFS= read -r p; do
        echo -e "           ${YELLOW}-> ${p}${RESET}"
      done
    fi
    if [[ -n "$dlp_pem_files" ]]; then
      echo -e "         ${RED}[PEM Private Key]${RESET}"
      echo "$dlp_pem_files" | head -10 | while IFS= read -r p; do
        echo -e "           ${YELLOW}-> ${p}${RESET}"
      done
    fi
    echo_warn "Immediately review these files manually, delete or move out of working directory after confirmation"
    record_finding "$check_id" "CRITICAL" \
      "Potential plaintext private key detected: ETH=${dlp_eth} BTC=${dlp_btc} mnemonic≈${dlp_mnemonic}" \
      "Immediately review and remove private keys from memory/workspace files"
  else
    echo_finding "PASS" "$check_id" "DLP scan: no obvious private key/mnemonic patterns found ✓"
    record_finding "$check_id" "PASS" "DLP scan passed" ""
  fi
}

# I9.3 Critical file sha256 hash baseline comparison
_check_dlp_file_hash_baseline() {
  local check_id="I9.3"
  local OC="$1"
  local HASH_DIR="$2"

  local baseline_file="${HASH_DIR}/config-baseline.sha256"
  local cur_hash_file="${HASH_DIR}/config-current.sha256"

  local tracked_files=(
    "${OC}/openclaw.json"
    "${OC}/SOULS.md"
    "/etc/ssh/sshd_config"
    "$HOME/.ssh/authorized_keys"
  )

  : > "$cur_hash_file"
  for f in "${tracked_files[@]}"; do
    [[ -f "$f" ]] && sha256sum "$f" >> "$cur_hash_file" 2>/dev/null || true
  done

  if [[ -f "$baseline_file" ]]; then
    local diff_result
    diff_result=$(diff "$baseline_file" "$cur_hash_file" 2>/dev/null || true)
    if [[ -z "$diff_result" ]]; then
      echo_finding "PASS" "$check_id" "Critical file sha256 baseline verification passed ✓"
      record_finding "$check_id" "PASS" "File hash baseline verification passed" ""
    else
      echo_finding "HIGH" "$check_id" \
        "Critical file hash does not match baseline! Possible tampering detected"
      echo "diff output:"
      echo "$diff_result" | head -20
      record_finding "$check_id" "HIGH" \
        "Critical files modified (hash mismatch)" \
        "Review diff and determine if changes were authorized; update baseline if valid"
      # Update baseline (can be updated manually after review)
    fi

    # 独立检查文件权限
    local perm_oc
    perm_oc=$(stat -c "%a" "${OC}/openclaw.json" 2>/dev/null || echo "MISSING")
    if [[ "$perm_oc" != "600" && "$perm_oc" != "MISSING" ]]; then
      echo_finding "HIGH" "${check_id}b" \
        "openclaw.json permissions insecure: ${perm_oc} (should be 600)"
      record_finding "${check_id}b" "HIGH" \
        "openclaw.json permissions issue: ${perm_oc}" \
        "Fix: chmod 600 ${OC}/openclaw.json"
      [[ "${FIX_MODE:-false}" == "true" ]] && chmod 600 "${OC}/openclaw.json" && \
        echo_info "Fixed: chmod 600 ${OC}/openclaw.json"
    else
      echo_finding "PASS" "${check_id}b" "openclaw.json permissions: ${perm_oc} ✓"
      record_finding "${check_id}b" "PASS" "openclaw.json permissions OK" ""
    fi
  else
    # 首次运行：生成基线
    cp "$cur_hash_file" "$baseline_file" 2>/dev/null || true
    echo_info "[${check_id}] First run: Generated critical file hash baseline → ${baseline_file}"
    echo_finding "PASS" "$check_id" "Hash baseline created (first run) ✓"
    record_finding "$check_id" "PASS" "Hash baseline initialization completed" ""
  fi
}

# I9.4 Skill/MCP file fingerprint baseline diff
_check_dlp_skill_mcp_fingerprint() {
  local check_id="I9.4"
  local OC="$1"
  local HASH_DIR="$2"

  local skill_dir="${OC}/workspace/skills"
  local mcp_dir="${OC}/workspace/mcp"
  local cur_skill_hash="${HASH_DIR}/skill-mcp-current.sha256"
  local base_skill_hash="${HASH_DIR}/skill-mcp-baseline.sha256"

  # 也检查 SKILLS_DIR (来自命令行参数)
  [[ -n "${SKILLS_DIR:-}" ]] && skill_dir="${SKILLS_DIR}"

  : > "$cur_skill_hash"
  for d in "$skill_dir" "$mcp_dir"; do
    if [[ -d "$d" ]]; then
      find "$d" -type f -print0 2>/dev/null | sort -z \
        | xargs -0 sha256sum 2>/dev/null >> "$cur_skill_hash" || true
    fi
  done

  if [[ -s "$cur_skill_hash" ]]; then
    local skill_file_count
    skill_file_count=$(wc -l < "$cur_skill_hash")

    if [[ -f "$base_skill_hash" ]]; then
      local skill_diff
      skill_diff=$(diff "$base_skill_hash" "$cur_skill_hash" 2>/dev/null || true)
      if [[ -z "$skill_diff" ]]; then
        echo_finding "PASS" "$check_id" "Skill/MCP file fingerprint matches baseline ✓"
        record_finding "$check_id" "PASS" "Skill/MCP fingerprint baseline consistent" ""
      else
        local changed_count
        changed_count=$(echo "$skill_diff" | grep -c '^[<>]' || echo "?")
        echo_finding "HIGH" "$check_id" \
          "Skill/MCP file fingerprint changed! Possible supply chain tampering detected, manual review required (${changed_count} differences)"
        echo "$skill_diff" | head -20
        record_finding "$check_id" "HIGH" \
          "Skill/MCP files modified (${changed_count} differences)" \
          "Review changed skills carefully; re-install from official ClawHub if compromised"
        # Update baseline (after review)
        cp "$cur_skill_hash" "$base_skill_hash" 2>/dev/null || true
      fi
    else
      cp "$cur_skill_hash" "$base_skill_hash" 2>/dev/null || true
      echo_info "[${check_id}] First run: Skill/MCP baseline generated (${skill_file_count} files)"
      echo_finding "PASS" "$check_id" "Skill/MCP baseline initialized (${skill_file_count} files) ✓"
      record_finding "$check_id" "PASS" "Skill/MCP baseline initialization completed" ""
    fi
  else
    echo_finding "PASS" "$check_id" "No skills/mcp directory files found (no check needed) ✓"
    record_finding "$check_id" "PASS" "No Skill/MCP files" ""
  fi
}

# I9.5 Brain backup auto-sync
_check_dlp_brain_backup() {
  local check_id="I9.5"
  local OC="$1"
  local today
  today=$(date +%F)
  local backup_status="skip"

  if [[ ! -d "${OC}/.git" ]]; then
    echo_finding "LOW" "$check_id" \
      "\$OC directory has not initialized Git repository, brain backup unavailable" \
      "Initialize: cd ${OC} && git init && git remote add origin <private-repo-url>"
    record_finding "$check_id" "LOW" \
      "Brain backup not configured" \
      "Setup: cd ${OC} && git init && git remote add origin <private-repo-url>"
    return
  fi

  (
    cd "$OC" || exit 1
    git add . 2>/dev/null || true
    if git diff --cached --quiet 2>/dev/null; then
      backup_status="skip"
    else
      if git commit -m "🛡️ dejavu nightly brain backup (${today})" \
          --no-verify 2>/dev/null \
         && git push origin main 2>/dev/null; then
        backup_status="ok"
      else
        backup_status="fail"
      fi
    fi
    echo "$backup_status" > /tmp/dejavu_backup_status_$$
  ) || echo "fail" > /tmp/dejavu_backup_status_$$

  [[ -f /tmp/dejavu_backup_status_$$ ]] && \
    backup_status=$(cat /tmp/dejavu_backup_status_$$) && \
    rm -f /tmp/dejavu_backup_status_$$

  case "$backup_status" in
    ok)
      echo_finding "PASS" "$check_id" "Brain backup: incremental changes pushed to remote repository ✓"
      record_finding "$check_id" "PASS" "Brain backup successful" ""
      ;;
    skip)
      echo_finding "PASS" "$check_id" "Brain backup: no changes, push skipped ✓"
      record_finding "$check_id" "PASS" "Brain backup: no changes" ""
      ;;
    fail)
      echo_finding "LOW" "$check_id" \
        "Brain backup push failed (does not block this inspection)" \
        "Check remote repository permissions: git -C ${OC} remote -v ; git -C ${OC} push"
      record_finding "$check_id" "LOW" \
        "Brain backup push failed" \
        "Check remote repo access: git -C ${OC} remote -v"
      ;;
  esac
}
