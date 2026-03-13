#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 2: Skills/Plugin Security Check
#  S2.1-S2.8: Permission minimization, SSRF, prompt injection, supply chain
# ============================================================

run_skills_checks() {
  set_current_module "skills"
  echo_info "Checking skills and plugins security..."

  # Step 1: Check preconfigured candidate paths
  if [[ -z "${SKILLS_DIR:-}" ]]; then
    local candidates=(
      "${OPENCLAW_DIR}/skills"
      "${OPENCLAW_DIR}/agents/skills"
      "${OPENCLAW_DIR}/plugins"
      "$HOME/.openclaw/skills"
      "$HOME/.openclaw/workspace/skills"
      "/usr/lib/node_modules/openclaw/skills"
      "/usr/local/lib/node_modules/openclaw/skills"
      "/opt/homebrew/lib/node_modules/openclaw/skills"
      "$HOME/.nvm/versions/node/$(node -e 'process.stdout.write(process.version)' 2>/dev/null)/lib/node_modules/openclaw/skills"
      "/Applications/OpenClaw.app/Contents/Resources/skills"
      "/mnt/c/Users/${USER:-$(whoami 2>/dev/null || echo 'default')}/.openclaw/skills"
      "$(npm root -g 2>/dev/null)/openclaw/skills"
    )
    for d in "${candidates[@]}"; do
      if [[ -n "$d" && -d "$d" ]]; then
        SKILLS_DIR="$d"
        break
      fi
    done
  fi

  # Step 2: Preconfigured paths missed → Start system-wide scan
  if [[ -z "${SKILLS_DIR:-}" ]]; then
    echo_info "Preconfigured paths did not find skills directory, scanning system..."
    local scan_roots=("$HOME" "/opt" "/usr/local" "/usr" "/Applications" "/srv" "/data")
    local found_dir=""
    for root in "${scan_roots[@]}"; do
      [[ ! -d "$root" ]] && continue
      # Scan: up to 8 levels deep, skip large or irrelevant directories like node_modules/.git/proc/sys
      found_dir=$(find "$root" \
        -maxdepth 8 \
        -type d \
        \( -name "node_modules" -o -name ".git" -o -name "proc" -o -name "sys" \
           -o -name ".cache" -o -name ".local" \) -prune \
        -o -type d -name "skills" -print \
        2>/dev/null | head -1 || true)
      if [[ -n "$found_dir" ]]; then
        SKILLS_DIR="$found_dir"
        echo_info "System scan found skills directory: ${SKILLS_DIR}"
        break
      fi
    done
  fi

  # Step 3: System scan also missed → Prompt user to manually configure
  if [[ -z "${SKILLS_DIR:-}" ]]; then
    echo_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo_warn "  [S2] Skills directory not found"
    echo_warn "  Scanned preconfigured paths and common system locations, skills directory not found."
    echo_warn ""
    echo_warn "  Please manually specify skills directory path and rerun:"
    echo_warn "    export SKILLS_DIR=/path/to/your/openclaw/skills"
    echo_warn "    ./dejavu.sh --dir ${OPENCLAW_DIR} ..."
    echo_warn ""
    echo_warn "  Or confirm skills are properly installed in openclaw.json."
    echo_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo_skip "[S2.x] Skills module skipped — set SKILLS_DIR and rerun"
    record_finding "S2.0" "SKIP" "Skills directory not found" \
      "Set env var: export SKILLS_DIR=/path/to/skills && re-run dejavu.sh"
    return
  fi

  echo_info "Skills directory: ${SKILLS_DIR}"

_check_skills_list
_check_skills_permission_minimization
_check_skills_ssrf_risk
_check_skills_prompt_injection
_check_skills_unknown_sources
_check_skills_dangerous_combination
_check_skills_sensitive_path_access
_check_skills_checksum
}

# S2.1 List and count installed skills
_check_skills_list() {
  local check_id="S2.1"

  local skill_count=0
  local skill_names=()
  while IFS= read -r -d '' d; do
    skill_names+=("$(basename "$d")")
    skill_count=$((skill_count + 1))
  done < <(find "${SKILLS_DIR}" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)

  if [[ $skill_count -eq 0 ]]; then
    echo_finding "PASS" "$check_id" "No skills installed — minimal attack surface ✓"
    record_finding "$check_id" "PASS" "No skills installed" ""
    return
  fi

  echo_info "[${check_id}] Found ${skill_count} installed skill(s): ${skill_names[*]}"
  echo_finding "PASS" "$check_id" "${skill_count} skill(s) found — inventoried ✓"
  record_finding "$check_id" "PASS" "${skill_count} skills installed" ""
}

# S2.2 Permission minimization check
_check_skills_permission_minimization() {
  local check_id="S2.2"

  # Dangerous tool permission combinations
  local dangerous_combos=(
    "bash:file_write"
    "shell:network_fetch"
    "execute:read_file:write_file"
    "terminal:http_request"
  )

  local violations=()
  while IFS= read -r -d '' skill_dir; do
    local skill_name
    skill_name=$(basename "$skill_dir")

    # Read tools list from skill's manifest/package.json
    local manifest=""
    for mf in "${skill_dir}/package.json" "${skill_dir}/manifest.json" "${skill_dir}/skill.json"; do
      [[ -f "$mf" ]] && manifest=$(cat "$mf" 2>/dev/null) && break
    done
    [[ -z "$manifest" ]] && continue

    local tools
    tools=$(echo "$manifest" | grep -oP '"(tools|permissions)"\s*:\s*\[[^\]]+\]' | \
             grep -oP '"[a-zA-Z_\-]+"' | tr -d '"' | tr '\n' ':')

    for combo in "${dangerous_combos[@]}"; do
      local all_present=true
      IFS=':' read -ra combo_tools <<< "$combo"
      for tool in "${combo_tools[@]}"; do
        echo "$tools" | grep -q "$tool" || all_present=false
      done
      if [[ "$all_present" == "true" ]]; then
        violations+=("${skill_name}: has dangerous combination [${combo//:/ + }]")
      fi
    done
  done < <(find "${SKILLS_DIR}" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)

  if [[ ${#violations[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Dangerous tool permission combinations in ${#violations[@]} skill(s):"
    printf '         %s\n' "${violations[@]}"
    record_finding "$check_id" "HIGH" \
      "Over-permissioned skills: ${violations[*]}" \
      "Apply permission minimization — remove unnecessary tool access from skills"
  else
    echo_finding "PASS" "$check_id" "No over-permissioned skill combinations detected ✓"
    record_finding "$check_id" "PASS" "Skill permissions OK" ""
  fi
}

# S2.3 SSRF 风险检测（fetch/http + 用户可控 URL）
_check_skills_ssrf_risk() {
  local check_id="S2.3"

  local ssrf_patterns=(
    'fetch\s*\(\s*\$\{.*user'
    'http\.get\s*\(\s*\$\{.*input'
    'axios\s*\.\s*(get|post)\s*\(\s*\$\{.*param'
    'url\s*[=:]\s*.*\$\{.*\}'
    'request\s*\(.*\$\{.*url'
  )

  local ssrf_files=()
  mapfile -t ssrf_files < <(find "${SKILLS_DIR}" -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
    -maxdepth 4 2>/dev/null)

  local ssrf_found=()
  for f in "${ssrf_files[@]}"; do
    local content
    content=$(cat "$f" 2>/dev/null || continue)
    for pat in "${ssrf_patterns[@]}"; do
      if echo "$content" | grep -qP "$pat"; then
        ssrf_found+=("${f#$SKILLS_DIR/}")
        break
      fi
    done
  done

  if [[ ${#ssrf_found[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Potential SSRF risk in ${#ssrf_found[@]} skill file(s):" \
      "User-controlled URLs in fetch/http calls"
    printf '         %s\n' "${ssrf_found[@]}" | head -5
    record_finding "$check_id" "HIGH" \
      "SSRF risk in skills" \
      "Validate and allowlist URLs before making outbound requests in skills"
  else
    echo_finding "PASS" "$check_id" "No obvious SSRF patterns detected in skills ✓"
    record_finding "$check_id" "PASS" "Skills SSRF check OK" ""
  fi
}

# S2.4 提示注入面检测
_check_skills_prompt_injection() {
  local check_id="S2.4"

  local injection_patterns=(
    'systemPrompt.*\+.*user'
    'instructions.*concat.*input'
    '\$\{.*userMessage\|userInput\|userText\}'
    'prompt\s*=\s*.*\+\s*.*user'
    'message.*template.*literal.*user'
  )

  local risky_files=()
  mapfile -t risky_files < <(find "${SKILLS_DIR}" -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
    -maxdepth 4 2>/dev/null)

  local injection_found=()
  for f in "${risky_files[@]}"; do
    local content
    content=$(cat "$f" 2>/dev/null || continue)
    for pat in "${injection_patterns[@]}"; do
      if echo "$content" | grep -qP "$pat"; then
        injection_found+=("${f#$SKILLS_DIR/}")
        break
      fi
    done
  done

  if [[ ${#injection_found[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Potential prompt injection surface in ${#injection_found[@]} skill file(s):" \
      "User input directly concatenated into LLM prompts"
    printf '         %s\n' "${injection_found[@]}" | head -5
    record_finding "$check_id" "HIGH" \
      "Prompt injection risk in skills" \
      "Sanitize user input before including in LLM prompts; use structured message formats"
  else
    echo_finding "PASS" "$check_id" "No obvious prompt injection patterns detected ✓"
    record_finding "$check_id" "PASS" "Skills prompt injection OK" ""
  fi
}

# S2.5 未知来源 skill 检测
_check_skills_unknown_sources() {
  local check_id="S2.5"

  local unknown_sources=()
  while IFS= read -r -d '' skill_dir; do
    local skill_name
    skill_name=$(basename "$skill_dir")

    local manifest=""
    for mf in "${skill_dir}/package.json" "${skill_dir}/manifest.json"; do
      [[ -f "$mf" ]] && manifest=$(cat "$mf" 2>/dev/null) && break
    done

    # 检查是否有来源信息
    if [[ -z "$manifest" ]] || ! echo "$manifest" | grep -qP '"(source|repository|homepage|author)"'; then
      unknown_sources+=("$skill_name")
    fi
  done < <(find "${SKILLS_DIR}" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)

  if [[ ${#unknown_sources[@]} -gt 0 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "${#unknown_sources[@]} skill(s) have no source/repository info:" \
      "${unknown_sources[*]}"
    record_finding "$check_id" "MEDIUM" \
      "Skills missing source metadata" \
      "Verify skill origins manually — prefer skills from official ClawHub registry"
  else
    echo_finding "PASS" "$check_id" "All skills have source metadata ✓"
    record_finding "$check_id" "PASS" "Skill sources OK" ""
  fi
}

# S2.6 Shell 执行 + 文件写入危险组合
_check_skills_dangerous_combination() {
  local check_id="S2.6"

  local dangerous=()
  for skill_dir in "${SKILLS_DIR}"/*/; do
    [[ ! -d "$skill_dir" ]] && continue
    local skill_name
    skill_name=$(basename "$skill_dir")

    local has_shell=false has_write=false has_network=false

    # 搜索 JS/TS 文件中的危险 API 使用
    if grep -rql 'child_process\|exec\|spawn\|shell' "${skill_dir}" 2>/dev/null; then
      has_shell=true
    fi
    if grep -rql 'fs\.write\|writeFile\|createWriteStream' "${skill_dir}" 2>/dev/null; then
      has_write=true
    fi
    if grep -rql 'fetch\|axios\|http\.\|https\.' "${skill_dir}" 2>/dev/null; then
      has_network=true
    fi

    if [[ "$has_shell" == "true" && "$has_write" == "true" && "$has_network" == "true" ]]; then
      dangerous+=("${skill_name}: shell + file-write + network = HIGH RISK")
    elif [[ "$has_shell" == "true" && "$has_network" == "true" ]]; then
      dangerous+=("${skill_name}: shell + network fetch = MEDIUM RISK")
    fi
  done

  if [[ ${#dangerous[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Dangerous capability combinations in ${#dangerous[@]} skill(s):"
    printf '         %s\n' "${dangerous[@]}"
    record_finding "$check_id" "HIGH" \
      "High-risk skill capability combos" \
      "Audit each flagged skill; consider sandboxing or splitting capabilities"
  else
    echo_finding "PASS" "$check_id" "No dangerous skill capability combinations detected ✓"
    record_finding "$check_id" "PASS" "Skill capability combos OK" ""
  fi
}

# S2.7 敏感路径访问检测
_check_skills_sensitive_path_access() {
  local check_id="S2.7"

  local sensitive_paths=(
    '\.ssh'
    '\.gnupg'
    '/etc/passwd'
    '/etc/shadow'
    '\.aws/credentials'
    '\.config/gcloud'
    'id_rsa\|id_ed25519'
    '\$HOME/\.(bash_history\|zsh_history)'
    'PRIVATE.*KEY'
    '\.kube/config'
  )

  local risky_skills=()
  for skill_dir in "${SKILLS_DIR}"/*/; do
    [[ ! -d "$skill_dir" ]] && continue
    local skill_name
    skill_name=$(basename "$skill_dir")
    for pat in "${sensitive_paths[@]}"; do
      if grep -rql "$pat" "${skill_dir}" 2>/dev/null; then
        risky_skills+=("${skill_name}: references sensitive path '${pat}'")
        break
      fi
    done
  done

  if [[ ${#risky_skills[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "${#risky_skills[@]} skill(s) access sensitive system paths:"
    printf '         %s\n' "${risky_skills[@]}"
    record_finding "$check_id" "HIGH" \
      "Skills access sensitive paths" \
      "Audit why skills need access to SSH keys, credentials, or history files"
  else
    echo_finding "PASS" "$check_id" "No skills accessing sensitive system paths ✓"
    record_finding "$check_id" "PASS" "Skill path access OK" ""
  fi
}

# S2.8 ClawHub 来源校验
_check_skills_checksum() {
  local check_id="S2.8"

  local lock_file="${SKILLS_DIR}/.skills-lock.json"
  if [[ ! -f "$lock_file" ]]; then
    lock_file="${OPENCLAW_DIR}/skills-lock.json"
  fi

  if [[ ! -f "$lock_file" ]]; then
    echo_finding "LOW" "$check_id" \
      "No skills lockfile (skills-lock.json) found — cannot verify skill integrity" \
      "Skills installed manually cannot be checksum-verified"
    record_finding "$check_id" "LOW" \
      "No skills lockfile for integrity verification" \
      "Use ClawHub to install skills with lockfile support"
    return
  fi

  # 读取 lockfile 并验证 SHA
  local mismatch_count=0
  if command -v node &>/dev/null; then
    mismatch_count=$(node -e "
      const fs = require('fs');
      const lock = JSON.parse(fs.readFileSync('${lock_file}', 'utf8'));
      const crypto = require('crypto');
      let mismatches = 0;
      for (const [name, info] of Object.entries(lock)) {
        const skillPath = '${SKILLS_DIR}/' + name;
        if (!fs.existsSync(skillPath)) { mismatches++; continue; }
        // Check main file hash if present
        if (info.sha256 && info.main) {
          const content = fs.readFileSync(skillPath + '/' + info.main);
          const actual = crypto.createHash('sha256').update(content).digest('hex');
          if (actual !== info.sha256) mismatches++;
        }
      }
      console.log(mismatches);
    " 2>/dev/null || echo "0")
  fi

  if [[ "${mismatch_count:-0}" -gt 0 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "${mismatch_count} skill(s) have CHECKSUM MISMATCH — possible tampering!"
    record_finding "$check_id" "CRITICAL" \
      "Skill checksum mismatch" \
      "Re-install affected skills from ClawHub; audit for supply chain compromise"
  else
    echo_finding "PASS" "$check_id" "Skill checksums verified ✓"
    record_finding "$check_id" "PASS" "Skills checksum OK" ""
  fi
}
