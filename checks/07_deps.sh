#!/usr/bin/env bash
# ============================================================
#  CHECK MODULE 7: 依赖漏洞扫描
#  集成 npm audit + 自定义 toxic_skills 规则库
# ============================================================

run_deps_checks() {
  set_current_module "deps"
  echo_info "Scanning dependencies for known vulnerabilities..."

  _check_npm_audit
  _check_node_version
  _check_toxic_skills_db
  _check_skill_typosquatting
  _check_skill_update_anomaly
}

_check_npm_audit() {
  local check_id="D7.1"

  local pkg_json
  pkg_json=$(find "$OPENCLAW_DIR" -maxdepth 2 -name "package.json" \
    ! -path "*/node_modules/*" 2>/dev/null | head -1)

  # Fallback: look in openclaw global installation directory
  if [[ -z "$pkg_json" ]]; then
    local npm_root=""
    command -v npm &>/dev/null && npm_root=$(npm root -g 2>/dev/null || true)
    for loc in \
      "${OPENCLAW_PKG_JSON:+$(dirname "$OPENCLAW_PKG_JSON")}" \
      "${npm_root}/openclaw" \
      "/usr/lib/node_modules/openclaw" \
      "/usr/local/lib/node_modules/openclaw"; do
      if [[ -n "$loc" && -f "$loc/package.json" ]]; then
        pkg_json="$loc/package.json"
        break
      fi
    done
  fi

  if [[ -z "$pkg_json" ]]; then
    echo_skip "[${check_id}] No package.json found"
    echo_info "         Searched paths:"
    echo_info "           \$OPENCLAW_DIR         = ${OPENCLAW_DIR}"
    echo_info "           /usr/lib/node_modules/openclaw/package.json"
    echo_info "           /usr/local/lib/node_modules/openclaw/package.json"
    echo_info "         If openclaw is installed elsewhere, please set:"
    echo_info "           export OPENCLAW_PKG_JSON=/your/path/to/openclaw/package.json"
    return
  fi

  if ! command -v npm &>/dev/null; then
    echo_skip "[${check_id}] npm not available — install Node.js to enable dependency scanning"
    return
  fi

  echo_info "[${check_id}] Running npm audit..."
  local audit_output
  audit_output=$(cd "$(dirname "$pkg_json")" && npm audit --json 2>/dev/null || true)

  if [[ -z "$audit_output" ]]; then
    echo_skip "[${check_id}] npm audit returned no output"
    return
  fi

  local critical=0 high=0 moderate=0 low=0
  if command -v node &>/dev/null; then
    read -r critical high moderate low < <(
      echo "$audit_output" | node -e "
        let d=''; process.stdin.on('data',c=>d+=c);
        process.stdin.on('end',()=>{
          try {
            const r = JSON.parse(d);
            const v = r.metadata && r.metadata.vulnerabilities || {};
            console.log(
              (v.critical||0) + ' ' + (v.high||0) + ' ' +
              (v.moderate||0) + ' ' + (v.low||0)
            );
          } catch(e) { console.log('0 0 0 0'); }
        });
      " 2>/dev/null
    )
  else
    critical=$(echo "$audit_output" | grep -o '"critical":[0-9]*' | cut -d: -f2 | head -1 || echo "0")
    high=$(echo "$audit_output" | grep -o '"high":[0-9]*' | cut -d: -f2 | head -1 || echo "0")
  fi
  critical="${critical:-0}"; high="${high:-0}"
  moderate="${moderate:-0}"; low="${low:-0}"

  if [[ "$critical" -gt 0 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "npm audit: ${critical} CRITICAL vulnerabilities in dependencies"
    record_finding "$check_id" "CRITICAL" \
      "Critical npm vulnerabilities" \
      "Run: npm audit fix --force (review breaking changes first)"
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}cd $(dirname "$pkg_json") && npm audit fix${RESET}"
  elif [[ "$high" -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "npm audit: ${high} HIGH vulnerabilities in dependencies"
    record_finding "$check_id" "HIGH" \
      "High npm vulnerabilities" \
      "Run: npm audit fix"
  elif [[ $((moderate + low)) -gt 0 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "npm audit: ${moderate} moderate / ${low} low vulnerabilities"
    record_finding "$check_id" "MEDIUM" \
      "Moderate/low npm vulnerabilities" \
      "Run: npm audit and review findings"
  else
    echo_finding "PASS" "$check_id" "npm audit: No known vulnerabilities ✓"
    record_finding "$check_id" "PASS" "npm audit clean" ""
  fi
}

_check_node_version() {
  local check_id="D7.2"

  if ! command -v node &>/dev/null; then
    echo_skip "[${check_id}] Node.js not in PATH"
    return
  fi

  local node_ver
  node_ver=$(node --version 2>/dev/null | tr -d 'v')
  local major
  major=$(echo "$node_ver" | cut -d. -f1)

  # Bug Fix #39: v19 和 v21 是奇数非 LTS 版本，已于 2024 年 EOL，需单独列出（对齐 dejavu.ps1 Bug#27）
  if [[ "$major" -le 18 || "$major" -eq 19 || "$major" -eq 21 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Node.js v${node_ver} is END-OF-LIFE — no longer receives security patches"
    record_finding "$check_id" "HIGH" \
      "EOL Node.js version" \
      "Upgrade to Node.js v22 (LTS)"
    [[ "${FIX_MODE:-false}" == "true" ]] && \
      echo -e "         ${GREEN}${BOLD}FIX:${RESET} ${GREEN}nvm install 22 && nvm use 22${RESET}"
  elif [[ "$major" -eq 20 ]]; then
    echo_finding "MEDIUM" "$check_id" \
      "Node.js v${node_ver} reaches EOL April 2026 — upgrade soon"
    record_finding "$check_id" "MEDIUM" \
      "Node.js v20 approaching EOL" \
      "Plan upgrade to Node.js v22"
  else
    echo_finding "PASS" "$check_id" "Node.js v${node_ver} is supported ✓"
    record_finding "$check_id" "PASS" "Node.js version OK" ""
  fi
}

_check_toxic_skills_db() {
  local check_id="D7.3"
  local rules_file="${SCRIPT_DIR}/rules/toxic_skills.txt"

  if [[ ! -f "$rules_file" ]]; then
    echo_skip "[${check_id}] toxic_skills.txt not found — skipping malicious skill check"
    return
  fi

  [[ -z "${SKILLS_DIR:-}" ]] && { echo_skip "[${check_id}] No skills dir set, skipping"; return; }

  local hits=()
  while IFS= read -r signature; do
    [[ -z "$signature" || "$signature" == \#* ]] && continue
    local match
    match=$(grep -rl "$signature" "${SKILLS_DIR}" 2>/dev/null || true)
    [[ -n "$match" ]] && hits+=("${match#$OPENCLAW_DIR/} (matched: ${signature:0:50})")
  done < "$rules_file"

  if [[ ${#hits[@]} -gt 0 ]]; then
    echo_finding "CRITICAL" "$check_id" \
      "TOXIC SKILL SIGNATURE MATCHED in ${#hits[@]} skill(s)!"
    printf '         %s\n' "${hits[@]}" | head -5
    record_finding "$check_id" "CRITICAL" \
      "Known malicious skill signatures found" \
      "Immediately quarantine matching skills and audit agent memory for poisoning"
    if [[ "${FIX_MODE:-false}" == "true" ]]; then
      echo -e "         ${RED}${BOLD}QUARANTINE:${RESET}"
      for hit in "${hits[@]}"; do
        local fname
        fname=$(echo "$hit" | cut -d' ' -f1)
        echo -e "         ${GREEN}mv \"${OPENCLAW_DIR}/${fname}\" \"${OPENCLAW_DIR}/${fname}.quarantine\"${RESET}"
      done
    fi
  else
    echo_finding "PASS" "$check_id" "No known toxic skill signatures detected ✓"
    record_finding "$check_id" "PASS" "Toxic skills DB check OK" ""
  fi
}

_check_skill_typosquatting() {
  local check_id="D7.4"
  [[ -z "${SKILLS_DIR:-}" ]] && { echo_skip "[${check_id}] No skills dir, skipping"; return; }

  if ! command -v python3 &>/dev/null; then
    echo_skip "[${check_id}] python3 not available — skipping typosquatting check"
    return
  fi

  local legitimate_skills=(
    "web-search" "file-manager" "code-runner" "email-sender"
    "calendar" "browser-control" "screen-capture" "system-info"
    "git-helper" "docker-manager" "database-query" "api-tester"
  )

  local suspicious=()
  while IFS= read -r -d '' skill_dir; do
    local skill_name
    skill_name=$(basename "$skill_dir")
    for legit in "${legitimate_skills[@]}"; do
      local similar
      similar=$(python3 - <<EOF 2>/dev/null
def lev(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0] = i
    for j in range(n+1): dp[0][j] = j
    for i in range(1, m+1):
        for j in range(1, n+1):
            dp[i][j] = dp[i-1][j-1] if a[i-1]==b[j-1] else 1+min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1])
    return dp[m][n]
d = lev("${skill_name}", "${legit}")
if 0 < d <= 2:
    print("${skill_name} ~ ${legit} (distance=" + str(d) + ")")
EOF
)
      [[ -n "$similar" ]] && suspicious+=("$similar")
    done
  done < <(find "${SKILLS_DIR}" -maxdepth 1 -type d -print0 2>/dev/null)

  if [[ ${#suspicious[@]} -gt 0 ]]; then
    echo_finding "HIGH" "$check_id" \
      "Potential typosquatting skill names: ${#suspicious[@]} match(es)"
    printf '         %s\n' "${suspicious[@]}"
    record_finding "$check_id" "HIGH" \
      "Typosquatting skill names detected" \
      "Manually verify these skills are from trusted sources"
  else
    echo_finding "PASS" "$check_id" "No typosquatting skill names detected ✓"
    record_finding "$check_id" "PASS" "Skill names OK" ""
  fi
}

_check_skill_update_anomaly() {
  local check_id="D7.5"
  [[ -z "${SKILLS_DIR:-}" ]] && { echo_skip "[${check_id}] No skills dir, skipping"; return; }

  local recently_modified=()
  while IFS= read -r -d '' f; do
    recently_modified+=("${f#$OPENCLAW_DIR/}")
  done < <(find "${SKILLS_DIR}" -type f -mtime -7 -print0 2>/dev/null | head -20)

  if [[ ${#recently_modified[@]} -gt 0 ]]; then
    echo_finding "LOW" "$check_id" \
      "${#recently_modified[@]} skill file(s) modified in the last 7 days"
    printf '         %s\n' "${recently_modified[@]}" | head -5
    record_finding "$check_id" "LOW" \
      "Recently modified skills (${#recently_modified[@]} files)" \
      "Review recent skill updates, especially if auto-pulled from ClawHub"
  else
    echo_finding "PASS" "$check_id" "No anomalous skill updates detected ✓"
    record_finding "$check_id" "PASS" "Skill update anomaly OK" ""
  fi
}
