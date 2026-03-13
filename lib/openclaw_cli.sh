#!/usr/bin/env bash
# ============================================================
#  lib/openclaw_cli.sh — openclaw.mjs CLI 封装层
#  用于 Module 05/06 直连运行中实例
# ============================================================

# 自动探测 openclaw 可执行文件路径
detect_openclaw_bin() {
  local candidates=(
    "${OPENCLAW_DIR}/node_modules/.bin/openclaw"
    "${OPENCLAW_DIR}/openclaw.mjs"
    "$(command -v openclaw 2>/dev/null || echo '')"
    "$HOME/.local/bin/openclaw"
    "/usr/local/bin/openclaw"
  )
  for bin in "${candidates[@]}"; do
    if [[ -n "$bin" && ( -f "$bin" || -x "$bin" ) ]]; then
      echo "$bin"
      return 0
    fi
  done
  echo ""
}

# 调用 openclaw security audit（返回 JSON）
invoke_openclaw_audit() {
  local bin
  bin=$(detect_openclaw_bin)
  if [[ -z "$bin" ]]; then
    echo '{"error": "openclaw binary not found"}'
    return 1
  fi

  local result
  if [[ "$bin" == *.mjs ]]; then
    result=$(node "$bin" security audit --deep --output json 2>/dev/null \
      || echo '{"error":"cli_failed"}')
  else
    result=$("$bin" security audit --deep --output json 2>/dev/null \
      || echo '{"error":"cli_failed"}')
  fi
  echo "$result"
}

# 读取 openclaw.json（支持 JSON5 注释格式）
read_openclaw_config() {
  local config_path="${1:-}"

  local candidates=(
    "${OPENCLAW_DIR}/openclaw.json"
    "${OPENCLAW_DIR}/config/openclaw.json"
    # Bug Fix #37: 移除 $HOME/.openclaw 回退，避免扫描器静默切换至用户主目录配置
  )

  [[ -n "$config_path" ]] && candidates=("$config_path" "${candidates[@]}")

  for f in "${candidates[@]}"; do
    if [[ -f "$f" ]]; then
      export OPENCLAW_CONFIG_PATH="$f"
      if command -v node &>/dev/null; then
        node -e "
          const fs = require('fs');
          const txt = fs.readFileSync('$f','utf8')
            .replace(/(?<![:\/])\/\/[^\n]*/g,'')  // Bug Fix #38: 负向回顾，避免误删 URL 中的 ://
            .replace(/\/\*[\s\S]*?\*\//g,'');
          const clean = txt.replace(/,(\s*[}\]])/g, '\$1');
          try {
            console.log(JSON.stringify(JSON.parse(clean)));
          } catch(e) {
            console.log(JSON.stringify({parseError: e.message}));
          }
        " 2>/dev/null && return 0
      else
        cat "$f" && return 0
      fi
    fi
  done

  echo '{"error":"config_not_found"}'
  return 1
}

# 从解析后的 JSON 中提取字段
json_get() {
  local json="$1" key="$2"
  if command -v node &>/dev/null; then
    echo "$json" | node -e "
      let d=''; process.stdin.on('data',c=>d+=c);
      process.stdin.on('end',()=>{
        try { const v = JSON.parse(d); const k='${key}'.split('.');
          let r=v; for(let p of k) r=r&&r[p];
          console.log(r===undefined?'__UNDEFINED__':JSON.stringify(r));
        } catch(e) { console.log('__PARSE_ERR__'); }
      });
    " 2>/dev/null
  elif command -v python3 &>/dev/null; then
    echo "$json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
keys='${key}'.split('.')
r=d
for k in keys:
    r=r.get(k) if isinstance(r,dict) else None
print('__UNDEFINED__' if r is None else json.dumps(r))
    " 2>/dev/null
  else
    echo "__NO_PARSER__"
  fi
}
