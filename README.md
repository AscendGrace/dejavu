<div align="center">

<h1>🛡️ dejavu</h1>
<h3>Dejavu Security Baseline Checker</h3>

<p>
  <a href="#-快速开始"><img src="https://img.shields.io/badge/Quick%20Start-中文-blue?style=flat-square" alt="Quick Start"></a>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick%20Start-English-green?style=flat-square" alt="Quick Start EN"></a>
  <img src="https://img.shields.io/badge/version-2.0.0-orange?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell" alt="PowerShell">
  <img src="https://img.shields.io/badge/Bash-4.0%2B-green?style=flat-square&logo=gnubash" alt="Bash">
  <img src="https://img.shields.io/badge/English%20Only-%E2%9C%93-purple?style=flat-square" alt="English Only">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
</p>

<p><em>针对 OpenClaw AI 网关的零依赖安全配置基线检查工具<br>Zero-dependency security baseline checker for OpenClaw AI Gateway</em></p>


<p align="center">
  <img src="逮虾户LOGO.png" >
</p>
</div>

---

<!-- TOC -->
- [中文文档](#-中文文档)
  - [功能特性](#功能特性)
  - [系统要求](#系统要求)
  - [快速开始](#-快速开始)
  - [项目结构](#项目结构)
  - [检查模块详解](#检查模块详解)
  - [评分体系](#评分体系)
  - [退出码](#退出码)
  - [CI/CD 集成](#cicd-集成)
  - [AI 深度审计](#ai-深度审计)
  - [参与贡献](#参与贡献)
- [English Documentation](#-english-documentation)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Quick Start](#-quick-start)
  - [Project Structure](#project-structure)
  - [Check Modules](#check-modules)
  - [Scoring System](#scoring-system)
  - [Exit Codes](#exit-codes)
  - [CI/CD Integration](#cicd-integration)
  - [AI-Assisted Audit](#ai-assisted-audit)
  - [Contributing](#contributing)
  <!-- /TOC -->

---

# 🇨🇳 中文文档

## 功能特性

| 特性 | 说明 |
|------|------|
| 🔍 **9 大检查模块** | config · skills · network · proxy · runtime · auth · deps · hostaudit · dlp |
| 💻 **双平台支持** | Bash 4.0+（Linux/macOS）+ PowerShell 5.1+（Windows 10/11） |
| 🤖 **AI 深度审计** | 配套 3 套 LLM Prompt，扫描报告自动送入 AI 二次研判 |
| 📊 **量化评分** | 模块加权总评，100 分制，输出风险等级（LOW / MEDIUM / HIGH / CRITICAL） |
| 🔧 **自动修复** | `--fix` 模式一键修复低风险配置问题 |
| 📄 **多格式报告** | Markdown / JSON（支持 `jq` 格式化），自动保存至 `output/` |
| ⚙️ **CI/CD 友好** | 语义化退出码，开箱即用的 GitHub Actions 配置 |
| 🔧 **智能文件名** | JSON 报告自动处理文件名，避免重复扩展名 |
| 🚫 **零依赖** | 纯 Shell/PowerShell 实现，无需额外安装任何工具 |

---

## 系统要求

- **Linux / macOS**：Bash 4.0+，`jq`（可选，用于 JSON 美化格式化），Node.js（可选，用于 `npm audit`）
- **Windows**：PowerShell 5.1+（Windows 10/11 内置），Node.js（可选，用于依赖漏洞扫描）

---

## 🚀 快速开始

### Linux / macOS（Bash）

```bash
# 进入项目目录
cd dejavu-main

# ⚠️ 如果文件来自 Windows（CRLF 换行符），必须先转换，否则会报 "No such file or directory"
# 方法一：使用 dos2unix（推荐）
sudo apt-get install -y dos2unix && find . -name "*.sh" -exec dos2unix {} \;
# 方法二：无 dos2unix 时用 sed
find . -name "*.sh" -exec sed -i 's/\r//' {} \;

# ⚠️ 注意：参数格式更新为 --option（双横线）格式
# 旧格式 -d -c 等已废弃，请使用 --dir --checks 等新格式

# 授权执行
chmod +x dejavu.sh checks/*.sh lib/*.sh

# 全量检查（含运行时状态）
./dejavu.sh --dir /path/to/openclaw --runtime --verbose

# 仅检查指定模块
./dejavu.sh --dir /path/to/openclaw --checks network,auth,config

# 输出 Markdown 报告
./dejavu.sh --dir /path/to/openclaw --output markdown --report report.md

# 输出 JSON 报告（支持格式化输出）
./dejavu.sh --dir /path/to/openclaw --output json --report report.json

# 检查并自动修复低风险项
./dejavu.sh --dir /path/to/openclaw --fix

# 查看全部选项
./dejavu.sh --help
```

#### `--fix` 会修复的内容

`--fix` 是**干运行（dry-run）模式**：标有 ✅ 的项会直接执行变更，标有 💡 的项仅打印修复命令供参考，**不会自动执行**。

| 检查项 | 触发条件 | 修复动作 | 类型 |
|--------|----------|----------|---------|
| **C1.5** 配置文件权限 | `openclaw.json` 对 group/other 可读 | `chmod 600 openclaw.json` | ✅ 立即执行 |
| **C1.5a** world-writable 文件 | 项目内 `*.json`/`*.md` 文件全局可写 | `chmod o-w` 批量移除 write 位 | ✅ 立即执行 |
| **N3.1** 网关端口暴露 | 端口 18789 绑定到 `0.0.0.0` | 打印 `iptables -I INPUT -p tcp --dport 18789 -j DROP` | 💡 仅提示 |
| **R5.1** 未启用认证 | `gateway.auth.mode` 为 `none` 或未设置 | 打印配置修改建议：`"auth": {"mode": "token"}` | 💡 仅提示 |
| **R5.2** 网关绑定全接口 | `gateway.bind` 为 `0.0.0.0`/`all`/未设置 | 打印配置修改建议：`"bind": "loopback"` | 💡 仅提示 |
| **A6.1** Token 强度不足 | 认证 token 长度 < 32 字符 | 打印 `openssl rand -hex 32`（生成 256-bit token） | 💡 仅提示 |
| **D7.1** npm 高危依赖 | `npm audit` 存在 CRITICAL 漏洞 | 打印 `npm audit fix` 命令 | 💡 仅提示 |
| **D7.2** Node.js 版本过旧 | Node.js 版本 EOL（≤18、19、21） | 打印 `nvm install 22 && nvm use 22` | 💡 仅提示 |
| **D7.3** 恶意 skill 签名命中 | 命中 `rules/toxic_skills.txt` 中的已知恶意特征 | 打印 `mv skill.js skill.js.quarantine` 隔离命令 | 💡 仅提示 |
| **I9.3b** 配置文件权限（DLP） | `openclaw.json` 权限非 600 | `chmod 600 openclaw.json` | ✅ 立即执行 |

> **注意**：C1.3（硬编码密钥）、C1.4（SOUL.md 注入）、C1.6（危险标志）、N3.2（浏览器控制端口）等高风险项需要**人工审查**，`--fix` 不会自动处理。

> **常见问题**：若运行时出现 `line 1: #!/usr/bin/env bash: No such file or directory`，说明脚本含 Windows CRLF 换行符，执行上方 `dos2unix` 或 `sed` 命令修复后重试。

### 语言一致性

自 2.0.0 版本起，所有脚本使用**统一的英文输出**，以提供更好的国际化兼容性。之前中英混合的输出已统一为英文。所有运行时输出消息（包括检测日志、警告、错误和报告内容）均为英文，代码注释可能仍包含中文说明。

### Windows（PowerShell）

```powershell
# 进入项目目录
Set-Location .\dejavu-main

# 如需解除执行策略限制（仅当前会话）
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# ⚠️ 注意：参数格式更新为 --option（双横线）格式
# 旧格式 -Dir -Checks 等已废弃，请使用 --dir --checks 等新格式

# 全量检查
.\dejavu.ps1 --dir "C:\Users\you\.openclaw"

# 指定模块 + 详细输出
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --checks "config,network,auth" --showdetails

# 输出 Markdown 报告
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --output markdown --report .\report.md

# 输出 JSON 报告（支持格式化输出）
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --output json --report .\report.json

# 自动修复模式
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --fix

# 查看帮助
.\dejavu.ps1 --help
```

### 实际运行示例输出

```
  Security Baseline Checker v2.0.0 [PowerShell Edition]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [config] Configuration File Security
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] [C1.1] No hardcoded API keys or secrets detected
[SKIP] [C1.2] No SOUL.md found — skipping
[PASS] [C1.4] No world-writable config files found
[PASS] [C1.6] No dangerous configuration flags detected

  [auth] Authentication Strength
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] [A6.1] Auth token meets entropy requirements (>=40 hex chars)
[PASS] [A6.2] Token passes weak-pattern check
[PASS] [A6.3] auth.mode=token
[MEDI] [A6.5] No rate limiting configured on gateway

  Overall Score: 99/100  [████████████████████]
  Risk Level:    LOW RISK
  CRITICAL: 0  HIGH: 0  MEDIUM: 1
```

---

## 项目结构

```
dejavu/
├── dejavu.sh                    # 主入口（Bash / Linux / macOS）
├── dejavu.ps1                   # 主入口（PowerShell / Windows）
├── README.md                   # 本文档
│
├── checks/                     # 检查模块（Bash）
│   ├── 01_config.sh            #   配置文件安全
│   ├── 02_skills.sh            #   Skills 权限审计
│   ├── 03_network.sh           #   网络暴露分析
│   ├── 04_proxy.sh             #   反代配置检查
│   ├── 05_runtime.sh           #   运行时实例检查（需 --runtime）
│   ├── 06_auth.sh              #   认证强度检查
│   ├── 07_deps.sh              #   依赖漏洞扫描
│   ├── 08_hostaudit.sh         #   主机行为审计
│   └── 09_dlp.sh               #   数据泄露防护
│
├── lib/                        # 公共库
│   ├── color.sh                #   ANSI 颜色 + 输出函数
│   ├── score.sh                #   评分引擎（模块加权）
│   ├── openclaw_cli.sh         #   openclaw CLI 集成
│   └── report.sh               #   报告生成（Markdown / JSON）
│
├── rules/                      # 规则库
│   ├── toxic_skills.txt        #   已知恶意 skill 名单
│   ├── dangerous_patterns.json #   DLP 正则规则库
│   └── openclaw_schema.json    #   配置文件 JSON Schema
│
├── prompts/                    # AI 审计 Prompt
│   ├── audit_prompt.md         #   综合安全审计 Prompt
│   ├── config_review_prompt.md #   配置文件专项审查 Prompt
│   └── skill_chain_audit.md    #   Skills 链路审计 Prompt
│
├── ci/                         # CI/CD 集成
│   ├── github-actions.yml      #   GitHub Actions 工作流
│   └── pre-commit-hook.sh      #   Git 预提交钩子
│
└── output/                     # 报告输出（自动创建）
    └── dejavu_report_*.md       #   时间戳命名报告文件
```

---

## 检查模块详解

<details>
<summary><b>C — 配置文件安全（config）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| C1.1 | 硬编码 API Key / Secret（支持 OpenAI/Anthropic/GitHub/AWS 等格式） | CRITICAL |
| C1.2 | `SOUL.md` 提示注入检测（越权指令、越狱模式） | HIGH |
| C1.3 | 配置文件 ACL 安全（检测 Everyone 可写） | MEDIUM |
| C1.4 | 文件系统权限验证 | MEDIUM |
| C1.5 | JSON Schema 合规验证 | LOW |
| C1.6 | 危险配置标志（`allowAll`、`disableSafety`、`bypassAuth` 等） | HIGH |
| C1.7 | 环境变量注入风险 | MEDIUM |

</details>

<details>
<summary><b>S — Skills 权限审计（skills）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| S2.1 | Skill 权限最小化原则验证 | HIGH |
| S2.2 | SSRF 风险（URL 白名单缺失） | HIGH |
| S2.3 | 提示注入检测（系统 Prompt 劫持） | CRITICAL |
| S2.4 | 来源合法性验证（已知 toxic skill 名单比对） | HIGH |
| S2.5 | 校验和完整性验证 | MEDIUM |
| S2.6 | Skill 沙箱隔离检查 | MEDIUM |
| S2.7 | 跨 Skill 数据泄露风险 | MEDIUM |
| S2.8 | 外部命令执行权限审计 | HIGH |

</details>

<details>
<summary><b>N — 网络暴露分析（network）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| N3.1 | Gateway 端口绑定（检测 `0.0.0.0` 全网暴露） | CRITICAL |
| N3.2 | Browser control 端口隔离 | CRITICAL |
| N3.3 | TLS/HTTPS 强制配置 | HIGH |
| N3.4 | 对外可达性验证 | HIGH |
| N3.5 | CORS 配置（检测通配符 `*`） | HIGH |
| N3.6 | 防火墙规则检查（Windows: NetFirewallRule） | HIGH |
| N3.7 | 代理链端到端安全 | MEDIUM |

</details>

<details>
<summary><b>A — 认证强度检查（auth）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| A6.1 | Auth Token 熵值（要求 >= 40 hex chars） | CRITICAL |
| A6.2 | 弱 Token 模式检测（全零、重复字符等） | CRITICAL |
| A6.3 | `auth.mode` 配置验证（检测 `none`/`open`） | CRITICAL |
| A6.4 | Token 轮换策略 | MEDIUM |
| A6.5 | 速率限制配置 | MEDIUM |
| A6.6 | Session TTL 配置 | LOW |

</details>

<details>
<summary><b>D — 依赖漏洞扫描（deps）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| D7.1 | `npm audit` CVE 扫描 | CRITICAL/HIGH |
| D7.2 | Node.js 版本 EOL 检测 | HIGH/MEDIUM |
| D7.3 | 已知供应链恶意包检测 | HIGH |
| D7.4 | Typosquatting 相似包名检测 | MEDIUM |
| D7.5 | 锁定文件完整性验证 | MEDIUM |

</details>

<details>
<summary><b>H — 主机行为审计（hostaudit）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| H8.1 | 关键目录文件变更检测 | HIGH |
| H8.2 | 可疑 cron 任务审计 | HIGH |
| H8.3 | 登录失败事件统计 | MEDIUM |
| H8.4 | 异常外联连接检测 | HIGH |
| H8.5 | SUID/SGID 文件审计 | HIGH |
| H8.6 | 运行进程可疑行为分析 | MEDIUM |
| H8.7 | 系统日志完整性 | MEDIUM |
| H8.8 | 内核参数安全配置 | LOW |
| H8.9 | 用户账号特权审计 | HIGH |

</details>

<details>
<summary><b>I — 数据泄露防护（dlp）</b></summary>

| 检查项 | 说明 | 风险等级 |
|--------|------|---------|
| I9.1 | 私钥文件泄露检测（PEM/PFX/P12） | CRITICAL |
| I9.2 | 助记词 / 钱包种子短语检测 | CRITICAL |
| I9.3 | 文件哈希基线完整性验证 | HIGH |
| I9.4 | Brain / Memory 数据备份验证 | MEDIUM |
| I9.5 | 敏感字段加密状态检查 | MEDIUM |

</details>

---

## 评分体系

各模块按权重加权计算总评分（满分 100 分）：

| 模块 | 权重 | 说明 |
|------|------|------|
| skills | 20% | Skills 供应链是最大风险面 |
| network | 20% | 网络暴露直接影响攻击面 |
| config | 15% | 配置错误为高频漏洞来源 |
| proxy | 15% | 反代配置影响整体信任链 |
| deps | 10% | 依赖漏洞影响底层安全 |
| runtime | 10% | 运行时状态检查 |
| auth | 5% | 认证配置（与 token 质量相关） |
| hostaudit | 3% | 主机行为安全（仅 Bash） |
| dlp | 2% | 数据泄露防护（仅 Bash） |

**风险等级划分**：

| 分值范围 | 等级 | CI/CD 建议 |
|---------|------|-----------|
| 90–100 | ✅ LOW RISK | 允许自动部署 |
| 70–89 | ⚠️ MEDIUM RISK | 人工审核后部署 |
| 50–69 | ❌ HIGH RISK | 阻断部署 |
| 0–49 | 🚨 CRITICAL RISK | 立即阻断，通知安全团队 |

---

## 退出码

### Bash（`dejavu.sh`）

| 退出码 | 含义 | CI/CD 建议 |
|--------|------|-----------|
| `0` | 无 MEDIUM 及以上问题 | ✅ 允许部署 |
| `1` | 存在 MEDIUM 严重性问题 | ⚠️ 警告，人工确认 |
| `2` | 存在 HIGH 严重性问题 | ❌ 建议阻断 |
| `3` | 存在 CRITICAL 严重性问题 | 🚨 立即阻断 |

### PowerShell（`dejavu.ps1`）

| 退出码 | 含义 | CI/CD 建议 |
|--------|------|-----------|
| `0` | 全部通过，无 MEDIUM 及以上问题 | ✅ 允许部署 |
| `1` | 存在 MEDIUM 严重性问题 | ⚠️ 警告，人工确认 |
| `2` | 存在 HIGH 严重性问题 | ❌ 建议阻断 |
| `3` | 存在 CRITICAL 严重性问题 | 🚨 立即阻断 |

---

## CI/CD 集成

### GitHub Actions

将 `ci/github-actions.yml` 复制到 `.github/workflows/dejavu.yml`：

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-check:
    uses: ./.github/workflows/dejavu.yml
    with:
      openclaw-dir: ${{ github.workspace }}
```

### Git 预提交钩子

```bash
# 安装预提交钩子
cp ci/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 卸载钩子
rm .git/hooks/pre-commit
```

钩子将在每次 `git commit` 前自动运行 `config` 和 `auth` 快速扫描，阻断包含 CRITICAL 问题的提交。

---

## AI 深度审计

dejavu 提供 3 套配套 LLM Prompt，用于将扫描报告送入 AI 进行深度分析：

| Prompt 文件 | 用途 |
|-------------|------|
| `prompts/audit_prompt.md` | 综合安全审计，适用于完整报告 |
| `prompts/config_review_prompt.md` | 配置文件专项深度审查 |
| `prompts/skill_chain_audit.md` | Skills 供应链安全审计 |

**使用流程（Linux/macOS）**：

```bash
# 生成 Markdown 格式报告
./dejavu.sh --dir /path/to/openclaw --output markdown --report /tmp/dejavu_report.md

# 合并 Prompt + 报告，发送给 AI
cat prompts/audit_prompt.md /tmp/dejavu_report.md | pbcopy   # macOS
cat prompts/audit_prompt.md /tmp/dejavu_report.md | xclip    # Linux
```

**使用流程（Windows PowerShell）**：

```powershell
# 生成报告
.\dejavu.ps1 -Dir "C:\Users\you\.openclaw" -Output markdown -Report C:\temp\report.md

# 合并并复制到剪贴板
Get-Content prompts\audit_prompt.md, C:\temp\report.md | Set-Clipboard
```

---

## 参与贡献

欢迎提交 Issue 和 Pull Request！贡献前请注意：

1. **新增检查项**：在 `checks/` 目录对应模块的 `.sh` 文件中添加，并更新 `rules/` 中的规则文件
2. **新增 PowerShell 检查**：在 `dejavu.ps1` 的对应 `Invoke-*Checks` 函数中添加
3. **规则更新**：向 `rules/toxic_skills.txt` 或 `rules/dangerous_patterns.json` 提交已知危险规则
4. **提交前验证**：确保 `bash -n` 和 PowerShell `[scriptblock]::Create()` 均通过语法检查

---

## 许可证

[MIT License](LICENSE) © 2026 dejavu Contributors

---

# 🇬🇧 English Documentation

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **9 Check Modules** | config · skills · network · proxy · runtime · auth · deps · hostaudit · dlp |
| 💻 **Cross-Platform** | Bash 4.0+ (Linux/macOS) + PowerShell 5.1+ (Windows 10/11) |
| 🤖 **AI-Assisted Audit** | 3 bundled LLM prompts for AI-powered deep analysis |
| 📊 **Quantified Scoring** | Weighted module scoring, 100-point scale with risk levels |
| 🔧 **Auto-Fix Mode** | `--fix` flag for one-click remediation of low-risk issues |
| 📄 **Multi-Format Reports** | Markdown / JSON (with `jq` formatting support), auto-saved to `output/` |
| ⚙️ **CI/CD Ready** | Semantic exit codes + out-of-the-box GitHub Actions workflow |
| 🔧 **Smart Filenames** | JSON reports auto-handle filenames to prevent duplicate extensions |
| 🚫 **Zero Dependencies** | Pure Shell/PowerShell — no additional tools required |

---

## Requirements

- **Linux / macOS**: Bash 4.0+, `jq` (optional, for JSON pretty formatting), Node.js (optional, for `npm audit`)
- **Windows**: PowerShell 5.1+ (built-in on Windows 10/11), Node.js (optional)

---

## 🚀 Quick Start

### Linux / macOS (Bash)

```bash
cd dejavu-main

# ⚠️ If files were created/cloned on Windows, convert CRLF to LF first.
# Otherwise you will see: line 1: #!/usr/bin/env bash: No such file or directory
# Option 1: dos2unix (recommended)
sudo apt-get install -y dos2unix && find . -name "*.sh" -exec dos2unix {} \;
# Option 2: sed fallback
find . -name "*.sh" -exec sed -i 's/\r//' {} \;

# ⚠️ Note: Parameter format updated to --option (double-dash) format
# Old format -d -c etc. is deprecated, please use --dir --checks etc.

chmod +x dejavu.sh checks/*.sh lib/*.sh

# Full scan (including runtime checks)
./dejavu.sh --dir /path/to/openclaw --runtime --verbose

# Scan specific modules
./dejavu.sh --dir /path/to/openclaw --checks network,auth,config

# Export Markdown report
./dejavu.sh --dir /path/to/openclaw --output markdown --report report.md

# Export JSON report (with formatting support)
./dejavu.sh --dir /path/to/openclaw --output json --report report.json

# Auto-fix mode
./dejavu.sh --dir /path/to/openclaw --fix

./dejavu.sh --help
```

#### What `--fix` Remediates

`--fix` operates in **dry-run mode**: items marked ✅ are applied immediately; items marked 💡 only print the remediation command — **nothing is executed automatically**.

| Check | Trigger | Action | Type |
|-------|---------|--------|---------|
| **C1.5** Config file permissions | `openclaw.json` readable by group/others | `chmod 600 openclaw.json` | ✅ Applied |
| **C1.5a** World-writable files | `*.json`/`*.md` files in project are world-writable | `chmod o-w` bulk remove write bit | ✅ Applied |
| **N3.1** Gateway port exposed | Port 18789 bound to `0.0.0.0` | Print `iptables -I INPUT -p tcp --dport 18789 -j DROP` | 💡 Hint only |
| **R5.1** No authentication | `gateway.auth.mode` is `none` or unset | Print config suggestion: `"auth": {"mode": "token"}` | 💡 Hint only |
| **R5.2** Gateway on all interfaces | `gateway.bind` is `0.0.0.0`/`all`/unset | Print config suggestion: `"bind": "loopback"` | 💡 Hint only |
| **A6.1** Weak auth token | Token shorter than 32 characters | Print `openssl rand -hex 32` (256-bit token) | 💡 Hint only |
| **D7.1** Critical npm vulns | `npm audit` reports CRITICAL issues | Print `npm audit fix` command | 💡 Hint only |
| **D7.2** EOL Node.js | Node.js version is EOL (≤18, 19, or 21) | Print `nvm install 22 && nvm use 22` | 💡 Hint only |
| **D7.3** Toxic skill matched | Skill file matches `rules/toxic_skills.txt` | Print `mv skill.js skill.js.quarantine` quarantine command | 💡 Hint only |
| **I9.3b** Config permissions (DLP) | `openclaw.json` permissions are not 600 | `chmod 600 openclaw.json` | ✅ Applied |

> **Note**: High-risk findings such as C1.3 (hardcoded secrets), C1.4 (SOUL.md injection), C1.6 (dangerous flags), and N3.2 (browser control port) require **manual review** — `--fix` will not auto-remediate them.

> **Troubleshooting**: If you see `line 1: #!/usr/bin/env bash: No such file or directory`, run the `dos2unix` or `sed` command above to strip Windows CRLF line endings.

### Language Consistency

As of version 2.0.0, all scripts now use **consistent English output** for better international compatibility. Previous mixed Chinese/English output has been unified to English across all modules and error messages. All runtime output messages (including detection logs, warnings, errors, and report content) are in English. Code comments may still contain Chinese descriptions.

### Windows (PowerShell)

```powershell
Set-Location .\dejavu-main
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# ⚠️ Note: Parameter format updated to --option (double-dash) format
# Old format -Dir -Checks etc. is deprecated, please use --dir --checks etc.

# Full scan
.\dejavu.ps1 --dir "C:\Users\you\.openclaw"

# Specific modules with verbose output
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --checks "config,network,auth" --showdetails

# Export Markdown report
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --output markdown --report .\report.md

# Export JSON report (with formatting support)
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --output json --report .\report.json

# Auto-fix mode
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --fix

.\dejavu.ps1 --help
```

---

## Project Structure

```
dejavu/
├── dejavu.sh                    # Entry point (Bash / Linux / macOS)
├── dejavu.ps1                   # Entry point (PowerShell / Windows)
├── README.md
├── checks/
│   ├── 01_config.sh            # Configuration file security
│   ├── 02_skills.sh            # Skills permission audit
│   ├── 03_network.sh           # Network exposure analysis
│   ├── 04_proxy.sh             # Proxy/reverse-proxy audit
│   ├── 05_runtime.sh           # Live instance runtime checks
│   ├── 06_auth.sh              # Authentication strength
│   ├── 07_deps.sh              # Dependency vulnerability scan
│   ├── 08_hostaudit.sh         # Host behavior audit
│   └── 09_dlp.sh               # Data loss prevention
├── lib/
│   ├── color.sh
│   ├── score.sh                # Weighted scoring engine
│   ├── openclaw_cli.sh         # openclaw CLI integration
│   └── report.sh               # Report generation (MD/JSON)
├── rules/
│   ├── toxic_skills.txt        # Known malicious skill names
│   ├── dangerous_patterns.json # DLP regex rule library
│   └── openclaw_schema.json    # Config file JSON Schema
├── prompts/
│   ├── audit_prompt.md
│   ├── config_review_prompt.md
│   └── skill_chain_audit.md
├── ci/
│   ├── github-actions.yml
│   └── pre-commit-hook.sh
└── output/
    └── dejavu_report_*.md       # Timestamped report files
```

---

## Check Modules

| Module | Check IDs | Key Areas |
|--------|-----------|-----------|
| **config** | C1.1–C1.7 | Hardcoded credentials, SOUL.md injection, file permissions, dangerous flags |
| **skills** | S2.1–S2.8 | Least-privilege, SSRF, prompt injection, source verification, checksums |
| **network** | N3.1–N3.7 | Port binding, public exposure, TLS, CORS, firewall rules |
| **proxy** | P4.1–P4.6 | trustedProxies, X-Forwarded-For, security headers |
| **runtime** | R5.1–R5.9 | auth_mode, denyCommands, paired_devices, session_ttl |
| **auth** | A6.1–A6.6 | Token entropy, leaked token detection, weak patterns, rotation policy |
| **deps** | D7.1–D7.5 | npm audit CVEs, Node.js EOL, poisoned packages, typosquatting |
| **hostaudit** | H8.1–H8.9 | File changes, suspicious cron jobs, login failures, outbound anomalies |
| **dlp** | I9.1–I9.5 | Private key leakage, mnemonic phrases, file hash baseline, Brain backup |

---

## Scoring System

| Module | Weight | Rationale |
|--------|--------|-----------|
| skills | 20% | Skills supply chain: largest attack surface |
| network | 20% | Network exposure directly determines reachability |
| config | 15% | Misconfiguration is the most common vulnerability source |
| proxy | 15% | Proxy config impacts the entire trust chain |
| deps | 10% | Dependency vulnerabilities affect the underlying runtime |
| runtime | 10% | Real-time instance state monitoring |
| auth | 5% | Authentication quality (correlated with token strength) |
| hostaudit | 3% | Host-level security posture (Bash only) |
| dlp | 2% | Data loss prevention baseline (Bash only) |

**Risk Levels**:

| Score Range | Level | CI/CD Action |
|-------------|-------|-------------|
| 90–100 | ✅ LOW RISK | Allow automated deployment |
| 70–89 | ⚠️ MEDIUM RISK | Manual review before deployment |
| 50–69 | ❌ HIGH RISK | Block deployment |
| 0–49 | 🚨 CRITICAL RISK | Immediate block + notify security team |

---

## Exit Codes

### Bash (`dejavu.sh`)

| Code | Meaning | CI/CD Action |
|------|---------|-------------|
| `0` | No MEDIUM or above issues | ✅ Allow deployment |
| `1` | MEDIUM severity findings present | ⚠️ Warning, manual confirmation |
| `2` | HIGH severity findings present | ❌ Recommend blocking |
| `3` | CRITICAL severity findings present | 🚨 Immediate block |

### PowerShell (`dejavu.ps1`)

| Code | Meaning | CI/CD Action |
|------|---------|-------------|
| `0` | All checks passed, no MEDIUM+ issues | ✅ Allow deployment |
| `1` | MEDIUM severity findings present | ⚠️ Warning, manual confirmation |
| `2` | HIGH severity findings present | ❌ Recommend blocking |
| `3` | CRITICAL severity findings present | 🚨 Immediate block |

---

## CI/CD Integration

### GitHub Actions

Copy `ci/github-actions.yml` to `.github/workflows/dejavu.yml`:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-check:
    uses: ./.github/workflows/dejavu.yml
    with:
      openclaw-dir: ${{ github.workspace }}
```

### Git Pre-commit Hook

```bash
cp ci/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Uninstall
rm .git/hooks/pre-commit
```

---

## AI-Assisted Audit

| Prompt File | Purpose |
|-------------|---------|
| `prompts/audit_prompt.md` | Full security audit, suitable for complete reports |
| `prompts/config_review_prompt.md` | Deep-dive config file security review |
| `prompts/skill_chain_audit.md` | Skills supply chain security analysis |

**Workflow (Linux/macOS)**:

```bash
./dejavu.sh --dir /path/to/openclaw --output markdown --report /tmp/dejavu_report.md
cat prompts/audit_prompt.md /tmp/dejavu_report.md | pbcopy   # macOS
cat prompts/audit_prompt.md /tmp/dejavu_report.md | xclip    # Linux
```

**Workflow (Windows PowerShell)**:

```powershell
.\dejavu.ps1 --dir "C:\Users\you\.openclaw" --output markdown --report C:\temp\report.md
Get-Content prompts\audit_prompt.md, C:\temp\report.md | Set-Clipboard
```

---

## Contributing

1. **Adding check items**: Add to the corresponding `.sh` module in `checks/`, update rule files in `rules/`
2. **PowerShell checks**: Add within the appropriate `Invoke-*Checks` function in `dejavu.ps1`
3. **Rule updates**: Submit known-malicious entries to `rules/toxic_skills.txt` or `rules/dangerous_patterns.json`
4. **Before submitting**: Verify syntax with `bash -n` (Bash) and `[scriptblock]::Create()` (PowerShell)

---

## License

[MIT License](LICENSE) © 2026 dejavu Contributors

---

<div align="center">
<sub>Built for the OpenClaw AI Gateway ecosystem · Designed with security-first principles</sub>
</div>
