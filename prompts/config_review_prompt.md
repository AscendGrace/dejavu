# openclaw.json 安全配置专项审计 Prompt

## 角色定义
你是 OpenClaw AI 网关配置安全专家。请对提供的 `openclaw.json` 配置文件进行语义级安全审计，识别所有安全风险。

## 待审计配置

（将 openclaw.json 完整内容粘贴至此处）

```json
// 粘贴 openclaw.json 内容
```

## 审计维度

### 1. gateway 绑定与端口暴露
检查以下字段的安全语义：
- `gateway.bind`：是否为 `loopback`/`127.0.0.1`？若为 `0.0.0.0`/`lan`/`all` 则为高危
- `gateway.port`：端口是否为默认值 18789？是否有防火墙保护？
- `gateway.browserPort`：浏览器控制端口 18791 是否也绑定到回环？

### 2. 认证配置深度审查
- `gateway.auth.mode`：`none`=立即修复，`token`=检查强度，`trusted-proxy`=检查代理配置
- `gateway.auth.token`：
  - 长度是否 ≥40 个字符？
  - 是否为强随机十六进制？
  - 是否存在明显弱模式（重复字符、常见词）？
- `gateway.rateLimit`：是否配置了速率限制防暴力破解？

### 3. 命令控制面审查
- `gateway.nodes.denyCommands`：
  - 高危命令黑名单是否包含：`rm -rf`, `dd`, `mkfs`, `shutdown`, `reboot`?
  - 空数组意味着 AI Agent 可执行任意 shell 命令
- `trustedProxies`：是否限制了具体 IP？空数组在反代环境下允许 X-Forwarded-For 伪造

### 4. 多智能体/多 Agent 配置
- 是否有多个 Agent 配置？Agent 间的权限隔离是否充分？
- `agents[*].auth` 是否独立设置还是继承全局 token？
- paired devices 配置是否有过期机制？

### 5. 功能性危险配置
- `allowAll: true`：授予所有权限，高危
- `devMode: true`：开发模式可能禁用安全检查
- `skipAuth: true` / `disableSafety: true`：明显安全绕过
- MCP server 配置：是否有指向未知域名的 MCP 服务端？

## 输出格式

```markdown
## openclaw.json 安全审计结果

### 整体风险评级：[CRITICAL / HIGH / MEDIUM / LOW]

### 危险配置项
| 字段路径 | 当前值 | 风险 | 建议值 |
|---------|--------|------|--------|
| ...     | ...    | ...  | ...    |

### 详细分析

#### 认证配置
（分析）

#### 网络暴露
（分析）

#### 命令控制
（分析）

### 最小化安全配置模板
```json
{
  "gateway": {
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "<use: openssl rand -hex 32>"
    },
    "rateLimit": { "enabled": true, "max": 60, "windowMs": 60000 }
  }
}
```
```
