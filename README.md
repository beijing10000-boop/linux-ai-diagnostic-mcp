# Linux AI Diagnostic MCP

[![CI](https://github.com/beijing10000-boop/linux-ai-diagnostic-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/beijing10000-boop/linux-ai-diagnostic-mcp/actions/workflows/ci.yml)

**v0.1.0 · 内测基线** — 中文 Web、飞书 OAuth 管理员身份、SSH 限制诊断、主机组、代理资产管理、安全审计与本地 MCP stdio 工具。

> **安全提醒：当前版本未完成真实飞书租户/生产服务器的端到端验证，不允许直接公网开放 9099 或接入生产 root 密钥。** 分布式 Proxy Agent 尚未实现执行通道；上游 classfang 的任意 Shell / SFTP / Job 不开放。

## 核心功能

| 功能 | 状态 |
|---|---|
| 飞书 Open ID 管理员登录 / 首次初始化 | 实现基础功能，待真实应用验证 |
| 加密的 Web 配置 / SSH Ed25519 私钥 | 已实现 |
| 主机组 / 主机 / 代理管理 | 已实现；代理仅登记 |
| 只读 SSH 固定动作 / 强制命令 | 已实现；需目标端安装网关 |
| MCP 标准工具（stdio） | 已实现，本地受信任进程可运行 |
| 公网 MCP HTTP、SFTP、任意 Shell | 明确禁用 |
| 诊断审计、CSRF、Host / Origin 校验 | 已实现基础防护 |

## 本机内测

```bash
git clone https://github.com/beijing10000-boop/linux-ai-diagnostic-mcp.git
cd linux-ai-diagnostic-mcp
mkdir -p data
sudo chown 10001:10001 data
sudo chmod 700 data
docker compose up -d --build
docker compose exec web cat /app/data/bootstrap.token
```

默认 **9099**，仅绑定 `127.0.0.1:9099`。首次访问请在 **受限 HTTPS 反向代理/VPN** 下进行，凭本机一次性初始化凭证填写飞书 App ID、App Secret、管理员 Open ID（ou_...）和 HTTPS 域名。飞书应用中配置 `https://你的域名/auth/feishu/callback` 为回调地址。

页面：
- `/` 诊断工作台
- `/inventory` 主机与主机组、代理资产管理
- `/settings` 飞书、SSH 私钥、安全审计
- `/healthz` 非敏感健康与版本信息

应用凭据加密保存在 `data/inventory.db`；解密根密钥保存在 `data/master.key`（0600），必须安全备份且限制目录权限。**无需编辑任何 .env 文件。** 不要把 `data/` 提交到 GitHub，也不要将私钥写入 Compose 文件或 GitHub Actions Secrets 以外的公开资料。

## SSH 诊断网关

必须在每台目标 Linux 主机上以 root 安装 `gateway/ai-diagnostic-gateway` 为 `/usr/local/sbin/ai-diagnostic-gateway`，使用 root 拥有、0755 权限，并在 root `authorized_keys` 上为专用密钥添加：

```text
from="DIAGNOSTIC_SERVER_IP",restrict,command="/usr/local/sbin/ai-diagnostic-gateway" ssh-ed25519 YOUR_DIAGNOSTIC_PUBLIC_KEY ai-diagnostic
```

新建主机时填写可信渠道核验的 `/etc/ssh/ssh_host_ed25519_key.pub` 内容。默认只有 CPU、内存、磁盘、网络、网络连接、进程和指定服务状态等查询动作。**root 本身并不只读**，安全性取决于仅允许受限公钥、强制命令和网关审计；正式使用前务必验证不可启动 Shell/上传文件。

## MCP 本地接入

```bash
docker compose exec -T web python -m app.mcp_server
```

这是供可信内部进程启动的 MCP **stdio** 服务，提供 `list_linux_hosts` 和 `diagnose_linux_host`。标准 MCP HTTP 服务、跨机房代理任务通道及用户级 MCP 身份认证仍在规划，**不要直接向公网开放 stdio 包装服务**。

详见 [部署说明](docs/DEPLOYMENT.md)、[飞书认证](docs/FEISHU_SETUP.md)、[安全说明](SECURITY.md)、[更新日志](CHANGELOG.md)。
