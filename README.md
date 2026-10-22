# Linux AI Diagnostic MCP

自建 Linux SSH 只读诊断平台（初始开发版本）。

## 功能
- FastAPI 诊断 API 与中文 Web 控制台
- SSH 主机白名单、严格主机密钥校验、专用密钥
- root 公钥强制命令网关；不向 AI 开放 root Shell
- CPU、内存、磁盘、网络、进程和服务状态查询

## 安全边界
**root 不是只读账号。** 本项目通过 SSH authorized_keys 的 `restrict,command=` 限制特定公钥的执行入口。不要给诊断密钥额外的 root 登录权限。不要开放 SCP/SFTP、端口转发、任意 shell。项目仍需独立安全审计后才能生产使用。

## 目标服务器
安装 `gateway/ai-diagnostic-gateway` 至 `/usr/local/sbin/ai-diagnostic-gateway`，root 拥有，权限 0755。将 MCP 专用公钥添加到 root 的 authorized_keys（替换占位符）：

```text
from="MCP_SERVER_IP",restrict,command="/usr/local/sbin/ai-diagnostic-gateway" ssh-ed25519 YOUR_PUBLIC_KEY diagnostic-mcp
```

强制命令通过 `SSH_ORIGINAL_COMMAND` 选择固定诊断动作。建议在 sshd 中限制该专用来源和密钥，并保留现有管理员连接进行验证。

## Web 部署
复制 `.env.example` 为 `.env`，填写真实的授权主机 IP、密钥路径和高强度 API Token。准备 `secrets/diagnostic_key` 和 `secrets/known_hosts`（需核对 SSH 主机指纹）。然后执行：

```bash
docker compose up -d --build
```

Web 绑定在本机 127.0.0.1:8088，建议经 HTTPS 反向代理和访问控制后使用。API Token 当前由用户手动输入，不持久化到浏览器存储。

## 状态
这是第一阶段基础实现，**不是已完成的生产级 MCP 系统**。尚需添加 MCP 标准工具服务、用户权限、审计存储、日志脱敏、异步任务、实时图表、测试与安全加固。不要直接接入生产 root 密钥。
