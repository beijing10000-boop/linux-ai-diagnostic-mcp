# Linux AI Diagnostic MCP

Linux 诊断平台（开发中）：飞书 OAuth 登录、一次性初始化、加密设置、主机组、主机与代理资产管理、SSH 强制命令网关。

## 安全状态

**当前版本尚未完成端到端验证与安全审计，不可直接公网发布或连接生产 root 私钥。**
当前仅支持管理员 Open ID 登录。主机代理仍为资产登记，未实现代理任务转发；标准 MCP 服务仍在开发。

## 首次部署（内网测试）

```bash
git clone https://github.com/beijing10000-boop/linux-ai-diagnostic-mcp.git
cd linux-ai-diagnostic-mcp
mkdir -p data
sudo chown 10001:10001 data
chmod 700 data
docker compose up -d --build
docker compose exec web cat /app/data/bootstrap.token
```

当前服务只绑定 `127.0.0.1:8088`。通过受信任的 HTTPS 反向代理和受控网络访问首页，输入本机读取的一次性凭证，完成飞书 App ID、App Secret、管理员 Open ID（ou_...）和公网 HTTPS 地址初始化。飞书开发者后台必须配置精确回调：`https://域名/auth/feishu/callback`。

配置保存在 `data/inventory.db`，飞书密钥使用 `data/master.key` 加密。两者需要一起备份并严格控制访问权限。**不再要求手动填写 .env 业务配置。** 诊断 SSH 密钥和目标主机信任清单的 Web 管理尚未完成，当前不能通过 Web 配置诊断连接。

详情参见 [飞书配置](docs/FEISHU_SETUP.md)、[代理设计](docs/PROXY_DESIGN.md)。

## 诊断安全

root 不是只读账号。仅通过 SSH authorized_keys `restrict,command=` 将专用公钥绑定到受限网关，网关使用固定参数命令，不提供 Shell、文件传输或修改操作。需要完整的测试、日志脱敏、审计和凭据隔离后才能用于生产。
