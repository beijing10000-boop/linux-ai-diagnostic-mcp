# v0.1.0 内测部署与安全检查

## 前提
- Linux + Docker Engine / Docker Compose
- 内网 HTTP 使用服务器私有 IP；公网 HTTPS 使用域名与反向代理
- 飞书自建应用的 App ID、App Secret 和管理员 Open ID
- 目标主机 sshd 与 Python 3（`/usr/bin/python3`）

## 内网 HTTP（当前部署方式）

选择独立的 LAN 配置启动，不需要反向代理或证书：

```bash
mkdir -p data
sudo chown 10001:10001 data
sudo chmod 700 data
docker compose -f compose.lan.yaml up -d --build
docker compose -f compose.lan.yaml ps
docker compose -f compose.lan.yaml exec web cat /app/data/bootstrap.token
```

浏览器访问 `http://服务器内网IP:9099`。初始化填写同一访问地址、飞书应用凭据与管理员 Open ID；飞书安全设置添加精确回调 `http://服务器内网IP:9099/auth/feishu/callback`。

此配置发布 `0.0.0.0:9099`，网络上仅向受信任内网开放。HTTP 不加密传输。管理员会话与 OAuth 临时 Cookie 在 HTTP 下不设 Secure、保留 HttpOnly/SameSite=Lax；HTTPS 下恢复 Secure。Host、Origin、CSRF、管理员校验与 SSH 网关限制保持启用。

浏览器需可达该内网 IP；服务器需能访问 `open.feishu.cn:443` 的接口。回调由浏览器跳转完成，服务无需公网入站。复制功能在 HTTP 下自动使用兼容实现。

已有配置从 HTTPS 切换到 HTTP 时，应先在“系统设置”修改访问地址；变更会注销原会话。不要删除数据库或主密钥。

## 控制台配置顺序

1. 在“系统配置”选择 HTTP，填写内网 IP 与端口，核对飞书回调地址。飞书凭据、管理员与访问地址变化后需要重新登录。
2. 在“SSH 诊断凭据”保存专用 Ed25519 私钥。展开公钥与部署说明，复制诊断公钥，按下文将其以强制命令方式授权到目标端。
3. 在“主机与代理”登记主机组、目标主机和经可信渠道核验的主机公钥；使用跳板时先补齐代理的独立连接信息与凭据。
4. 在“连接调试”读取平台配置，选择测试主机，执行一次 CPU 查询。这会真实执行固定查询并记入诊断历史和审计。
5. 在“只读诊断台”执行所需查询，在“任务与审计”按状态或主机筛选、分页并回看结果。总览的任务统计可直接跳转至对应明细。

“配置完整”只表示字段与凭据准备情况；实际可达性以诊断结果为准。“重新读取”会清空当前未保存的配置输入。

## 与 zabbix-ai-ops 同机部署

两个项目放在各自的目录中，并分别启动 Compose。Zabbix AI Ops 使用 8088，本项目使用 9099；分别保留各自的数据目录、飞书应用配置与备份。按本项目的 `compose.lan.yaml` 启动即可，不需要修改 Zabbix 的容器或监听端口。若 Zabbix 的实际部署已改用 9099，应先为其中一个项目更换宿主机发布端口，并同步 Web 访问地址及飞书回调。

## 默认端口
Web 容器监听 **9099/TCP**。`compose.lan.yaml` 用于内网直连，发布 `0.0.0.0:9099`；默认 `compose.yaml` 仅发布 `127.0.0.1:9099`，用于 HTTPS 反向代理。后续日志、更新和重启请使用与启动相同的配置文件。

## 初始化
```bash
mkdir -p data
sudo chown 10001:10001 data
sudo chmod 700 data
docker compose up -d --build
docker compose ps
docker compose exec web cat /app/data/bootstrap.token
```
浏览器在受保护 HTTPS 地址打开首页，输入一次性 token、飞书应用 ID/Secret、管理员 Open ID、HTTPS Origin。完成后可使用飞书登录。密钥和 Token 永不粘贴到 GitHub 仓库。

## HTTPS 反向代理示例（Nginx）

将 `diag.example.com`、证书文件路径替换为真实值。以下是内测样例，公网部署前还需要 WAF / IP 限流 / 日志与监控：

```nginx
limit_req_zone $binary_remote_addr zone=diag_login:10m rate=10r/m;
server {
    listen 443 ssl;
    server_name diag.example.com;
    ssl_certificate     /etc/letsencrypt/live/diag.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/diag.example.com/privkey.pem;
    client_max_body_size 128k;
    location /auth/ {
        limit_req zone=diag_login burst=20 nodelay;
        proxy_pass http://127.0.0.1:9099;
        proxy_set_header Host $http_host;
    }
    location / {
        proxy_pass http://127.0.0.1:9099;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
```
对 `/setup` 还应限定 VPN/特定管理员来源 IP；初始化完成后可在反向代理层禁止它（应用层也拒绝第二次初始化）。本应用不从不受信任的 `X-Forwarded-*` 请求头决定授权状态。

## SSH 凭据、主机公钥
诊断服务建议单独创建 Ed25519 密钥，**不要使用现有的 Ansible 管理私钥**。在可信管理电脑上生成密钥并将私钥录入 Web 的“系统设置”，只将公钥部署到目标服务器 root `authorized_keys` 的强制命令条目。

目标端安装：
```bash
install -o root -g root -m 0755 gateway/ai-diagnostic-gateway /usr/local/sbin/ai-diagnostic-gateway
```
`authorized_keys` 中的 `from="DIAGNOSTIC_SERVER_IP"` 必须填写真正的诊断源地址。每台目标机须通过控制台/可信渠道读取并核验：
```bash
cat /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```
将经核验的公钥 `ssh-ed25519 AAAA...` 填入对应主机 Web 表单。不要只凭网络上抓到的 `ssh-keyscan` 返回值建立信任。

## 权限验证（必须）
- 使用对应专用 SSH 密钥，`ssh root@server cpu` 有正常读数。
- `ssh root@server 'id'` 应由网关拒绝；`ssh root@server 'reboot'` 应拒绝。
- 交互式 Shell、SCP、SFTP、SSH 端口转发必须无法使用。
- 未经核对或变更过主机公钥的连接必须失败。
- 普通访客打开 `/api/hosts`、`/api/diagnose` 必须收到 401。
- 修改资源需要有效飞书管理员会话、Origin 和 CSRF Token。

## 故障与备份
```bash
docker compose logs --tail 100 web
docker compose ps
```
需要 **同时备份** `data/master.key` 与 `data/inventory.db`，并设置受保护的备份权限。主密钥丢失将无法解密 App Secret 或 SSH 私钥。不要将 `data` 挂载为公开静态目录。

## 当前限制
- 支持一层 SSH 跳板代理，配置见 [跳板代理](PROXY_DESIGN.md)；不支持主动回连 Agent 与离线任务队列。
- MCP stdio 仅供可信 OS/容器操作者，未实现每个 AI 调用者的权限认证。
- 不提供 SSH 任意 Shell、文件读写、后台任务、外网主机访问。
- v0.1.0 不是生产安全合格声明。

## 现有安装升级

1. 维护窗口中备份数据库和原始 `master.key`，不要更换或删除主密钥。
2. 更新仓库代码后执行 `docker compose up -d --build`。
3. 启动会自动补齐旧代理的连接字段并创建诊断历史表；原有配置保留。
4. 在每台目标机重新安装更新后的 `gateway/ai-diagnostic-gateway`（root:root，0755）。
5. 登录 Web 核对 SSH 配置。旧版本登记的代理需要补齐 IP、公钥和专用私钥。
6. 在“连接调试”验证已授权测试主机，再执行 CPU / 内存等诊断，核对输出、历史与安全审计。内网 HTTP 安装的升级命令使用 `docker compose -f compose.lan.yaml up -d --build`。

诊断历史最多保存 500 次，输出与错误信息加密存储。诊断台默认展示最新 8 条；总览展示最新 6 条；“任务与审计”分页展示全部保留记录（每页 20 / 50 / 100 条）。`/api/runs` 继续返回最近 50 条摘要，`/api/activity` 提供分页筛选，完整输出由受保护的结果详情接口按需解密读取。主密钥缺失时应用拒绝启动，请恢复原始密钥。
