# v0.1.0 内测部署与安全检查

## 前提
- Linux + Docker Engine / Docker Compose
- 测试域名与可信 HTTPS 反向代理（建议先在 VPN 内使用）
- 飞书自建应用的 App ID、App Secret 和管理员 Open ID
- 目标主机 sshd 与 Python 3（`/usr/bin/python3`）

## 默认端口
Web 容器监听 **9099/TCP**；Docker Compose 只发布在 **127.0.0.1:9099**，请勿改为 `0.0.0.0:9099` 直接暴露公网。

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
6. 在已授权测试主机上执行 CPU / 内存等诊断，核对输出、历史与安全审计。

诊断历史最多保存 500 次，输出与错误信息加密存储。Web 返回最近 50 条摘要，工作台默认展示最新 8 条。主密钥缺失时应用拒绝启动，请恢复原始密钥。
