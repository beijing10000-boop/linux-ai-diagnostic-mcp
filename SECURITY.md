# 安全说明

本项目涉及 root SSH 诊断。**root 不具有真正的只读权限**，通过 authorized_keys 强制命令网关来收窄这把专用公钥的操作能力。

## v0.1.0 已实施
- 飞书管理员 Open ID 授权、会话服务端存储、HttpOnly/SameSite Cookie；HTTPS 下启用 Secure，受信任内网 HTTP 下不启用 Secure。
- 浏览器绑定 OAuth state；管理操作 CSRF Token + Origin；HTTP/HTTPS 均校验 Host。
- 管理接口不提供未经认证的诊断调用；MCP 只开放本地 stdio 入口。
- 私有 IP 目标、单独 SSH Ed25519 私钥、公钥固定、固定动作白名单。
- 主密钥保护、密文设置与诊断历史、代理私钥不回显、日志不输出私钥、成功/失败诊断统一审计。
- 修改访问域名时原子保存配置并撤销会话及未消费的 OAuth state；无变化的设置不强制退出。
- 主密钥丢失时拒绝初始化替代密钥，防止现有数据库无法解密。
- Docker 非 root、只读根文件系统、无附加 Linux capabilities。

## 部署前必须执行
- 在目标 Linux 上验证 root 公钥 ForceCommand 生效，且无法登录交互式 shell、不能执行其他命令、不能使用 SFTP。
- 校验 SSH 公钥指纹由可信渠道提供，不能仅信任 ssh-keyscan 返回值。
- 按访问范围选择受信任内网 HTTP 或 HTTPS 反向代理，限制初始化访问源，并备份主密钥和数据库。应用已有限流，反向代理可增加入口限流。
- 审计飞书应用配置和域名回调，检查 SSH 网关代码及权限，完成真实端到端测试。
- 设置 GitHub 仓库 Private 或确保绝不提交敏感凭据。
- 对 MCP stdio 进程实施操作系统用户隔离；不能把它放在未经授权的人可调用的位置。
- SSH 跳板代理必须使用专用账号、独立密钥和精确的 `PermitOpen`；目标端继续使用强制命令。默认配置将 9099 绑定到本机；LAN 配置允许受信任内网访问。

## 安全报告
请通过 GitHub 私有漏洞报告或向仓库维护者私下提交问题，切勿在公开 issue 粘贴真实私钥、会话 Cookie、飞书 Secret 或生产主机列表。

## 内网 HTTP 模式

`compose.lan.yaml` 允许内网浏览器通过 IP:9099 访问；HTTP 访问地址仅接受 RFC1918 IPv4、IPv6 ULA 或回环地址。此模式保留认证、CSRF、Origin、Host、网关白名单与凭据加密存储，但传输本身不加密，网络层应限制为受信任内网。HTTPS 配置仍启用 Secure Cookie 与 HSTS，不信任客户端提交的 X-Forwarded-Proto 来决定 Cookie 标志。
