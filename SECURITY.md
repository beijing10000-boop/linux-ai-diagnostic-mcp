# 安全说明

本项目涉及 root SSH 诊断。**root 不具有真正的只读权限**，通过 authorized_keys 强制命令网关来收窄这把专用公钥的操作能力。

## v0.1.0 已实施
- 飞书管理员 Open ID 授权、会话服务端存储、HttpOnly Secure Cookie。
- 浏览器绑定 OAuth state；管理操作 CSRF Token + Origin；公网 Host 检查。
- 管理接口不提供未经认证的诊断调用；MCP 只开放本地 stdio 入口。
- 私有 IP 目标、单独 SSH Ed25519 私钥、公钥固定、固定动作白名单。
- 主密钥保护、密文设置、日志不输出私钥、审计记录。
- Docker 非 root、只读根文件系统、无附加 Linux capabilities。

## 部署前必须执行
- 在目标 Linux 上验证 root 公钥 ForceCommand 生效，且无法登录交互式 shell、不能执行其他命令、不能使用 SFTP。
- 校验 SSH 公钥指纹由可信渠道提供，不能仅信任 ssh-keyscan 返回值。
- 使用 HTTPS 反向代理、限制初始化访问源、添加登录与诊断限流、备份主密钥和数据库。
- 审计飞书应用配置和域名回调，检查 SSH 网关代码及权限，完成真实端到端测试。
- 设置 GitHub 仓库 Private 或确保绝不提交敏感凭据。
- 对 MCP stdio 进程实施操作系统用户隔离；不能把它放在未经授权的人可调用的位置。
- 当前版本不支持分布式代理执行，不支持公网直接连接 9099 端口。

## 安全报告
请通过 GitHub 私有漏洞报告或向仓库维护者私下提交问题，切勿在公开 issue 粘贴真实私钥、会话 Cookie、飞书 Secret 或生产主机列表。
