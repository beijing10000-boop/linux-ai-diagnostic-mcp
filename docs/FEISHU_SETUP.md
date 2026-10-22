# 飞书 OAuth 与初始化

本阶段使用管理员 Open ID (`ou_...`) 作为唯一授权主体，其他飞书用户即使登录成功也会被拒绝。正式生产前仍需完成安全测试、限流、审计及代理安全设计。

1. 部署时首次启动自动在容器持久化目录 `/app/data/bootstrap.token` 生成随机初始化凭证。
2. 管理员在服务器本机使用 `docker compose exec web cat /app/data/bootstrap.token` 读取。不要将凭证发送给其他人。
3. 经 HTTPS 访问首页，填写一次性凭证、App ID、App Secret、管理员 Open ID 和公网 HTTPS Origin。
4. 飞书应用安全设置中配置 `https://你的域名/auth/feishu/callback`，按官方文档启用网页应用登录所需权限。
5. 初始化后删除 bootstrap token，App Secret 使用 Fernet 加密保存在 SQLite。
6. `master.key` 是解密根密钥，必须仅允许服务账号读取，并离线备份；泄露该文件和数据库意味着密文可被解密。
7. 浏览器使用 HttpOnly、Secure、SameSite=Lax Cookie，会话在服务端校验并可注销。
8. 所有资产 API 与诊断 API 均要求飞书管理员会话；变更操作检查 Origin。

**公网部署警告**：该实现尚未完成反向代理、IP 限流、OAuth 流程集成测试和安全审计。不要直接将 8088 映射到公网。初始化页面只使用一次性本地凭证，建议初次配置时额外限制来源 IP 或通过 VPN 完成。

业务配置通过 Web 管理；安装所需的本地加密主密钥是信任根，不是业务环境变量。
