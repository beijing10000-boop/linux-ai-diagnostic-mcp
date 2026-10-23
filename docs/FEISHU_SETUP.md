# 飞书 OAuth 管理员登录（v0.1.0）

使用飞书应用提供的网页授权码登录，登录后从飞书用户信息响应中读取 Open ID（以 `ou_` 开头）。仅允许与初始化时配置的管理员 Open ID 完全匹配的用户访问。

## 内网 HTTP

飞书安全设置可以登记 HTTP 重定向地址。内网部署时填写 `http://服务器内网IP:9099/auth/feishu/callback`，必须与 Web 访问地址的协议、IP、端口和回调路径一致。不要将回调写成 `0.0.0.0`；这是监听地址，不是浏览器访问地址。

浏览器访问内网应用、跳转飞书授权、再返回内网回调。浏览器必须能访问两侧；服务器需可出网调用飞书的 HTTPS token/user_info 接口。未提供免认证模式，内网 HTTP 同样校验管理员 Open ID、OAuth state、会话和 CSRF。

参考：
- https://open.feishu.cn/document/develop-web-apps/configure-redirect-urls
- https://open.feishu.cn/document/faq/trouble-shooting/how-to-resolve-the-authorization-page-20029-error?lang=zh-CN

## 配置步骤
1. 在飞书开放平台创建自建应用并开通网页授权所需权限。
2. 安全设置中登记精确的回调 `访问地址/auth/feishu/callback`，支持内网 HTTP 或 HTTPS。
3. 容器部署后从本地文件读取一次性初始化凭证：`docker compose exec web cat /app/data/bootstrap.token`。
4. 在内网 HTTP 或 HTTPS 页面填写 App ID、Secret、管理员 Open ID 和访问地址。
5. 浏览器点击“使用飞书登录”，完成 OAuth 授权码交换。

## 安全设计
- OAuth 的 state 存在数据库并与发起登录浏览器的 HttpOnly 临时 nonce Cookie（HTTPS 下添加 Secure） 绑定，5 分钟内一次性消费。
- 通过 token 接口交换短期 user_access_token，仅用于服务端调用 user_info，不存到 Cookie。
- 返回 Open ID 必须与管理员 Open ID 完全一致，否则拒绝。
- 会话保存服务器侧 token 摘要，Cookie 仅是随机不透明凭证，8 小时过期；Secure 随配置的访问协议自动选择。
- Web 写操作使用随机会话派生的 CSRF Token 和严格 Origin 检查。
- App Secret 加密存储且从不回显；Web 支持轮换，轮换会注销旧会话。
- 首次初始化凭证只在本机文件中，成功后删除；网页不显示凭证。

## 正式上线前须验证
目前尚未使用真实飞书应用完成端到端授权回调、应用审核/权限及公网反向代理的实际验收。正式使用前配置反向代理的限流、初始化访问源过滤、日志脱敏和安全监测。SSH 诊断、数据库、MCP stdio 不对公网提供独立端口。

参考：飞书开放平台 Web SSO 开发文档 https://open.larkenterprise.com/document/sso/web-application-sso/login-overview
