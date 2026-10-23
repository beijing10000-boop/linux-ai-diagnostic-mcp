# SSH / MCP 实现范围与参考

本项目参考过 [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) 的 SSH 与 MCP 使用场景。当前运行时使用 Python Paramiko 和 MCP SDK，自行实现固定诊断工具，并未将该上游的通用 SSH 服务作为依赖或代理启动。

## 当前实现

- 飞书管理员登录后的 Web API，以及受信任本地进程启动的 MCP stdio，调用同一诊断执行模块。
- MCP 仅提供 `list_linux_hosts` 与 `diagnose_linux_host`；诊断参数为主机 ID、固定动作及可选服务名。
- SSH 仅连接已登记的私有 IP，核验固定 Ed25519 主机公钥；支持直连或一层 SSH 跳板。
- 跳板使用独立凭据，固定跳板和目标两端公钥，通过 `direct-tcpip` 转发到已登记目标。
- 目标 root 的专用公钥必须绑定强制命令网关，网关拒绝白名单以外的动作。
- 设置、SSH 凭据和诊断结果在 SQLite 中加密保存；诊断结果记录主机、动作、服务、时间、耗时及状态，操作审计记录调用者。
- Web 写操作校验会话、管理员、Origin 和 CSRF；MCP 访问由操作系统/容器权限控制，不复用浏览器会话。

## 尚未实现

主动回连 Agent、分布式任务队列、每个 MCP 客户端的身份授权、公网 MCP HTTP 服务、内置 AI 对话及自动诊断报告均不在当前版本中。页面中的“代理”指已实现的 SSH 跳板，不代表部署了 Agent。

任意 Shell、文件读写、SFTP 与后台 Job 不属于本项目的工具范围。后续如引入外部源码，需要核对相应版本的许可证，并保留所要求的版权与许可声明。

当前可操作的配置见 [部署说明](DEPLOYMENT.md) 和 [跳板配置](PROXY_DESIGN.md)；限制与权限验证见 [安全说明](../SECURITY.md)。
