# SSH MCP 上游参考与安全集成设计

上游仓库：https://github.com/classfang/ssh-mcp-server
NPM 包：@fangjunjie/ssh-mcp-server
上游 License：ISC。引入或修改上游源码时保留原许可证和版权声明。

## 已核实的上游能力
- SSH 密码、私钥和带密码私钥认证
- 多 SSH 连接，支持 `--config-file` / `--ssh` / SSH config
- `exec` 和 `shell` 两种 SSH transport
- 命令白名单/黑名单
- SOCKS5 / HTTP(S) SSH 网络代理、跳板机场景
- MCP stdio、Streamable HTTP
- `execute-command`、`list-servers`、文件读写传输、后台 job 管理

## 本项目明确的安全边界
公网 Web → 飞书管理员认证 → 授权 API → 结构化诊断动作 → SSH 连接 → 目标机 ForceCommand 网关。

**不将上游 MCP HTTP 服务直接开放到公网或交给 AI 访问。** 禁止将 `execute-command` 以原始参数向模型提供；只发布固定操作（cpu、memory、disk、network、sockets、processes、service）。上传、下载、read-file、write-file、job-*、shell 模式均应从可暴露的 MCP 工具集合中移除，不能只靠提示词隐藏。

上游的 commandWhitelist 是第一层校验，但 root 权限由目标机控制，因此 ForceCommand 网关是必需的第二层防护。SSH Host Key 必须预先验证并固定，绝不自动接受未知指纹。

## 架构
1. Web 数据库存储主机组、主机、代理路由策略与凭据引用；业务设置通过 Web 修改。
2. 加密密钥仓库独立持久化，主密钥与加密数据库分开保护。
3. MCP 适配层将 host_id + enum action 转换为固定的 SSH_ORIGINAL_COMMAND；严禁任意 cmdString。
4. 分布式 Proxy Agent 主动回连控制平面，使用 mTLS + 主机组授权 + 任务签名/过期时间/防重放。
5. 每条诊断记录用户、主机 ID、代理 ID、动作、结果、耗时和时间，并脱敏输出。
6. 飞书 OAuth 管理员身份只允许访问 Web，MCP 客户端独立认证、独立权限与限流，不复用浏览器 Cookie。

## Web 管理需求
- 全部业务配置集中在 Web，包括 SSH 凭据、密钥轮换、known_hosts、主机组、代理、诊断策略、飞书、AI、MCP。
- 首次启动使用本机一次性初始化凭证；飞书管理员 Open ID。
- 不要求人工编辑 .env。
- 权限管理、操作审计、主机/组授权、诊断报告、任务中心、实时图表、节点状态与告警。
- 内置安全检查项：未配置 TLS、未知 SSH Host Key、root 普通 Shell 可用、策略过宽时禁止上线。

## 适配实现分期
### A. 能力适配
- 确定上游版本/固定依赖哈希，评审 `src` 实际实现，编写固定动作适配器。
- 仅允许 `exec` 模式；不对模型暴露 shell/SFTP/job tools。
- 进行负面用例（管道、重定向、命令替换、控制字符、参数注入、任意路径、错误主机）。
### B. Web/身份
- 飞书 OAuth E2E 验证、首启初始化锁、防暴力破解、安全 Cookie、CSRF、审计。
- SSH 连接凭据加密、known_hosts 指纹确认与凭据更新。
### C. 代理与 MCP
- 代理注册/撤销、心跳、队列及任务签名；标准 MCP 工具可被现有 Zabbix AI Ops 调用。
- 生产环境必须完成容器、SSH、OAuth 和安全测试后再开放公网。

## 与上游区别
上游是通用 SSH MCP；本项目是专用于只读 Linux 诊断的 Web 管理平台。上游 `--proxy` 网络代理并不等同于离线/跨机房分布式 Proxy Agent。

目前仓库仍处于开发阶段，本文件是基于已核实上游 README 的功能适配设计，**不代表运行时集成已经完成**。
