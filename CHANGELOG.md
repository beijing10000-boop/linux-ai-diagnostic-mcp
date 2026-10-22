# Changelog

## v0.1.0 — 2026-10-22

首个安全基础版本（候选）：在已有概念验证代码上进行架构整理与漏洞修复。

### Added
- 中文、响应式的 Web 诊断台 / 主机组 / 代理登记 / 系统设置 / 安全审计。
- 飞书 Open ID 管理员单点登录与一次性初始化向导。
- 数据库加密配置、SSH Ed25519 凭据 Web 管理、SSH 主机公钥固定。
- 私有地址主机登记、按主机 ID 运行固定只读诊断。
- MCP stdio 适配层（仅本机受信任进程使用），不开放公网 MCP HTTP。
- 自动化 GitHub Actions、单元回归测试、Docker 镜像隔离。

### Fixed
- 容器内部、外部与文档默认端口统一为 **9099**。
- 统一 SQLite 数据库路径，实现持久化资产数据。
- 删除旧版依赖 .env 的诊断访问路径；不允许通过输入任意 IP 直接触发 SSH。
- OAuth state 与浏览器 nonce 绑定，增加 CSRF Token、Origin 与 Host 校验。
- 公网 Web 安全响应头与脚本外置，禁用未受限 MCP 文件操作。
- 限制 SSH 并发、超时、输出量与目标地址。

### Deliberately not implemented
- 分布式 Proxy Agent 连接与队列（目前仅登记）。
- 上游 classfang 的 SFTP、任意 shell、后台任务和 Streamable HTTP 公网暴露。
- 多租户权限、审批、AI 模型内建、历史诊断可视化。
- 完整的真实飞书应用 E2E 测试及生产安全认证。

**注意：v0.1.0 是开发/测试基线，不能理解为公网生产验收通过。**
