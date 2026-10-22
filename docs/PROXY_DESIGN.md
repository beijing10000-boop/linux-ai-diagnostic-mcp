# SSH 跳板代理

当前实现为 **SSH Jump Host**：控制台先认证到跳板机，建立到已登记目标 IP/SSH 端口的 `direct-tcpip` 通道，再通过此通道进行第二次 SSH 握手。跳板机和目标主机都独立固定 Ed25519 主机公钥。

这适合“诊断服务器可达跳板机、跳板机可达目标主机”的网络。它不需要安装常驻 Agent，也不提供主动回连、任务队列或心跳；界面中的“已配置”仅表示配置齐全，不表示在线。

## Web 配置

1. 在“资产与代理 → 跳板代理”添加名称、私有 IP、SSH 端口、登录用户名。
2. 通过可信渠道核验跳板机主机公钥，填写完整 `ssh-ed25519 AAAA...`。
3. 录入跳板专用 Ed25519 私钥及其口令（如有）。它与“系统设置”里的目标 root 诊断密钥独立。
4. 编辑目标主机，将连接方式改为对应跳板代理。
5. 在诊断工作台选择目标主机，运行一个固定诊断动作。

代理私钥与口令在数据库中加密保存，不会从查询 API 或编辑表单回显。编辑时私钥留空可保留当前密钥；轮换私钥时同时填写新的口令。

旧版本登记的代理会自动迁移为“待配置”。补齐连接信息和凭据后才可诊断；不会自动退回直连。代理仍有关联主机时，删除操作会被拒绝。

## 跳板机最小权限示例

建议使用专用 `diag-proxy` 用户，保留主机原有管理账号。通过可信方式创建账号及其 `.ssh/authorized_keys`，确保目录 0700、文件 0600，归属正确。

针对诊断专用公钥的条目（替换来源 IP、目标及公钥）：

```text
from="DIAGNOSTIC_SERVER_IP",restrict,port-forwarding,permitopen="172.20.1.10:22",permitopen="172.20.1.11:2222",command="/usr/bin/false" ssh-ed25519 YOUR_PROXY_PUBLIC_KEY diagnostic-proxy
```

在 sshd 配置中为此账号添加限制，避免允许远程转发或其他用途：

```text
Match User diag-proxy
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    GatewayPorts no
    MaxSessions 0
    PermitOpen 172.20.1.10:22 172.20.1.11:2222
```

先执行 `sshd -t` 检查，再按系统的既有维护流程重载 sshd。`PermitOpen` 必须逐一对应资产中实际使用的目标 IP 和 SSH 端口。如果目标连接方式改变，目标端 `authorized_keys` 的 `from=` 也必须允许正确的直连或跳板来源地址。

目标主机继续使用 [部署说明](DEPLOYMENT.md) 中的 root 强制命令网关，禁止 Shell、SFTP、文件写入与转发。跳板账号只转发连接，目标账号只运行网关动作。

## 连接失败

| 提示 | 检查项 |
|---|---|
| 代理配置不完整 | IP、主机公钥、代理专用私钥 |
| SSH 认证失败 | 对应跳板用户/目标 root 的公钥、私钥口令、`from=` |
| 通道被拒绝 | `AllowTcpForwarding local`、`PermitOpen`、准确的目标端口 |
| 主机公钥不匹配 | 通过可信控制台核验跳板与目标的主机公钥 |
| 连接超时 | 诊断机到跳板、跳板到目标两段路由与防火墙 |

只支持一层跳板，目标和跳板均限 RFC1918 IPv4 / IPv6 ULA。所有诊断调用共享并发、动作、超时、结果大小和审计限制。
