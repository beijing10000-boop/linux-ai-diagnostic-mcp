"use strict";
const Diag = {
  csrf: "",
  actionNames: {
    cpu: "CPU 负载",
    memory: "内存使用",
    disk: "磁盘",
    network: "网络接口",
    sockets: "网络连接",
    processes: "进程",
    service: "服务状态",
  },
  errors: {
    "Feishu login required": "请先使用飞书登录",
    "Session expired": "登录已过期，请重新登录",
    "Administrator required": "此账号没有管理员权限",
    "Invalid CSRF token": "安全凭证已失效，请刷新页面后重试",
    "Origin mismatch": "访问地址与系统配置不一致，请从配置的 HTTPS 地址登录",
    "Unrecognized Host": "当前域名与系统配置不一致",
    "Duplicate group": "主机组名称已存在",
    "Duplicate proxy": "代理名称已存在",
    "Duplicate host": "主机名或 IP 地址已存在",
    "Duplicate host name or address": "主机名或 IP 地址已存在",
    "Unknown host": "目标主机不存在，请刷新资产",
    "Unknown group": "主机组不存在，请刷新后重试",
    "Unknown proxy": "代理不存在，请刷新后重试",
    "Group not found": "主机组已被删除",
    "Host not found": "主机已被删除",
    "Proxy not found": "代理已被删除",
    "Only RFC1918 or ULA addresses are allowed":
      "仅支持私有 IP：10.x、172.16–31.x、192.168.x 或 IPv6 ULA",
    "Invalid SSH host key": "SSH 主机公钥无效，请粘贴完整的 Ed25519 公钥",
    "Use a verified SSH public host key: ssh-ed25519 AAAA...":
      "请填写已核验的 ssh-ed25519 主机公钥",
    "SSH private key has not been configured":
      "尚未配置 SSH 私钥，请先到系统设置保存诊断专用密钥",
    "Invalid Ed25519 SSH private key or passphrase":
      "Ed25519 私钥或口令无效，请核对完整私钥和口令",
    "Unsupported diagnostic request":
      "诊断动作或服务名无效，仅支持固定诊断项目",
    "Proxy is assigned to hosts; reassign them before deleting":
      "该代理仍有关联主机，请先更改主机连接方式后再删除",
    "Proxy routing is not configured; edit the proxy address, host key and SSH credential":
      "跳板代理配置不完整，请补齐 IP、主机公钥和专用私钥",
    "SSH host key mismatch; verify the target and proxy public keys":
      "SSH 主机公钥不匹配。请通过可信渠道核验目标或代理公钥后更新",
    "SSH authentication failed; check the dedicated key and authorized_keys":
      "SSH 认证失败，请检查专用私钥、用户名和 authorized_keys",
    "SSH channel denied; check proxy forwarding and permitopen restrictions":
      "跳板通道被拒绝，请检查 TCP 转发和 permitopen 目标限制",
    "SSH connection timed out; check address, port and routing":
      "SSH 连接超时，请检查 IP、端口、防火墙和路由",
    "SSH connection failed; check sshd, network and pinned host keys":
      "SSH 连接失败，请检查 sshd、网络连通性和主机公钥",
    "SSH diagnostic timed out; check the target gateway and network":
      "诊断执行超时，请检查目标网关和网络",
    "SSH connection closed before returning an exit status":
      "SSH 连接提前关闭，未收到退出状态",
    "Diagnostic workers are busy; retry shortly":
      "当前诊断任务较多，请稍后重试",
    "Diagnostic execution failed": "诊断执行失败，请查看服务日志与安全审计",
    "Rate limit exceeded": "操作过于频繁，请稍后重试",
    "Public URL must be a valid HTTPS origin":
      "访问地址必须是 HTTPS 域名，可含端口，不应包含路径或查询参数",
    "Already initialized": "系统已完成初始化，请前往登录页",
    "Invalid bootstrap token":
      "初始化凭证无效，请从服务器读取正确的一次性 Token",
    "Name must contain 1 to 80 characters": "名称不能为空，最多 80 个字符",
  },
  errorMessage(detail, status) {
    if (Array.isArray(detail)) {
      const labels = {
        name: "名称",
        address: "IP 地址",
        ssh_port: "SSH 端口",
        host_key: "主机公钥",
        private_key: "SSH 私钥",
        app_id: "App ID",
        admin_open_id: "管理员 Open ID",
        app_secret: "App Secret",
        public_url: "HTTPS 地址",
        bootstrap_token: "初始化凭证",
        service: "服务名",
        username: "SSH 用户名",
      };
      return detail
        .map(
          (e) =>
            `${labels[e.loc?.at(-1)] || e.loc?.at(-1) || "参数"}：${e.msg.includes("blank") ? "不能为空" : "格式或长度不符合要求，请检查"}`,
        )
        .join("；");
    }
    return (
      this.errors[detail] ||
      (typeof detail === "string" ? detail : `请求失败（HTTP ${status}）`)
    );
  },
  async init() {
    const response = await fetch("/api/me", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.status === 401 || response.status === 403) {
      location.assign("/login");
      throw Error("请使用飞书登录");
    }
    if (!response.ok) throw Error("无法验证管理员登录，请稍后刷新");
    const data = await response.json();
    this.csrf = data.csrf_token;
    document
      .querySelectorAll("[data-version]")
      .forEach((n) => (n.textContent = "v" + data.version));
    document
      .querySelectorAll(".nav-item")
      .forEach((n) => n.setAttribute("aria-label", n.textContent.trim()));
    return data;
  },
  async api(path, options = {}) {
    await this.ready;
    const method = options.method || "GET",
      headers = { Accept: "application/json" };
    if (options.body !== undefined)
      headers["Content-Type"] = "application/json";
    if (!["GET", "HEAD"].includes(method)) headers["X-CSRF-Token"] = this.csrf;
    let response;
    try {
      response = await fetch("/api/" + path, {
        method,
        headers,
        body:
          options.body === undefined ? undefined : JSON.stringify(options.body),
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch (_) {
      throw Error("无法连接服务，请检查网络后重试");
    }
    if (response.status === 401) {
      location.assign("/login");
      throw Error("登录已过期");
    }
    const data = await response
      .json()
      .catch(() => ({ detail: "服务返回了无法解析的响应" }));
    if (!response.ok)
      throw Error(this.errorMessage(data.detail, response.status));
    return data;
  },
  message(id, value, error = false) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value;
      el.classList.toggle("error", error);
    }
  },
  toast(value, error = false) {
    const el = document.getElementById("toast");
    if (!el) return;
    clearTimeout(this.toastTimer);
    el.textContent = value;
    el.hidden = false;
    el.classList.toggle("error", error);
    this.toastTimer = setTimeout(() => {
      el.hidden = true;
    }, 4500);
  },
  async busy(button, fn, label = "正在保存…") {
    if (button.dataset.busy) return;
    const nodes = [...button.childNodes],
      disabled = button.disabled;
    button.dataset.busy = "true";
    button.disabled = true;
    button.textContent = label;
    button.classList.add("loading");
    try {
      return await fn();
    } finally {
      button.replaceChildren(...nodes);
      button.disabled = disabled;
      delete button.dataset.busy;
      button.classList.remove("loading");
    }
  },
  node(tag, text = "", className = "") {
    const el = document.createElement(tag);
    el.textContent = text;
    if (className) el.className = className;
    return el;
  },
  icon(name) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", "svg"),
      use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    el.classList.add("icon");
    el.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "/assets/icons.svg#" + name);
    el.append(use);
    return el;
  },
  date(time) {
    return new Date(time * 1000).toLocaleString("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  },
  duration(ms) {
    return ms < 1000 ? ms + " ms" : (ms / 1000).toFixed(1) + " s";
  },
  async copy(value) {
    try {
      await navigator.clipboard.writeText(value);
      this.toast("已复制到剪贴板");
    } catch (_) {
      this.toast("复制失败，请在 HTTPS 页面中使用复制功能", true);
    }
  },
};
window.Diag = Diag;
Diag.ready = Diag.init();
Diag.ready.catch((e) => {
  Diag.message("status", e.message, true);
  Diag.message("loadError", e.message, true);
  const el = document.getElementById("loadError");
  if (el) el.hidden = false;
});
document.querySelectorAll("[data-logout]").forEach((button) =>
  button.addEventListener("click", () =>
    Diag.busy(
      button,
      async () => {
        try {
          await Diag.api("logout", { method: "POST" });
          location.assign("/login");
        } catch (e) {
          Diag.toast(e.message, true);
        }
      },
      "退出中",
    ),
  ),
);
