"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let hosts = [],
    proxies = [],
    configured = false,
    running = false;
  function selection() {
    const host = hosts.find((h) => h.id === Number($("testHost").value)),
      proxy = host && proxies.find((p) => p.id === host.proxy_id);
    $("testHostHint").textContent = host
      ? `${host.address}:${host.ssh_port} · ${proxy ? "经 " + proxy.name : "直连"} · root`
      : "先选择需要验证的主机。";
    $("openDiagnostics").href =
      "/diagnostics" + (host ? "?host=" + host.id : "");
    $("testConnection").disabled = running || !configured || !host;
  }
  async function load() {
    try {
      const selected =
          $("testHost").value ||
          new URLSearchParams(location.search).get("host"),
        [status, h, p] = await Promise.all([
          Diag.api("status"),
          Diag.api("hosts"),
          Diag.api("proxies"),
        ]);
      hosts = h;
      proxies = p;
      configured = status.ssh_configured;
      Diag.renderReadiness($("connectionReadiness"), status);
      $("platformOutput").textContent =
        `数据库：${status.database === "ok" ? "正常" : "异常"}\n访问地址：${status.public_url}\nSSH 凭据：${configured ? "已配置" : "尚未配置"}\n主机：${status.inventory.hosts} 台（${status.inventory.configured_hosts} 台连接配置完整）\n跳板代理：${status.inventory.configured_proxies}/${status.inventory.proxies} 个已配置\nMCP 接入：本地 stdio\n只读动作：${status.readonly_actions.map((a) => Diag.actionNames[a] || a).join("、")}`;
      const blank = Diag.node(
        "option",
        h.length ? "请选择需要测试的主机" : "尚未添加主机",
      );
      blank.value = "";
      $("testHost").replaceChildren(blank);
      h.forEach((host) => {
        const option = Diag.node("option", host.name + " · " + host.address);
        option.value = host.id;
        $("testHost").append(option);
      });
      if ([...$("testHost").options].some((o) => o.value === String(selected)))
        $("testHost").value = selected;
      $("testHost").disabled = !h.length || running;
      selection();
      Diag.message("platformStatus", "配置检查完成");
    } catch (e) {
      Diag.message("platformStatus", e.message, true);
    }
  }
  $("testHost").addEventListener("change", selection);
  $("checkPlatform").addEventListener("click", () =>
    Diag.busy($("checkPlatform"), load, "检查中…"),
  );
  $("connectionForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (running) return;
    const host = hosts.find((h) => h.id === Number($("testHost").value));
    if (!host) return;
    running = true;
    $("testHost").disabled = true;
    $("checkPlatform").disabled = true;
    $("connectionOutput").textContent =
      "正在建立 SSH 连接、核验主机公钥并执行 CPU 查询…";
    Diag.message("connectionStatus", "");
    await Diag.busy(
      $("testConnection"),
      async () => {
        try {
          const r = await Diag.api("diagnose", {
            method: "POST",
            body: { host_id: host.id, action: "cpu", service: null },
          });
          $("connectionOutput").textContent = Diag.resultText(r);
          Diag.message(
            "connectionStatus",
            r.status === "success"
              ? `查询完成 · ${Diag.duration(r.duration_ms)} · 可在任务与审计查看记录`
              : `${r.status === "failed" ? "查询失败" : "查询需要关注"} · 退出状态 ${r.exit_code ?? "未返回"}，请核对下方输出`,
            r.status === "failed",
          );
        } catch (err) {
          Diag.message("connectionStatus", err.message, true);
          $("connectionOutput").textContent = err.message;
        } finally {
          running = false;
          $("testHost").disabled = !hosts.length;
          $("checkPlatform").disabled = false;
        }
      },
      "正在测试…",
    );
    selection();
  });
  load();
})();
