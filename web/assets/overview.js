"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  async function refresh() {
    try {
      const [status, runs] = await Promise.all([
        Diag.api("status"),
        Diag.api("runs"),
      ]);
      $("dbState").textContent = status.database === "ok" ? "正常" : "异常";
      $("dbState").className = status.database === "ok" ? "positive" : "error";
      $("sshState").textContent = status.ssh_configured ? "已配置" : "待配置";
      $("sshState").className = status.ssh_configured
        ? "positive"
        : "warning-text";
      $("hostCount").textContent = status.inventory.hosts;
      $("proxyCount").textContent = status.inventory.proxies;
      $("hostSummary").textContent =
        `${status.inventory.configured_hosts} 台连接配置完整 · ${status.inventory.groups} 个主机组`;
      $("proxySummary").textContent =
        `${status.inventory.configured_proxies} 个已配置 · 查看代理 →`;
      for (const [id, key] of [
        ["runTotal", "total"],
        ["runSuccess", "success"],
        ["runWarning", "warning"],
        ["runFailed", "failed"],
      ])
        $(id).textContent = status.runs[key];
      Diag.renderReadiness($("readiness"), status);
      $("recentRuns").replaceChildren();
      $("recentEmpty").hidden = runs.length > 0;
      runs.slice(0, 6).forEach((r) => {
        const tr = Diag.node("tr");
        [
          r.host_name,
          (Diag.actionNames[r.action] || r.action) +
            (r.service ? " · " + r.service : ""),
          Diag.date(r.time),
          Diag.duration(r.duration_ms),
        ].forEach((v) => tr.append(Diag.node("td", v)));
        const state = Diag.node("td");
        state.append(Diag.statusBadge(r.status));
        const cell = Diag.node("td"),
          link = Diag.node("a", "查看结果");
        link.href = "/activity?run=" + r.id;
        cell.append(link);
        tr.append(state, cell);
        $("recentRuns").append(tr);
      });
      Diag.message(
        "overviewStatus",
        "状态已更新 · " +
          new Date().toLocaleTimeString("zh-CN", {
            timeZone: "Asia/Shanghai",
            hour12: false,
          }),
      );
      $("loadError").hidden = true;
    } catch (e) {
      $("loadError").hidden = false;
      $("loadError").textContent = e.message;
    }
  }
  $("refreshOverview").addEventListener("click", () =>
    Diag.busy($("refreshOverview"), refresh, "读取中…"),
  );
  refresh();
})();
