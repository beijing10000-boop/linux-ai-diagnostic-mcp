"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let hosts = [],
    proxies = [],
    keyReady = false,
    running = false,
    currentResult = null,
    resultRequest = 0,
    raw = false;
  function updateHost() {
    const host = hosts.find((h) => h.id === Number($("host").value));
    const proxy = host && proxies.find((p) => p.id === host.proxy_id);
    $("hostHint").textContent = host
      ? `${host.address}:${host.ssh_port} · ${proxy ? "经 " + proxy.name : "直连"} · root`
      : "选择已登记并核验公钥的 Linux 服务器";
    $("run").disabled = running || !keyReady || !host;
  }
  function updateAction() {
    const service = $("action").value === "service";
    $("serviceField").hidden = !service;
    $("service").required = service;
    $("service").disabled = !service;
  }
  async function refresh() {
    try {
      const selected =
        $("host").value || new URLSearchParams(location.search).get("host");
      const [h, p, s] = await Promise.all(
        ["hosts", "proxies", "status"].map((x) => Diag.api(x)),
      );
      hosts = h;
      proxies = p;
      keyReady = s.ssh_configured;
      $("hostCount").textContent = h.length;
      $("groupCount").textContent = s.inventory.groups;
      $("proxyCount").textContent = p.length;
      $("proxySummary").textContent =
        `${p.filter((x) => x.status === "configured").length} 个已配置`;
      $("keyState").textContent = keyReady ? "已配置" : "待配置";
      $("keySummary").textContent = keyReady
        ? "诊断专用密钥已加密保存"
        : "前往系统设置添加专用私钥 →";
      const blank = Diag.node(
        "option",
        h.length ? "请选择目标主机" : "尚未添加主机",
      );
      blank.value = "";
      $("host").replaceChildren(blank);
      h.forEach((host) => {
        const proxy = p.find((x) => x.id === host.proxy_id),
          unavailable =
            !host.host_key ||
            (host.proxy_id && (!proxy || proxy.status !== "configured"));
        const option = Diag.node(
          "option",
          `${host.name} · ${host.address}${unavailable ? "（连接配置不完整）" : ""}`,
        );
        option.value = host.id;
        option.disabled = Boolean(unavailable);
        $("host").append(option);
      });
      if (
        [...$("host").options].some(
          (o) => o.value === String(selected) && !o.disabled,
        )
      )
        $("host").value = selected;
      $("host").disabled = running || !h.length;
      Diag.message(
        "notice",
        !h.length
          ? "先到资产与代理添加第一台主机。"
          : !keyReady
            ? "先到系统设置配置 SSH 诊断专用私钥。"
            : "",
      );
      $("loadError").hidden = true;
      updateHost();
    } catch (e) {
      $("loadError").textContent = e.message;
      $("loadError").hidden = false;
    }
  }
  function renderOutput(result, meta) {
    currentResult = result;
    raw = false;
    $("rawToggle").textContent = "JSON";
    $("rawToggle").disabled = false;
    $("copyOutput").disabled = false;
    $("outputEmpty").hidden = true;
    $("output").hidden = false;
    const status =
        meta.status || result.status || (result.error ? "failed" : "success"),
      failed = status === "failed",
      warning = status === "warning";
    $("resultBadge").textContent = failed
      ? "执行失败"
      : result.truncated
        ? "输出已截断"
        : warning
          ? "需关注"
          : "执行完成";
    $("resultBadge").className =
      "badge terminal-badge " +
      (failed ? "failed" : warning ? "warning" : "success");
    $("terminalTitle").textContent =
      meta.host_name + " / " + (Diag.actionNames[meta.action] || meta.action);
    $("resultMeta").textContent =
      `${Diag.date(meta.time || Date.now() / 1000)} · ${Diag.duration(meta.duration_ms || result.duration_ms || 0)}`;
    $("outputState").textContent = failed
      ? "连接或执行失败"
      : `退出状态 ${result.exit_code ?? "未返回"}${result.truncated ? " · 已保留部分输出" : ""}`;
    showText();
  }
  function showText() {
    if (!currentResult) return;
    $("output").textContent = raw
      ? JSON.stringify(currentResult, null, 2)
      : Diag.resultText(currentResult);
    $("rawToggle").setAttribute("aria-pressed", String(raw));
  }
  async function loadRuns() {
    try {
      const records = await Diag.api("runs");
      $("runs").replaceChildren();
      $("runsEmpty").hidden = records.length > 0;
      records.slice(0, 8).forEach((r) => {
        const tr = Diag.node("tr"),
          cell = Diag.node("td"),
          name = Diag.node("div", "", "cell-name"),
          symbol = Diag.node("span", "", "cell-icon");
        symbol.append(Diag.icon("server"));
        name.append(symbol, Diag.node("strong", r.host_name));
        cell.append(name);
        tr.append(cell);
        [
          (Diag.actionNames[r.action] || r.action) +
            (r.service ? " · " + r.service : ""),
          Diag.date(r.time),
          Diag.duration(r.duration_ms),
        ].forEach((t) => tr.append(Diag.node("td", t)));
        const state = Diag.node("td");
        state.append(Diag.statusBadge(r.status));
        tr.append(state);
        const actions = Diag.node("td"),
          button = Diag.node("button", "查看", "text-button");
        button.setAttribute(
          "aria-label",
          "查看 " + r.host_name + " 的诊断结果",
        );
        button.addEventListener("click", () =>
          Diag.busy(
            button,
            async () => {
              if (running) {
                Diag.toast("诊断执行中，请稍后查看历史");
                return;
              }
              const request = ++resultRequest;
              try {
                const detail = await Diag.api("runs/" + r.id);
                if (request !== resultRequest) return;
                renderOutput(detail.result, detail);
                $("output").focus({ preventScroll: true });
              } catch (e) {
                Diag.toast(e.message, true);
              }
            },
            "读取中",
          ),
        );
        actions.append(button);
        tr.append(actions);
        $("runs").append(tr);
      });
      Diag.message("runsStatus", "");
    } catch (e) {
      Diag.message("runsStatus", e.message, true);
    }
  }
  $("diagnoseForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (running) return;
    const host = hosts.find((h) => h.id === Number($("host").value));
    if (!host) return;
    const action = $("action").value,
      service = action === "service" ? $("service").value.trim() : null;
    running = true;
    resultRequest++;
    $("host").disabled = true;
    $("action").disabled = true;
    $("refresh").disabled = true;
    $("outputEmpty").hidden = true;
    $("output").hidden = false;
    $("output").textContent =
      "正在建立安全 SSH 连接…\n正在核验主机身份并执行诊断，请稍候。";
    $("resultBadge").textContent = "执行中";
    $("resultBadge").className = "badge terminal-badge";
    $("terminalTitle").textContent =
      host.name + " / " + Diag.actionNames[action];
    $("resultMeta").textContent = "任务执行中";
    $("outputState").textContent = "正在连接并执行诊断";
    $("copyOutput").disabled = true;
    $("rawToggle").disabled = true;
    Diag.message("notice", "");
    await Diag.busy(
      $("run"),
      async () => {
        try {
          const result = await Diag.api("diagnose", {
            method: "POST",
            body: { host_id: host.id, action, service },
          });
          renderOutput(result, { host_name: host.name, action });
        } catch (e) {
          renderOutput({ error: e.message }, { host_name: host.name, action });
          Diag.message("notice", e.message, true);
        } finally {
          running = false;
          $("host").disabled = false;
          $("action").disabled = false;
          $("refresh").disabled = false;
          await loadRuns();
        }
      },
      "正在诊断…",
    );
    updateHost();
  });
  $("host").addEventListener("change", updateHost);
  $("action").addEventListener("change", updateAction);
  $("rawToggle").addEventListener("click", () => {
    raw = !raw;
    $("rawToggle").textContent = raw ? "文本" : "JSON";
    showText();
  });
  $("copyOutput").addEventListener("click", () =>
    Diag.copy($("output").textContent),
  );
  $("refresh").addEventListener("click", () =>
    Diag.busy(
      $("refresh"),
      async () => {
        await refresh();
        await loadRuns();
      },
      "刷新中",
    ),
  );
  $("refreshRuns").addEventListener("click", () =>
    Diag.busy($("refreshRuns"), loadRuns, "读取中"),
  );
  updateAction();
  refresh();
  loadRuns();
})();
