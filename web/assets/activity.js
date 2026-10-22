"use strict";
(() => {
  const $ = (id) => document.getElementById(id),
    params = new URLSearchParams(location.search);
  let page = 1,
    total = 0,
    logs = [],
    current = null,
    raw = false,
    requestId = 0,
    runRequest = 0,
    loading = false;
  const requested = params.get("status");
  if (["success", "warning", "failed"].includes(requested))
    $("runStatus").value = requested;
  function controls() {
    const size = Number($("runPageSize").value);
    $("previousPage").disabled = loading || page <= 1;
    $("nextPage").disabled = loading || page * size >= total;
  }
  async function loadHistory() {
    const serial = ++requestId;
    loading = true;
    controls();
    Diag.message("historyStatus", "正在读取任务记录…");
    try {
      const q = new URLSearchParams({
          page,
          page_size: $("runPageSize").value,
          status: $("runStatus").value,
          query: $("runSearch").value.trim(),
        }),
        data = await Diag.api("activity?" + q);
      if (serial !== requestId) return;
      total = data.total;
      const last = Math.max(
        1,
        Math.ceil(total / Number($("runPageSize").value)),
      );
      if (page > last) {
        page = last;
        return loadHistory();
      }
      $("historyRows").replaceChildren();
      $("historyEmpty").hidden = data.items.length > 0;
      data.items.forEach((r) => {
        const tr = Diag.node("tr");
        [
          Diag.date(r.time),
          r.host_name,
          (Diag.actionNames[r.action] || r.action) +
            (r.service ? " · " + r.service : ""),
        ].forEach((v) => tr.append(Diag.node("td", v)));
        const state = Diag.node("td");
        state.append(Diag.statusBadge(r.status));
        tr.append(state, Diag.node("td", Diag.duration(r.duration_ms)));
        const cell = Diag.node("td"),
          button = Diag.node("button", "查看结果", "text-button");
        button.setAttribute(
          "aria-label",
          "查看 " + r.host_name + " 的诊断结果",
        );
        button.addEventListener("click", () => openRun(r.id));
        cell.append(button);
        tr.append(cell);
        $("historyRows").append(tr);
      });
      $("pageSummary").textContent = `共 ${total} 条 · 第 ${page} / ${last} 页`;
      Diag.message("historyStatus", "");
    } catch (e) {
      if (serial === requestId) Diag.message("historyStatus", e.message, true);
    } finally {
      if (serial === requestId) {
        loading = false;
        controls();
      }
    }
  }
  async function loadSummary() {
    try {
      const data = await Diag.api("status");
      $("runSummary").replaceChildren();
      for (const [label, key, cls] of [
        ["诊断总数", "total", ""],
        ["执行完成", "success", "positive"],
        ["需要关注", "warning", "warning-text"],
        ["执行失败", "failed", "error"],
      ]) {
        const card = Diag.node("div", "", "run-summary");
        card.append(
          Diag.node("span", label),
          Diag.node("strong", String(data.runs[key]), cls),
        );
        $("runSummary").append(card);
      }
    } catch (e) {
      Diag.message("historyStatus", e.message, true);
    }
  }
  function renderAudit() {
    const q = $("auditSearch").value.toLowerCase().trim(),
      filtered = logs.filter((r) =>
        [r.actor, r.action, Diag.auditName(r.action)].some((s) =>
          s.toLowerCase().includes(q),
        ),
      );
    $("audit").replaceChildren();
    $("auditEmpty").hidden = filtered.length > 0;
    filtered.forEach((r) => {
      const tr = Diag.node("tr");
      [
        Diag.date(r.time),
        r.actor === "mcp-stdio" ? "本地 MCP" : r.actor,
        Diag.auditName(r.action),
      ].forEach((v) => tr.append(Diag.node("td", v)));
      tr.lastChild.title = r.action;
      $("audit").append(tr);
    });
  }
  async function loadAudit() {
    try {
      logs = await Diag.api("audit");
      renderAudit();
      Diag.message("auditStatus", "");
    } catch (e) {
      Diag.message("auditStatus", e.message, true);
    }
  }
  function resultText() {
    if (!current) return;
    $("runDialogOutput").textContent = raw
      ? JSON.stringify(current.result, null, 2)
      : Diag.resultText(current.result);
    $("toggleRunJSON").textContent = raw ? "文本" : "JSON";
  }
  async function openRun(id) {
    const serial = ++runRequest;
    $("runDialogTitle").textContent = "正在读取诊断结果…";
    $("runDialogOutput").textContent = "";
    $("runDialogMeta").textContent = "";
    current = null;
    raw = false;
    $("toggleRunJSON").disabled = true;
    $("copyRunResult").disabled = true;
    Diag.message("runDialogStatus", "");
    if (!$("runDialog").open) $("runDialog").showModal();
    try {
      const record = await Diag.api("runs/" + id);
      if (serial !== runRequest || !$("runDialog").open) return;
      current = record;
      $("runDialogTitle").textContent =
        current.host_name +
        " · " +
        (Diag.actionNames[current.action] || current.action);
      $("runDialogMeta").textContent =
        Diag.date(current.time) + " · " + Diag.duration(current.duration_ms);
      Diag.message(
        "runDialogStatus",
        { success: "执行完成", warning: "结果需要关注", failed: "执行失败" }[
          current.status
        ],
        current.status === "failed",
      );
      resultText();
      $("toggleRunJSON").disabled = false;
      $("copyRunResult").disabled = false;
    } catch (e) {
      if (serial === runRequest)
        Diag.message("runDialogStatus", e.message, true);
    }
  }
  $("runDialog").addEventListener("close", () => runRequest++);
  $("closeRunDialog").addEventListener("click", () => $("runDialog").close());
  $("toggleRunJSON").addEventListener("click", () => {
    raw = !raw;
    resultText();
  });
  $("copyRunResult").addEventListener("click", () =>
    Diag.copy($("runDialogOutput").textContent),
  );
  $("historyFilter").addEventListener("submit", (e) => {
    e.preventDefault();
    page = 1;
    loadHistory();
  });
  $("historyFilter").addEventListener("reset", (e) => {
    e.preventDefault();
    $("runStatus").value = "all";
    $("runPageSize").value = "20";
    $("runSearch").value = "";
    page = 1;
    loadHistory();
  });
  $("previousPage").addEventListener("click", () => {
    if (page > 1 && !loading) {
      page--;
      loadHistory();
    }
  });
  $("runPageSize").addEventListener("change", () => {
    page = 1;
    loadHistory();
  });
  $("nextPage").addEventListener("click", () => {
    if (!loading) {
      page++;
      loadHistory();
    }
  });
  $("refreshActivity").addEventListener("click", () =>
    Diag.busy(
      $("refreshActivity"),
      () => Promise.all([loadHistory(), loadSummary(), loadAudit()]),
      "读取中…",
    ),
  );
  $("refreshAudit").addEventListener("click", () =>
    Diag.busy($("refreshAudit"), loadAudit, "读取中…"),
  );
  $("auditSearch").addEventListener("input", renderAudit);
  loadHistory();
  loadSummary();
  loadAudit();
  const run = params.get("run");
  if (run && /^\d+$/.test(run)) openRun(Number(run));
})();
