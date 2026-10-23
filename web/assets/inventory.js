"use strict";
(() => {
  const $ = (id) => document.getElementById(id),
    store = { hosts: [], groups: [], proxies: [] };
  let active = ["groups", "proxies"].includes(location.hash.slice(1))
      ? location.hash.slice(1)
      : "hosts",
    editing = null,
    pendingDelete = null;
  const names = { hosts: "主机", groups: "主机组", proxies: "跳板代理" },
    singular = { hosts: "host", groups: "group", proxies: "proxy" };
  function options(id, rows, label) {
    const select = $(id),
      value = select.value,
      blank = Diag.node("option", label);
    blank.value = "";
    select.replaceChildren(blank);
    rows.forEach((r) => {
      const o = Diag.node(
        "option",
        r.name + (r.status === "unconfigured" ? "（待配置）" : ""),
      );
      o.value = r.id;
      select.append(o);
    });
    if ([...select.options].some((o) => o.value === value))
      select.value = value;
  }
  function badge(text, state) {
    return Diag.node("span", text, "badge " + state);
  }
  function render() {
    document.querySelectorAll("[data-tab]").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === active);
      b.setAttribute("aria-selected", String(b.dataset.tab === active));
      b.tabIndex = b.dataset.tab === active ? 0 : -1;
    });
    $("assetPanel").setAttribute("aria-labelledby", "tab-" + active);
    $("groupFilter").hidden = active !== "hosts";
    $("addAsset").querySelector("span").textContent =
      (active === "groups" ? "新建" : "添加") + names[active];
    $("search").placeholder =
      active === "hosts"
        ? "搜索主机名称或 IP…"
        : "搜索" + names[active] + "名称或描述…";
    const query = $("search").value.toLowerCase().trim(),
      filter = $("groupFilter").value;
    const rows = store[active]
      .filter((r) =>
        [r.name, r.address, r.description].some((v) =>
          String(v || "")
            .toLowerCase()
            .includes(query),
        ),
      )
      .filter(
        (r) => active !== "hosts" || !filter || String(r.group_id) === filter,
      );
    const table = Diag.node("table"),
      header = Diag.node("thead"),
      hr = Diag.node("tr");
    const columns = {
      hosts: ["主机名称", "连接地址", "主机组", "连接方式", "主机身份", "操作"],
      groups: ["主机组名称", "描述", "主机数量", "操作"],
      proxies: [
        "代理名称",
        "SSH 地址",
        "登录用户",
        "配置状态",
        "关联主机",
        "操作",
      ],
    };
    columns[active].forEach((c) => hr.append(Diag.node("th", c)));
    header.append(hr);
    table.append(header);
    const body = Diag.node("tbody");
    rows.forEach((row) => {
      const tr = Diag.node("tr"),
        first = Diag.node("td"),
        name = Diag.node("div", "", "cell-name"),
        symbol = Diag.node("span", "", "cell-icon");
      symbol.append(
        Diag.icon(
          active === "hosts"
            ? "server"
            : active === "groups"
              ? "folder"
              : "route",
        ),
      );
      name.append(symbol, Diag.node("strong", row.name));
      first.append(name);
      tr.append(first);
      if (active === "hosts") {
        const ip = Diag.node("td"),
          group = store.groups.find((g) => g.id === row.group_id),
          proxy = store.proxies.find((p) => p.id === row.proxy_id);
        ip.append(
          Diag.node("span", row.address, "mono"),
          Diag.node("small", "SSH :" + row.ssh_port),
        );
        tr.append(
          ip,
          Diag.node("td", group?.name || "未分组"),
          Diag.node("td", proxy?.name || "直连"),
        );
        const key = Diag.node("td"),
          trust = Diag.node("span", "", "trust-label");
        trust.append(
          Diag.icon(row.host_key ? "shield" : "key"),
          document.createTextNode(row.host_key ? "已固定公钥" : "待配置"),
        );
        trust.title = row.fingerprint || "尚未固定主机公钥";
        key.append(trust);
        tr.append(key);
      } else if (active === "groups") {
        tr.append(
          Diag.node("td", row.description || "—"),
          Diag.node(
            "td",
            String(store.hosts.filter((h) => h.group_id === row.id).length) +
              " 台",
          ),
        );
      } else {
        const address = Diag.node("td");
        address.append(
          Diag.node("span", row.address || "未填写", "mono"),
          Diag.node(
            "small",
            row.address
              ? "SSH :" + row.ssh_port
              : row.description || "待补齐连接配置",
          ),
        );
        const state = Diag.node("td");
        state.append(
          badge(
            row.status === "configured" ? "已配置" : "待配置",
            row.status === "configured" ? "success" : "warning",
          ),
        );
        tr.append(
          address,
          Diag.node("td", row.username || "—"),
          state,
          Diag.node(
            "td",
            String(store.hosts.filter((h) => h.proxy_id === row.id).length) +
              " 台",
          ),
        );
      }
      const actions = Diag.node("td"),
        wrap = Diag.node("div", "", "row-actions");
      if (active === "hosts") {
        const link = Diag.node("a", "诊断");
        link.href = "/diagnostics?host=" + row.id;
        link.setAttribute("aria-label", "诊断 " + row.name);
        wrap.append(link);
      }
      for (const [action, label] of [
        ["edit", "编辑"],
        ["delete", "删除"],
      ]) {
        const button = Diag.node(
          "button",
          label,
          action === "delete" ? "delete" : "",
        );
        button.dataset.action = action;
        button.dataset.id = row.id;
        button.setAttribute("aria-label", label + " " + row.name);
        wrap.append(button);
      }
      actions.append(wrap);
      tr.append(actions);
      body.append(tr);
    });
    table.append(body);
    $("assetTable").replaceChildren(table);
    $("assetTable").hidden = !rows.length;
    $("assetEmpty").hidden = rows.length > 0;
    $("emptyTitle").textContent =
      query || filter
        ? "没有找到匹配的资产"
        : active === "hosts"
          ? "添加第一台 Linux 主机"
          : active === "groups"
            ? "按环境组织你的主机"
            : "连接其他网段的主机";
    $("emptyDescription").textContent =
      query || filter
        ? "尝试调整搜索词或主机组筛选。"
        : {
            hosts: "登记私有 IP 和已核验的 SSH 主机公钥，即可开始诊断。",
            groups: "建立生产、开发或测试分组，让资产清晰有序。",
            proxies: "添加 SSH 跳板代理，配置独立凭据和已核验的主机公钥。",
          }[active];
    $("emptyAdd").hidden = Boolean(query || filter);
    $("emptyAdd").lastChild.textContent = " 添加" + names[active];
    $("assetSummary").textContent =
      `显示 ${rows.length} / ${store[active].length} 个${names[active]}`;
    for (const key of Object.keys(store))
      $("count-" + key).textContent = store[key].length;
  }
  async function refresh() {
    try {
      const rows = await Promise.all(
        ["hosts", "groups", "proxies"].map((x) => Diag.api(x)),
      );
      [store.hosts, store.groups, store.proxies] = rows;
      options("groupSelect", store.groups, "不分组");
      options("proxySelect", store.proxies, "直连");
      options("groupFilter", store.groups, "全部主机组");
      render();
      Diag.message("status", "");
      return true;
    } catch (e) {
      Diag.message("status", e.message, true);
      return false;
    }
  }
  function showEditor(row = null) {
    editing = row?.id || null;
    const type = singular[active],
      form = $(type + "Form"),
      dialog = $(type + "Dialog");
    form.reset();
    Diag.message(type + "FormStatus", "");
    $(type + "DialogTitle").textContent =
      (row ? "编辑" : active === "groups" ? "新建" : "添加") + names[active];
    if (row)
      for (const [key, value] of Object.entries(row)) {
        const input = form.elements.namedItem(key);
        if (input && !["private_key", "passphrase"].includes(key))
          input.value = value ?? "";
      }
    if (active === "proxies") {
      $("proxyPrivateKey").required = !row?.key_configured;
      $("proxyKeyHint").textContent = row?.key_configured
        ? "已配置，留空保持原密钥"
        : "需要代理专用私钥";
    }
    dialog.showModal();
  }
  function changeTab(tab) {
    if (!["hosts", "groups", "proxies"].includes(tab)) tab = "hosts";
    active = tab;
    $("search").value = "";
    $("groupFilter").value = "";
    history.replaceState(
      null,
      "",
      "/inventory" + (tab === "hosts" ? "" : "#" + tab),
    );
    render();
  }
  document
    .querySelectorAll("[data-tab]")
    .forEach((b) =>
      b.addEventListener("click", () => changeTab(b.dataset.tab)),
    );
  document.querySelector("[role=tablist]").addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const tabs = [...document.querySelectorAll("[data-tab]")],
      current = tabs.findIndex((b) => b.dataset.tab === active);
    const index =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? tabs.length - 1
          : (current + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) %
            tabs.length;
    changeTab(tabs[index].dataset.tab);
    tabs[index].focus();
  });
  $("search").addEventListener("input", render);
  $("groupFilter").addEventListener("change", render);
  $("addAsset").addEventListener("click", () => showEditor());
  $("emptyAdd").addEventListener("click", () => showEditor());
  $("refresh").addEventListener("click", () =>
    Diag.busy($("refresh"), refresh, "刷新中"),
  );
  document.querySelectorAll("[data-close]").forEach((b) =>
    b.addEventListener("click", () => {
      if (!b.closest("form").dataset.saving) b.closest("dialog").close();
    }),
  );
  document.querySelectorAll("dialog").forEach((d) =>
    d.addEventListener("cancel", (e) => {
      if (
        d.querySelector("form")?.dataset.saving ||
        $("confirmDelete").dataset.busy
      )
        e.preventDefault();
    }),
  );
  for (const kind of ["hosts", "groups", "proxies"]) {
    const type = singular[kind],
      form = $(type + "Form"),
      dialog = $(type + "Dialog");
    dialog.addEventListener("close", () => {
      form.reset();
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (form.dataset.saving) return;
      const data = Object.fromEntries(new FormData(form));
      data.name = data.name.trim();
      if (!data.name) {
        Diag.message(type + "FormStatus", "名称不能为空", true);
        return;
      }
      if (kind !== "groups") data.ssh_port = Number(data.ssh_port);
      if (kind === "hosts")
        for (const key of ["group_id", "proxy_id"])
          data[key] = data[key] ? Number(data[key]) : null;
      if (kind === "proxies" && !data.private_key.trim()) {
        if (data.passphrase) {
          Diag.message(
            type + "FormStatus",
            "修改口令时请同时提供新的私钥",
            true,
          );
          return;
        }
        delete data.private_key;
        delete data.passphrase;
      }
      form.dataset.saving = "true";
      Diag.message(type + "FormStatus", "");
      await Diag.busy(form.querySelector("button[type=submit]"), async () => {
        try {
          await Diag.api(kind + (editing ? "/" + editing : ""), {
            method: editing ? "PUT" : "POST",
            body: data,
          });
          delete form.dataset.saving;
          dialog.close();
          await refresh();
          Diag.toast(names[kind] + "已保存");
        } catch (err) {
          Diag.message(type + "FormStatus", err.message, true);
        } finally {
          delete form.dataset.saving;
        }
      });
    });
  }
  $("assetTable").addEventListener("click", (e) => {
    const button = e.target.closest("button[data-action]");
    if (!button) return;
    const row = store[active].find((r) => r.id === Number(button.dataset.id));
    if (!row) return;
    if (button.dataset.action === "edit") showEditor(row);
    else {
      pendingDelete = { kind: active, id: row.id };
      $("confirmTitle").textContent = "删除" + names[active];
      $("confirmText").textContent =
        `确认删除“${row.name}”？` +
        (active === "groups"
          ? " 组内主机会保留并变为未分组。"
          : active === "proxies"
            ? " 仍有关联主机的代理不可删除。"
            : " 已有诊断历史会保留。");
      Diag.message("confirmStatus", "");
      $("confirmDialog").showModal();
    }
  });
  $("cancelDelete").addEventListener("click", () => {
    if (!$("confirmDelete").dataset.busy) $("confirmDialog").close();
  });
  $("confirmDelete").addEventListener("click", () =>
    Diag.busy(
      $("confirmDelete"),
      async () => {
        if (!pendingDelete) return;
        try {
          await Diag.api(pendingDelete.kind + "/" + pendingDelete.id, {
            method: "DELETE",
          });
          $("confirmDialog").close();
          await refresh();
          Diag.toast("资产已删除");
          pendingDelete = null;
        } catch (e) {
          Diag.message("confirmStatus", e.message, true);
        }
      },
      "正在删除…",
    ),
  );
  window.addEventListener("hashchange", () =>
    changeTab(location.hash.slice(1)),
  );
  render();
  refresh();
})();
