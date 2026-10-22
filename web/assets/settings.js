"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let initial = null,
    logs = [];
  function callback() {
    $("callbackUrl").textContent =
      ($("public_url").value.trim().replace(/\/$/, "") || "https://你的域名") +
      "/auth/feishu/callback";
  }
  async function load() {
    try {
      initial = await Diag.api("settings");
      for (const key of ["app_id", "admin_open_id", "public_url"])
        $(key).value = initial[key] || "";
      $("sshStatus").textContent = initial.ssh_private_key_configured
        ? "已配置专用 SSH 私钥"
        : "尚未配置 SSH 私钥";
      callback();
    } catch (e) {
      Diag.message("status", e.message, true);
    }
  }
  function renderLogs() {
    const q = $("auditSearch").value.toLowerCase().trim();
    $("audit").replaceChildren();
    const filtered = logs.filter((r) =>
      [r.actor, r.action].some((s) => s.toLowerCase().includes(q)),
    );
    filtered.forEach((r) => {
      const tr = Diag.node("tr");
      [Diag.date(r.time), r.actor, r.action].forEach((v, i) =>
        tr.append(Diag.node("td", v, i === 2 ? "mono" : "")),
      );
      $("audit").append(tr);
    });
    $("auditEmpty").hidden = filtered.length > 0;
  }
  async function loadAudit() {
    try {
      logs = await Diag.api("audit");
      renderLogs();
      Diag.message("auditStatus", "");
    } catch (e) {
      Diag.message("auditStatus", e.message, true);
    }
  }
  $("public_url").addEventListener("input", callback);
  $("copyCallback").addEventListener("click", () =>
    Diag.copy($("callbackUrl").textContent),
  );
  $("settingsForm").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!initial) {
      Diag.message("settingsStatus", "配置尚未加载完成，请稍后刷新", true);
      return;
    }
    const data = {};
    for (const key of ["app_id", "admin_open_id", "public_url"]) {
      const value = $(key)
        .value.trim()
        .replace(key === "public_url" ? /\/$/ : /$^/, "");
      if (value !== initial[key]) data[key] = value;
    }
    if ($("app_secret").value) data.app_secret = $("app_secret").value;
    if (!Object.keys(data).length) {
      Diag.message("settingsStatus", "设置未发生变化，无需保存");
      return;
    }
    Diag.busy($("saveSettings"), async () => {
      try {
        const result = await Diag.api("settings", {
          method: "PUT",
          body: data,
        });
        $("app_secret").value = "";
        Diag.message(
          "settingsStatus",
          result.reauth_required ? "配置已保存，即将重新登录…" : "配置已保存",
        );
        if (result.reauth_required) location.assign(result.redirect_url);
        else await load();
      } catch (err) {
        Diag.message("settingsStatus", err.message, true);
      }
    });
  });
  $("sshForm").addEventListener("submit", (e) => {
    e.preventDefault();
    Diag.busy($("saveSSH"), async () => {
      try {
        await Diag.api("settings/ssh", {
          method: "PUT",
          body: {
            private_key: $("ssh_key").value,
            passphrase: $("ssh_passphrase").value,
          },
        });
        $("sshForm").reset();
        $("sshStatus").textContent = "已配置专用 SSH 私钥";
        Diag.message("sshSaveStatus", "SSH 私钥已加密保存");
        Diag.toast("SSH 凭据已保存");
        await loadAudit();
      } catch (err) {
        Diag.message("sshSaveStatus", err.message, true);
      }
    });
  });
  $("refreshAudit").addEventListener("click", () =>
    Diag.busy($("refreshAudit"), loadAudit, "刷新中"),
  );
  $("auditSearch").addEventListener("input", renderLogs);
  load();
  loadAudit();
})();
