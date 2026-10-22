"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let initial = null;
  function origin() {
    return (
      $("web_protocol").value +
      "://" +
      $("web_public_host").value.trim().replace(/\/$/, "")
    );
  }
  function callback() {
    const value = origin();
    $("public_url").value = value;
    $("callbackUrl").textContent = value + "/auth/feishu/callback";
  }
  function sshState(data) {
    $("sshStatus").textContent = data.ssh_private_key_configured
      ? "已配置专用 SSH 私钥"
      : "尚未配置 SSH 私钥";
    $("sshStatus").className =
      "badge " + (data.ssh_private_key_configured ? "success" : "neutral");
    $("sshPublicKey").value = data.ssh_public_key || "";
    $("sshFingerprint").textContent = data.ssh_fingerprint || "";
    $("copyPublicKey").disabled = !data.ssh_public_key;
  }
  async function load() {
    try {
      const data = await Diag.api("settings"),
        url = new URL(data.public_url);
      initial = data;
      $("app_id").value = data.app_id || "";
      $("admin_open_id").value = data.admin_open_id || "";
      $("app_secret").value = "";
      $("web_protocol").value = url.protocol.replace(":", "");
      $("web_public_host").value = url.host;
      $("web_public_host").setCustomValidity("");
      $("app_secret").placeholder = data.app_secret_configured
        ? "••••••••（已配置，留空保持）"
        : "请输入 App Secret";
      $("feishuSecretHint").textContent = data.app_secret_configured
        ? "App Secret 已保存；留空保持当前凭据。"
        : "尚未配置 App Secret";
      $("sshForm").reset();
      sshState(data);
      callback();
      return true;
    } catch (e) {
      Diag.message("status", e.message, true);
      return false;
    }
  }
  $("web_protocol").addEventListener("change", callback);
  $("web_public_host").addEventListener("input", () => {
    $("web_public_host").setCustomValidity("");
    callback();
  });
  $("copyCallback").addEventListener("click", () =>
    Diag.copy($("callbackUrl").textContent),
  );
  $("copyPublicKey").addEventListener("click", () =>
    Diag.copy($("sshPublicKey").value),
  );
  $("reloadSettings").addEventListener("click", () =>
    Diag.busy(
      $("reloadSettings"),
      async () => {
        if (await load()) {
          Diag.message("settingsStatus", "");
          Diag.message("sshSaveStatus", "");
          Diag.message("status", "已重新读取配置，未保存的输入已清空");
        }
      },
      "读取中…",
    ),
  );
  $("settingsForm").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!initial) {
      Diag.message("settingsStatus", "配置尚未加载，请重新读取", true);
      return;
    }
    const host = $("web_public_host").value.trim();
    if (host.includes("://") || host.includes("/")) {
      $("web_public_host").setCustomValidity(
        "仅填写 IP 或域名与端口，协议在左侧选择",
      );
      $("web_public_host").reportValidity();
      return;
    }
    callback();
    const data = {};
    for (const key of ["app_id", "admin_open_id", "public_url"]) {
      const value = $(key).value.trim();
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
        Diag.message("settingsStatus", "保存失败：" + err.message, true);
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
        const data = await Diag.api("settings");
        sshState(data);
        Diag.message("sshSaveStatus", "SSH 私钥已加密保存，输入内容已清空");
        Diag.toast("SSH 凭据已保存");
      } catch (err) {
        Diag.message("sshSaveStatus", err.message, true);
      }
    });
  });
  load();
})();
