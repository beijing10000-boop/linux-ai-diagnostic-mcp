"use strict";
(() => {
  const form = document.getElementById("setupForm"),
    status = document.getElementById("setupStatus"),
    url = document.getElementById("setupUrl");
  url.addEventListener("input", () => {
    document.getElementById("setupCallback").textContent =
      (url.value.trim().replace(/\/$/, "") || "https://你的域名") +
      "/auth/feishu/callback";
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector("button[type=submit]");
    if (button.disabled) return;
    const nodes = [...button.childNodes];
    button.disabled = true;
    button.textContent = "正在初始化…";
    status.textContent = "";
    status.classList.remove("error");
    try {
      const data = Object.fromEntries(new FormData(form));
      for (const key of ["app_id", "admin_open_id", "public_url"])
        data[key] = data[key].trim();
      const response = await fetch("/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
        credentials: "same-origin",
      });
      const result = await response.json();
      if (!response.ok) {
        const map = {
          "Invalid bootstrap token":
            "一次性初始化凭证不正确，请从服务器重新核对",
          "Already initialized": "系统已经初始化，请前往登录",
          "Public URL must be a valid HTTPS origin":
            "请填写不含路径的有效 HTTPS 访问地址",
          "Rate limit exceeded": "操作过于频繁，请稍后再试",
        };
        throw Error(
          map[result.detail] ||
            (Array.isArray(result.detail)
              ? "配置格式不正确，请核对 App ID、Open ID 和凭据长度"
              : result.detail || "初始化失败"),
        );
      }
      document.getElementById("setupCallback").textContent =
        result.redirect_uri;
      status.textContent =
        "初始化完成。请确认飞书后台已配置以上回调地址，再前往登录。";
      form.reset();
      form.hidden = true;
      document.getElementById("loginLink").hidden = false;
    } catch (err) {
      status.textContent =
        err instanceof TypeError ? "连接失败，请检查网络后重试" : err.message;
      status.classList.add("error");
    } finally {
      button.replaceChildren(...nodes);
      button.disabled = false;
    }
  });
})();
