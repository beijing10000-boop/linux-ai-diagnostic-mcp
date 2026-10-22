"use strict";
const loginError = new URLSearchParams(location.search).get("error");
if (loginError) {
  const node = document.getElementById("loginError");
  const messages = {
    cancelled: "飞书授权已取消。你可以重新登录。",
    state: "登录凭证已过期或与当前浏览器不匹配，请重新登录。",
    unauthorized: "此飞书账号尚未获管理员授权，请联系管理员核对 Open ID。",
    unavailable: "暂时无法完成飞书验证，请稍后重试并核对应用配置。",
  };
  node.textContent =
    messages[loginError] || "登录未完成，请重新尝试或联系管理员。";
  node.hidden = false;
}
