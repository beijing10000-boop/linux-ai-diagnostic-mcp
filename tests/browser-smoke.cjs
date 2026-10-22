/* Real browser + real HTTP/HTTPS API. The isolated server uses test SSH results only. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const protocol = process.env.DIAG_UI_PROTOCOL === "http" ? "http" : "https";
const transport = require("node:" + protocol);
const { spawn } = require("node:child_process");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, ".."),
  origin = `${protocol}://127.0.0.1:${protocol === "http" ? 9098 : 9443}`;
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "diag-ui-run-"));
const fixturePath = path.join(temp, "fixture.json");
const artifacts =
  process.env.DIAG_UI_ARTIFACTS || path.join(root, "ui-artifacts");
fs.mkdirSync(artifacts, { recursive: true });
const server = spawn(
  process.env.DIAG_PYTHON || path.join(root, ".venv/bin/python"),
  ["-m", "tests.ui_server", fixturePath, protocol],
  { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
);
let serverLog = "",
  browser;
server.stdout.on("data", (b) => (serverLog += b.toString()));
server.stderr.on("data", (b) => (serverLog += b.toString()));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function health() {
  return new Promise((resolve) => {
    transport
      .get(origin + "/healthz", { rejectUnauthorized: false }, (r) => {
        r.resume();
        resolve(r.statusCode === 200);
      })
      .on("error", () => resolve(false));
  });
}
async function screenshot(page, name) {
  await page.screenshot({
    path: path.join(artifacts, name + ".png"),
    fullPage: true,
    animations: "disabled",
  });
}
async function waitText(page, selector, text) {
  await page.waitForFunction(
    ({ selector, text }) =>
      document.querySelector(selector)?.textContent.includes(text),
    { selector, text },
  );
}
async function checkOverflow(page) {
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  const overflow = await page.evaluate(() => ({
    width: window.innerWidth,
    scroll: document.documentElement.scrollWidth,
    wrappers: [...document.querySelectorAll(".table-scroll")].map((n) => ({
      html: n.outerHTML.slice(0, 150),
      rect: n.getBoundingClientRect().toJSON(),
      overflow: getComputedStyle(n).overflow,
      contain: getComputedStyle(n).contain,
      scroll: n.scrollWidth,
    })),
    elements: [...document.querySelectorAll("body *")]
      .filter((n) => {
        const r = n.getBoundingClientRect();
        return (
          r.right > innerWidth + 1 &&
          getComputedStyle(n).position !== "absolute" &&
          !n.closest(".table-scroll")
        );
      })
      .slice(0, 30)
      .map((n) => ({
        tag: n.tagName,
        id: n.id,
        cls: n.className,
        width: n.getBoundingClientRect().width,
        right: n.getBoundingClientRect().right,
      })),
  }));
  if (overflow.scroll > overflow.width + 1)
    await screenshot(page, "overflow-debug");
  assert(
    overflow.scroll <= overflow.width + 1,
    `${page.url()} must fit viewport: ${JSON.stringify(overflow)}`,
  );
}

(async () => {
  try {
    for (let i = 0; i < 100; i++) {
      if (server.exitCode !== null) throw Error(serverLog);
      if (fs.existsSync(fixturePath) && (await health())) break;
      if (i === 99) throw Error("UI server timeout: " + serverLog);
      await delay(100);
    }
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.DIAG_CHROMIUM || undefined,
      args: [
        "--no-sandbox",
        "--no-proxy-server",
        "--disable-dev-shm-usage",
        "--no-zygote",
        "--single-process",
        "--disable-gpu",
        "--host-resolver-rules=MAP diag.test 127.0.0.1",
      ],
    });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1440, height: 1050 },
      colorScheme: "light",
    });
    const page = await context.newPage(),
      errors = [];
    if (protocol === "http") {
      await page.addInitScript(() =>
        Object.defineProperty(navigator, "clipboard", {
          get: () => undefined,
          configurable: true,
        }),
      );
    }
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (
        message.type() === "error" &&
        /Content Security Policy|Refused to/.test(message.text())
      )
        errors.push(message.text());
    });
    await page.goto(origin);
    await page.locator("#setupForm").waitFor();
    await screenshot(page, "setup-desktop");
    for (const [name, value] of Object.entries({
      bootstrap_token: fixture.bootstrap_token,
      app_id: "cli_browsertest123",
      app_secret: "browser_test_secret_only",
      admin_open_id: "ou_browser_test_admin123",
      public_url: origin,
    }))
      await page.locator(`[name=${name}]`).fill(value);
    assert(
      await page.locator("#setupForm").evaluate((f) => f.checkValidity()),
      "setup fixture must pass form validation",
    );
    await page.getByRole("button", { name: "完成初始化" }).click();
    await page.locator("#loginLink").waitFor({ state: "visible" });
    assert(await page.locator("#setupForm").isHidden());
    await page.goto(origin + "/login");
    await page.getByRole("link", { name: "使用飞书登录" }).waitFor();
    await screenshot(page, "login-desktop");
    assert.equal(
      (await context.request.get(origin + "/api/hosts")).status(),
      401,
    );
    await context.addCookies([
      {
        name: "diag_session",
        value: fixture.session,
        domain: "127.0.0.1",
        path: "/",
        secure: protocol === "https",
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);
    await page.goto(origin);
    await waitText(page, "#hostCount", "0");
    await page.locator("#runsEmpty").waitFor({ state: "visible" });
    assert(await page.locator("#run").isDisabled());
    await page.goto(origin + "/settings");
    await waitText(page, "#sshStatus", "尚未配置");
    await page
      .locator("#ssh_key")
      .fill("invalid-private-key-for-browser-feedback".repeat(3));
    await page.locator("#saveSSH").click();
    await waitText(page, "#sshSaveStatus", "无效");
    await page.locator("#ssh_key").fill(fixture.private_key);
    await page.locator("#saveSSH").click();
    await waitText(page, "#sshSaveStatus", "已加密保存");
    assert.equal(await page.locator("#ssh_key").inputValue(), "");
    await page.locator("#saveSettings").click();
    await waitText(page, "#settingsStatus", "未发生变化");
    await page.goto(origin + "/inventory");
    await page.locator("#assetEmpty").waitFor({ state: "visible" });
    await page.locator("#tab-groups").click();
    await page.locator("#addAsset").click();
    await page.locator("#groupName").fill("生产环境 D3");
    await page.locator("#groupDescription").fill("业务服务器");
    await page.locator("#groupForm button[type=submit]").click();
    await page.locator("#groupDialog").waitFor({ state: "hidden" });
    await page
      .getByRole("button", { name: "编辑 生产环境 D3", exact: true })
      .click();
    await page.locator("#groupName").fill("生产环境");
    await page.locator("#groupForm button[type=submit]").click();
    await page.locator("#groupDialog").waitFor({ state: "hidden" });
    await page.locator("#tab-hosts").click();
    await page.locator("#addAsset").click();
    await page.locator("#hostName").fill("D3-WEB-01");
    await page.locator("#hostAddress").fill("172.20.1.10");
    await page.locator("#groupSelect").selectOption({ label: "生产环境" });
    await page
      .locator("#hostKey")
      .fill(fixture.host_key + " root@trusted-console");
    await page.locator("#hostForm button[type=submit]").click();
    await page.locator("#hostDialog").waitFor({ state: "hidden" });
    await page
      .getByRole("button", { name: "编辑 D3-WEB-01", exact: true })
      .click();
    assert.equal(
      await page.locator("#groupSelect option:checked").textContent(),
      "生产环境",
    );
    await page.locator("#hostPort").fill("2222");
    await page.locator("#hostForm button[type=submit]").click();
    await page.locator("#hostDialog").waitFor({ state: "hidden" });
    await page.locator("#search").fill("not-a-host");
    await waitText(page, "#emptyTitle", "没有找到");
    await page.locator("#search").fill("");
    await page.locator("#tab-proxies").click();
    await page.locator("#addAsset").click();
    await page.locator("#proxyName").fill("D3 跳板代理");
    await page.locator("#proxyAddress").fill("172.20.200.20");
    await page.locator("#proxyHostKey").fill(fixture.host_key);
    await page.locator("#proxyPrivateKey").fill(fixture.private_key);
    await page.locator("#proxyForm button[type=submit]").click();
    await page.locator("#proxyDialog").waitFor({ state: "hidden" });
    await page
      .getByRole("button", { name: "编辑 D3 跳板代理", exact: true })
      .click();
    assert.equal(await page.locator("#proxyPrivateKey").inputValue(), "");
    await page.locator("#proxyDescription").fill("SSH 转发节点");
    await page.locator("#proxyForm button[type=submit]").click();
    await page.locator("#proxyDialog").waitFor({ state: "hidden" });
    await page.locator("#tab-hosts").click();
    await page
      .getByRole("button", { name: "编辑 D3-WEB-01", exact: true })
      .click();
    await page.locator("#proxySelect").selectOption({ label: "D3 跳板代理" });
    await page.locator("#hostForm button[type=submit]").click();
    await page.locator("#hostDialog").waitFor({ state: "hidden" });
    await page.locator("#tab-proxies").click();
    await page
      .getByRole("button", { name: "删除 D3 跳板代理", exact: true })
      .click();
    await page.locator("#confirmDelete").click();
    await waitText(page, "#confirmStatus", "关联主机");
    await page.locator("#cancelDelete").click();
    await page.locator("#tab-hosts").click();
    await screenshot(page, "inventory-desktop");
    await page
      .getByRole("link", { name: "诊断 D3-WEB-01", exact: true })
      .click();
    await page.waitForFunction(
      () => document.querySelector("#host").value !== "",
    );
    await page.locator("#run").click();
    await waitText(page, "#resultBadge", "执行完成");
    await waitText(page, "#output", "load average");
    if (protocol === "http") {
      await page.locator("#copyOutput").click();
      await waitText(page, "#toast", "已复制到剪贴板");
      assert.equal(await page.locator(".clipboard-helper").count(), 0);
    }
    await waitText(page, "#runs", "D3-WEB-01");
    await page.locator("#rawToggle").click();
    await waitText(page, "#output", '"exit_code"');
    await page.locator("#rawToggle").click();
    await page.locator("#action").selectOption("service");
    await page.locator("#serviceField").waitFor({ state: "visible" });
    await page.locator("#service").fill("stopped-test.service");
    await page.locator("#run").click();
    await waitText(page, "#resultBadge", "需关注");
    await waitText(page, "#output", "inactive");
    await page.locator("#action").selectOption("disk");
    assert(await page.locator("#serviceField").isHidden());
    await page.locator("#run").click();
    await waitText(page, "#resultBadge", "执行失败");
    await waitText(page, "#output", "超时");
    await page.locator("#action").selectOption("cpu");
    await page.locator("#run").click();
    await waitText(page, "#resultBadge", "执行完成");
    await screenshot(page, "dashboard-desktop");
    await page.reload();
    await page
      .getByRole("button", { name: "查看 D3-WEB-01 的诊断结果" })
      .first()
      .click();
    await waitText(page, "#output", "load average");
    for (const width of [1280, 1440, 1920]) {
      await page.setViewportSize({ width, height: 900 });
      for (const route of ["/", "/inventory", "/settings"]) {
        await page.goto(origin + route);
        await page.waitForFunction(
          () =>
            document.querySelector("[data-version]")?.textContent === "v0.1.0",
        );
        await checkOverflow(page);
      }
    }
    await page.setViewportSize({ width: 1440, height: 1050 });
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto(origin);
    await waitText(page, "#hostCount", "1");
    await screenshot(page, "dashboard-dark");
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto(origin + "/settings");
    await waitText(page, "#audit", "diagnose");
    await page.locator("#auditSearch").fill("unlikely-no-match");
    await page.locator("#auditEmpty").waitFor({ state: "visible" });
    await page.locator("#auditSearch").fill("");
    await screenshot(page, "settings-desktop");
    await page.getByRole("button", { name: "退出登录", exact: true }).click();
    await page.waitForURL(origin + "/login");
    assert.equal(
      (await context.request.get(origin + "/api/hosts")).status(),
      401,
    );
    assert.deepEqual(errors, [], "No JavaScript or CSP errors");
    console.log(
      "Browser checks passed: setup, auth gates, credential errors, CRUD, proxy protection, diagnostics, history, search, desktop/dark layout, logout.",
    );
  } catch (error) {
    console.error(error.stack);
    if (serverLog) console.error(serverLog);
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    await new Promise((resolve) => server.once("exit", resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  }
})();
