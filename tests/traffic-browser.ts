/** Real Chromium UI checks with entirely synthetic local history; no installed node/config is accessed. */
import { chromium } from "playwright";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";
import { createPaths, createDefaultNode } from "../src/core.ts";
import { TrafficStore } from "../src/traffic-store.ts";
import { startTrafficDashboard } from "../src/traffic-web.ts";

const root = mkdtempSync(join(tmpdir(), "nexus-traffic-browser-"));
const paths = createPaths(join(root, "app.ts")), store = new TrafficStore(paths);
const a = { ...createDefaultNode("vless"), name: "主入口 · 日常使用", port: 443 };
const b = { ...createDefaultNode("vless"), name: "备用入口 · 按需连接", port: 8943 };
const s = { ...createDefaultNode("socks"), name: "工作设备 · SOCKS5", port: 1080 };
const now = Date.now(); let up = 0, down = 0, su = 0, sd = 0;
for (let i = 0; i < 25; i++) {
  up += (50 + i * 3) * 1024 ** 2; down += (500 + (i % 6) * 280) * 1024 ** 2;
  const at = now - (24 - i) * 3600_000 - 20000;
  store.apply("xray", "synthetic-xray", [a, b], { up, down, nodes: [{ id: a.id, up: up * .75, down: down * .875 }, { id: b.id, up: up * .25, down: down * .125 }], connections: [], peers: [{ nodeId: a.id, ip: "192.0.2.17", seenAt: at }], peersAvailable: true }, at);
  su += 4 * 1024 ** 2; sd += (50 + i * 5) * 1024 ** 2;
  store.apply("singBox", "synthetic-sing", [s], { up: su, down: sd, nodes: [], connections: [{ id: "demo-session", nodeId: s.id, ip: "198.51.100.28", up: su / 2, down: sd / 2, closed: false }], peers: [], peersAvailable: true }, at);
}
store.apply("xray", "synthetic-xray", [a, b], { up: up + 4 * 1024 ** 2, down: down + 20 * 1024 ** 2, nodes: [{ id: a.id, up: up * .75 + 4 * 1024 ** 2, down: down * .875 + 20 * 1024 ** 2 }, { id: b.id, up: up * .25, down: down * .125 }], connections: [], peers: [{ nodeId: a.id, ip: "192.0.2.17", seenAt: now - 10000 }], peersAvailable: true }, now - 10000);
store.apply("singBox", "synthetic-sing", [s], { up: su + 1024 ** 2, down: sd + 3 * 1024 ** 2, nodes: [], connections: [{ id: "demo-session", nodeId: s.id, ip: "198.51.100.28", up: su / 2, down: sd / 2, closed: false }], peers: [], peersAvailable: true }, now - 10000);
const dashboard = startTrafficDashboard(paths);
const browser = await chromium.launch({ headless: true, ...(process.env.NEXUS_EDGE_CHROMIUM_BINARY ? { executablePath: process.env.NEXUS_EDGE_CHROMIUM_BINARY } : {}) });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors: string[] = [], external: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => { if (new URL(request.url()).origin !== new URL(dashboard.url).origin) external.push(request.url()); });
  await page.goto(dashboard.url); await page.waitForFunction(() => document.getElementById("total")!.textContent !== "—");
  assert.equal(await page.locator("h1").textContent(), "流量分析");
  assert.equal(await page.locator("#node-rows tr").count(), 3);
  assert.match(await page.locator("#node-rows").innerText(), /443/); assert.match(await page.locator("#node-rows").innerText(), /8943/);
  assert.ok(await page.locator("#chart svg rect").count() > 10);
  assert.match(await page.locator("#peer-rows").innerText(), /核心未提供/);
  await page.locator('aside a[href="#peers"]').click();
  assert.equal(page.url(), dashboard.url, "Sidebar navigation must preserve the access-code fragment for reloads");
  const screenshotDir = process.env.NEXUS_EDGE_SCREENSHOTS ? resolve(process.env.NEXUS_EDGE_SCREENSHOTS) : undefined;
  if (screenshotDir) {
    mkdirSync(screenshotDir, { recursive: true });
    await page.locator(".eyebrow").evaluate(element => { element.textContent = "SYNTHETIC DATA · 合成数据示意"; });
    await page.screenshot({ path: join(screenshotDir, "traffic-desktop.png"), fullPage: true });
  }
  await page.getByRole("button", { name: "sing-box", exact: true }).click();
  assert.equal(await page.locator("#node-rows tr").count(), 1); assert.match(await page.locator("#node-rows").innerText(), /观察下限/);
  await page.getByRole("button", { name: "全部核心", exact: true }).click();
  await page.getByRole("searchbox").fill("8943"); assert.equal(await page.locator("#node-rows tr").count(), 1);
  await page.getByRole("searchbox").fill("");
  await page.locator("#node-rows tr").filter({ hasText: "主入口" }).click();
  assert.match(await page.locator("#peer-filter").textContent() ?? "", /443/);
  assert.match(await page.locator("#peer-rows").innerText(), /192\.0\.2\.17/);
  await page.getByRole("button", { name: "清除节点筛选" }).click();
  const before = await page.locator("#total").textContent();
  await page.getByRole("button", { name: "近 1 小时", exact: true }).click();
  await page.waitForFunction(value => document.getElementById("total")!.textContent !== value, before);
  await page.getByRole("button", { name: "近 24 小时", exact: true }).click();
  await page.waitForFunction(value => document.getElementById("total")!.textContent === value, before);
  await page.route("**/api/report?range=1h", async route => { await new Promise(resolve => setTimeout(resolve, 150)); await route.continue(); });
  const latest = page.waitForResponse(response => response.url().endsWith("range=24h"));
  await page.evaluate(() => {
    for (const range of ["1h", "30d", "24h"]) (document.querySelector('[data-range="' + range + '"]') as HTMLButtonElement).click();
  });
  await latest;
  assert.equal(await page.locator("#total").textContent(), before);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  if (screenshotDir) await page.screenshot({ path: join(screenshotDir, "traffic-mobile.png"), fullPage: true });
  const evil = { ...createDefaultNode("vless"), name: '<img src=x onerror="window.__trafficXss=1">', port: 4433 };
  store.apply("xray", "synthetic-xss", [evil], { up: 100, down: 100, nodes: [{ id: evil.id, up: 100, down: 100 }], connections: [], peers: [], peersAvailable: true });
  await page.reload(); await page.waitForFunction(() => document.getElementById("node-rows")!.textContent!.includes("__trafficXss"));
  assert.equal(await page.locator("#node-rows img").count(), 0); assert.equal(await page.evaluate(() => (window as any).__trafficXss), undefined);
  const unauthorized = await browser.newPage(); await unauthorized.goto(new URL(dashboard.url).origin); await unauthorized.locator("#error").waitFor({ state: "visible" });
  assert.equal(await unauthorized.locator("#total").textContent(), "—");
  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  await dashboard.close();
  await page.getByRole("button", { name: "近 1 小时", exact: true }).click();
  await page.locator("#error").waitFor({ state: "visible" });
  assert.equal(await page.locator("#rate").textContent(), "—");
  console.log("PASS Chromium: charts, rapid range changes, core/port/source filters, 390px layout, XSS escaping, no external requests, missing-token and disconnected states");
} finally { await browser.close(); await dashboard.close(); store.close(); rmSync(root, { recursive: true, force: true }); }
