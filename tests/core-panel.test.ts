import { afterEach, expect, test } from "bun:test";
import * as corePanelTestFs from "node:fs";
import * as corePanelTestOs from "node:os";
import * as corePanelTestPath from "node:path";
import { createPaths, createDefaultNode, configFingerprint, runtimeConfigFingerprint, type AppConfig, type DaemonStatus, type NodeProtocol } from "../src/core.ts";
import { readCoreSelection, coreReleaseFingerprint, type CoreReleaseCandidate, type CoreReleaseMap, type CoreSelectionState, type CoreUpdateCheck, type BinaryKind } from "../src/network.ts";
import { runCorePanel, type CorePanelServices } from "../src/core-panel.ts";
import { panelRuntimeMatches } from "../src/panel.ts";

const corePanelTestRoots: string[] = [];
afterEach(() => { for (const root of corePanelTestRoots.splice(0)) corePanelTestFs.rmSync(root, { recursive: true, force: true }); });

function corePanelTestCandidate(releases: CoreReleaseMap, tool: BinaryKind, version: string, prerelease = false): CoreReleaseCandidate {
  const candidate = structuredClone(releases[tool]);
  candidate.version = version; candidate.prerelease = prerelease; candidate.source = "github";
  candidate.tag = tool === "cloudflared" ? version : `v${version}`;
  if (tool === "singBox") {
    candidate.asset.asset = candidate.asset.asset.replace(`sing-box-${releases[tool].version}-`, `sing-box-${version}-`);
    candidate.asset.directory = candidate.asset.directory?.replace(`sing-box-${releases[tool].version}-`, `sing-box-${version}-`);
  }
  candidate.releaseUrl = candidate.releaseUrl.slice(0, candidate.releaseUrl.lastIndexOf("/") + 1) + candidate.tag;
  candidate.downloadUrl = candidate.releaseUrl.replace("/releases/tag/", "/releases/download/") + "/" + candidate.asset.asset;
  candidate.asset.sha256 = "f".repeat(64);
  return candidate;
}

function corePanelTestEnv(protocols: NodeProtocol[] = ["shadowsocks"], answers: number[] = [3]) {
  const root = corePanelTestFs.mkdtempSync(corePanelTestPath.join(corePanelTestOs.tmpdir(), "nexus-core-panel-")); corePanelTestRoots.push(root);
  const paths = createPaths(corePanelTestPath.join(root, "nexus-edge.ts"));
  let state = readCoreSelection(paths);
  const config: AppConfig = { schema: 2, nodes: [], webhook: { kind: "none", url: "" } };
  for (const protocol of protocols) config.nodes.push(createDefaultNode(protocol, config.nodes));
  const menus: { title: string; information: string; choices: string[]; initial: number }[] = [], reports: string[] = [];
  const calls: { channels: string[]; applied: CoreReleaseCandidate[][]; confirmed: CoreSelectionState[]; rollback: CoreSelectionState[]; release: string[]; pause: number } = { channels: [], applied: [], confirmed: [], rollback: [], release: [], pause: 0 };
  let checks: CoreUpdateCheck[] = (["singBox", "xray", "cloudflared"] as const).map(tool => ({ tool, current: state.active[tool], latest: state.active[tool], updateAvailable: false }));
  let status: DaemonStatus | null = null;
  let input = "";
  let specified: CoreReleaseCandidate = state.active.xray;
  const services: Partial<CorePanelServices> = {
    selection: () => structuredClone(state), config: () => structuredClone(config), status: async () => status && structuredClone(status),
    menu: async (title, information, choices, initial = 0) => {
      menus.push({ title, information, choices, initial });
      const answer = answers.shift();
      if (answer === undefined || answer < 0 || answer >= choices.length) throw new Error(`Unplanned menu: ${title}; answer=${answer}`);
      return answer;
    },
    input: async () => input, pause: async () => { calls.pause++; }, report: message => { reports.push(message); },
    check: async (_paths, channel) => { calls.channels.push(channel ?? "stable"); return structuredClone(checks); },
    release: async (tool, version) => { calls.release.push(`${tool}:${version}`); return structuredClone(specified); },
    apply: async (_paths, candidates, _report, _operations, expected) => {
      calls.applied.push(structuredClone(candidates));
      if (!expected) throw new Error("UI omitted the confirmed selection snapshot");
      calls.confirmed.push(structuredClone(expected));
      return { changed: true, restarted: Boolean(status), versions: state.active };
    },
    rollback: async (_paths, _report, _operations, expected) => {
      if (!expected) throw new Error("UI omitted the confirmed rollback snapshot");
      calls.rollback.push(structuredClone(expected));
      return { changed: true, restarted: Boolean(status), versions: state.previous! };
    },
  };
  return { paths, config, menus, reports, calls, answers, services,
    get state() { return state; }, set state(value) { state = value; },
    set checks(value: CoreUpdateCheck[]) { checks = value; },
    set status(value: DaemonStatus | null) { status = value; },
    set input(value: string) { input = value; }, set specified(value: CoreReleaseCandidate) { specified = value; },
  };
}

test("opening core management is read-only and needs no update or tunnel setup", async () => {
  const env = corePanelTestEnv();
  await runCorePanel(env.paths, env.services);
  expect(env.calls.channels).toEqual([]); expect(env.calls.applied).toEqual([]);
  expect(env.menus[0]!.information).toContain("没有隧道就不需要 cloudflared");
  expect(env.menus[0]!.choices[0]).toContain("稳定版");
  expect(corePanelTestFs.readdirSync(env.paths.root)).toEqual([]);
});

test("stable Xray older than selected preview is displayed without an upgrade or downgrade action", async () => {
  const env = corePanelTestEnv(["vless"], [0, 0, 3]);
  // Model a user who explicitly selected a newer preview, independent of defaults.
  env.state.active.xray = corePanelTestCandidate(env.state.active, "xray", "26.10.17", true) as CoreReleaseMap["xray"];
  env.checks = [{ tool: "xray", current: env.state.active.xray, latest: corePanelTestCandidate(env.state.active, "xray", "26.3.27"), updateAvailable: false }];
  await runCorePanel(env.paths, env.services);
  const result = env.menus.find(menu => menu.title === "稳定版检查结果")!;
  expect(result.information).toContain("保持当前版本"); expect(result.choices).toEqual(["返回"]);
  expect(env.calls.applied).toEqual([]); expect(env.calls.channels).toEqual(["stable"]);
});

test("normal upgrade selects only the core required by an SS node", async () => {
  const env = corePanelTestEnv(["shadowsocks"], [0, 0, 0, 3]);
  env.checks = (["singBox", "xray", "cloudflared"] as const).map(tool => ({ tool, current: env.state.active[tool], latest: corePanelTestCandidate(env.state.active, tool, tool === "singBox" ? "1.14.4" : tool === "xray" ? "26.11.1" : "2026.11.1"), updateAvailable: true }));
  await runCorePanel(env.paths, env.services);
  expect(env.calls.applied.map(batch => batch.map(candidate => candidate.tool))).toEqual([["singBox"]]);
  expect(env.calls.confirmed).toEqual([env.state]);
  expect(env.menus.find(menu => menu.title === "确认更新内核")!.information).toContain("后台当前未运行");
  expect(env.reports.some(message => message.includes("后台保持停止"))).toBe(true);
});

test("cancelled update preserves all selections and shows Quick tunnel restart impact", async () => {
  const env = corePanelTestEnv(["vmess"], [0, 0, 1, 3]);
  const node = env.config.nodes[0]!; node.transport.type = "ws"; node.tunnel.mode = "quick";
  env.status = { instanceId: "test-instance", pid: 12345, startedAt: "2026-10-21T00:00:00Z", configHash: configFingerprint(env.config), runtimeConfigHash: runtimeConfigFingerprint(env.config), coreReleaseHash: coreReleaseFingerprint(env.state.active), phase: "ready", cores: {}, nodes: [], links: [], lastError: null };
  env.checks = [{ tool: "singBox", current: env.state.active.singBox, latest: corePanelTestCandidate(env.state.active, "singBox", "1.14.4"), updateAvailable: true }];
  await runCorePanel(env.paths, env.services);
  expect(env.calls.applied).toEqual([]); expect(env.calls.confirmed).toEqual([]);
  expect(env.menus.find(menu => menu.title === "确认更新内核")!.information).toContain("临时隧道域名可能改变");
});

test("checking updates with no enabled node defaults to return rather than download unused cores", async () => {
  const env = corePanelTestEnv([], [0, 1, 3]);
  env.checks = [{ tool: "singBox", current: env.state.active.singBox, latest: corePanelTestCandidate(env.state.active, "singBox", "1.14.4"), updateAvailable: true }];
  await runCorePanel(env.paths, env.services);
  const result = env.menus.find(menu => menu.title === "稳定版检查结果")!;
  expect(result.choices).toEqual(["单独选择内核更新", "返回"]); expect(result.initial).toBe(1);
  expect(env.calls.applied).toEqual([]);
});

test("preview checks are behind advanced options and still compare selected versions", async () => {
  const env = corePanelTestEnv(["shadowsocks"], [2, 0, 0, 0, 3]);
  env.checks = [{ tool: "singBox", current: env.state.active.singBox, latest: corePanelTestCandidate(env.state.active, "singBox", "1.15.0-alpha.12", true), updateAvailable: true }];
  await runCorePanel(env.paths, env.services);
  expect(env.calls.channels).toEqual(["preview"]);
  expect(env.menus.find(menu => menu.title === "确认更新内核")!.information).toContain("预发布版可能改变配置");
  expect(env.calls.applied[0]![0]!.version).toBe("1.15.0-alpha.12");
});

test("explicit version selection displays a downgrade and passes the reviewed selection to the updater", async () => {
  const env = corePanelTestEnv(["vless"], [2, 1, 1, 0, 3]);
  env.state.active.xray = corePanelTestCandidate(env.state.active, "xray", "26.10.17", true) as CoreReleaseMap["xray"];
  env.input = "v26.3.27"; env.specified = corePanelTestCandidate(env.state.active, "xray", "26.3.27");
  await runCorePanel(env.paths, env.services);
  expect(env.calls.release).toEqual(["xray:v26.3.27"]);
  expect(env.menus.find(menu => menu.title === "确认更新内核")!.information).toContain("降级");
  expect(env.menus.find(menu => menu.title === "确认更新内核")!.information).toContain("26.10.17 → 26.3.27");
  expect(env.calls.confirmed).toEqual([env.state]);
  expect(env.calls.applied[0]![0]!.version).toBe("26.3.27");
});

test("a stale automatic update result cannot propose a downgrade after another panel upgraded", async () => {
  const env = corePanelTestEnv(["shadowsocks"], [0, 0, 3]);
  env.checks = [{ tool: "singBox", current: env.state.active.singBox, latest: corePanelTestCandidate(env.state.active, "singBox", "1.14.4"), updateAvailable: true }];
  const originalMenu = env.services.menu!;
  env.services.menu = async (...args) => {
    const value = await originalMenu(...args);
    if (args[0] === "稳定版检查结果") env.state.active.singBox.version = "1.15.0";
    return value;
  };
  await runCorePanel(env.paths, env.services);
  expect(env.calls.applied).toEqual([]);
  expect(env.menus.some(menu => menu.title === "确认更新内核")).toBe(false);
});

test("rollback confirmation captures the exact previous release set", async () => {
  const env = corePanelTestEnv(["shadowsocks"], [1, 0, 3]);
  env.state.previous = structuredClone(env.state.active);
  env.state.active.singBox = corePanelTestCandidate(env.state.active, "singBox", "1.14.4") as CoreReleaseMap["singBox"];
  await runCorePanel(env.paths, env.services);
  expect(env.calls.rollback).toEqual([env.state]);
  expect(env.menus.find(menu => menu.title === "确认回退内核")!.information).toContain("1.14.4 → 1.14.3");
  expect(env.calls.applied).toEqual([]);
});

test("panel runtime identity includes core versions while retaining old-worker compatibility", () => {
  const env = corePanelTestEnv();
  const status: DaemonStatus = { instanceId: "test-instance", pid: 12345, startedAt: "2026-10-21T00:00:00Z", configHash: configFingerprint(env.config), runtimeConfigHash: runtimeConfigFingerprint(env.config), coreReleaseHash: coreReleaseFingerprint(env.state.active), phase: "ready", cores: {}, nodes: [], links: [], lastError: null };
  expect(panelRuntimeMatches(status, env.config, env.paths)).toBe(true);
  expect(panelRuntimeMatches({ ...status, coreReleaseHash: "f".repeat(64) }, env.config, env.paths)).toBe(false);
  expect(panelRuntimeMatches({ ...status, coreReleaseHash: undefined }, env.config, env.paths)).toBe(true);
  corePanelTestFs.mkdirSync(env.paths.bin, { recursive: true });
  corePanelTestFs.writeFileSync(corePanelTestPath.join(env.paths.bin, "core-versions.json"), JSON.stringify(env.state));
  expect(panelRuntimeMatches({ ...status, coreReleaseHash: undefined }, env.config, env.paths)).toBe(false);
});
