import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AppConfig, type DaemonStatus, configFingerprint, createDefaultNode, createPaths, defaultConfig, getFirewallSettings, readConfig, runtimeConfigFingerprint, validateConfig, validateFirewallSettings, writeConfig } from "../src/core.ts";
import { buildFirewallPlan, type FirewallResult } from "../src/firewall.ts";
import { firewallPanelSummary, firewallPortSummary } from "../src/firewall-panel.ts";
import { panelApplyConfiguration, panelStopAll, type PanelRuntimeOperations } from "../src/panel.ts";
import { type StartupStatus } from "../src/platform.ts";

const integrationDirs: string[] = [];
const integrationLogs: ReturnType<typeof spyOn>[] = [];
afterEach(() => {
  for (const log of integrationLogs.splice(0)) log.mockRestore();
  for (const root of integrationDirs.splice(0)) rmSync(root, { recursive: true, force: true });
});

function firewallIntegration() {
  const root = mkdtempSync(join(tmpdir(), "nexus-firewall-integration-")); integrationDirs.push(root);
  integrationLogs.push(spyOn(console, "log").mockImplementation(() => {}));
  const paths = createPaths(join(root, "nexus-edge.ts"));
  const config: AppConfig = { ...defaultConfig(), nodes: [createDefaultNode("shadowsocks")] };
  config.nodes[0]!.address = "198.51.100.20";
  writeConfig(paths, config);
  const events: string[] = [], plans: AppConfig[] = [];
  const startup: StartupStatus = { mode: "none", enabled: false, running: true, detail: "Test portable worker" };
  const status: DaemonStatus = { instanceId: "firewall-test", pid: 1, startedAt: "2026-10-21T00:00:00Z", configHash: configFingerprint(config), runtimeConfigHash: runtimeConfigFingerprint(config), phase: "ready", cores: {}, nodes: [], links: [], lastError: null };
  const state = { status: status as DaemonStatus | null, firewallStatus: "synced" as FirewallResult["status"], running: true };
  const operations: PanelRuntimeOperations = {
    getStatus: async () => { events.push("status"); return state.status; },
    prepare: async (_paths, candidate = config) => { events.push("preflight"); return candidate; },
    syncFirewall: async (_paths, candidate, options) => {
      events.push(options?.remove ? "cleanup" : "firewall"); plans.push(structuredClone(candidate));
      const plan = buildFirewallPlan(paths, options?.remove ? { ...candidate, nodes: [] } : candidate);
      const result: FirewallResult = { backend: "windows", status: state.firewallStatus, changed: true, detail: "Synthetic firewall result", warnings: [], rules: plan.rules };
      options?.report?.(result); return result;
    },
    getStartup: async () => { events.push("startup"); return startup; },
    stop: async () => { events.push("stop"); state.running = false; },
    start: async () => { events.push("start"); state.running = true; },
    readiness: async () => { events.push("readiness"); },
    save: (target, candidate) => { events.push("save"); writeConfig(target, candidate); },
  };
  const changed = structuredClone(config); changed.nodes[0]!.port += 1; changed.nodes[0]!.publicPort += 1;
  return { paths, config, changed, events, plans, operations, startup, state };
}

describe("firewall configuration compatibility", () => {
  test("old schema-2 files default to auto without a rewrite or schema migration", () => {
    const old = defaultConfig();
    expect(getFirewallSettings(old)).toEqual({ mode: "auto", linuxBackend: "auto", firewalldZone: "" });
    expect(validateConfig(old)).toEqual(old);
    expect(validateConfig(old)).not.toHaveProperty("firewall");
    const oldWithNode = { ...old, nodes: [createDefaultNode("shadowsocks")] };
    const legacyRuntime = { ...oldWithNode, nodes: oldWithNode.nodes.map(({ address, publicPort, ...node }) => node) };
    const originalHash = createHash("sha256").update(JSON.stringify(legacyRuntime)).digest("hex");
    const changed = { ...oldWithNode, firewall: { mode: "manual" as const, linuxBackend: "firewalld" as const, firewalldZone: "public" } };
    expect(runtimeConfigFingerprint(oldWithNode)).toBe(originalHash);
    expect(runtimeConfigFingerprint(changed)).toBe(originalHash);
    expect(configFingerprint(changed)).not.toBe(configFingerprint(oldWithNode));
    expect(validateConfig(changed).firewall).toEqual(changed.firewall);
  });

  test("rejects invalid preferences and command-like zone text", () => {
    const valid = getFirewallSettings(defaultConfig());
    for (const firewall of [null, [], {}, { ...valid, mode: "yes" }, { ...valid, linuxBackend: "nft" }, { ...valid, firewalldZone: "public; reboot" }, { ...valid, firewalldZone: "public\n--reload" }, { ...valid, firewalldZone: "x".repeat(33) }]) {
      expect(() => validateConfig({ ...defaultConfig(), firewall })).toThrow();
    }
    expect(validateFirewallSettings({ ...valid, firewalldZone: "public-v6_1" }).firewalldZone).toBe("public-v6_1");
  });

  test("the menu distinguishes pending automatic work from manual management", () => {
    const env = firewallIntegration();
    expect(firewallPanelSummary(env.paths, env.config)).toContain("应用时检查");
    expect(firewallPortSummary(buildFirewallPlan(env.paths, env.config).rules)).toBe("TCP 8388、UDP 8388");
    expect(firewallPanelSummary(env.paths, { ...env.config, firewall: { ...getFirewallSettings(env.config), mode: "manual" } })).toContain("手动管理");
  });
});

describe("applying nodes and firewall changes together", () => {
  test("preflights and synchronizes ports before saving or stopping a running worker", async () => {
    const env = firewallIntegration();
    await panelApplyConfiguration(env.paths, env.changed, {}, env.operations);
    expect(env.events).toEqual(["status", "preflight", "firewall", "save", "startup", "stop", "start", "readiness"]);
    expect(readConfig(env.paths).nodes[0]!.port).toBe(8389);
    expect(env.plans[0]!.nodes[0]!.port).toBe(8389);
    expect(env.state.running).toBe(true);
  });

  test("failed core preflight cannot request elevation or change the firewall", async () => {
    const env = firewallIntegration(), before = readFileSync(env.paths.config, "utf8");
    env.operations.prepare = async () => { throw new Error("Core config rejected"); };
    await expect(panelApplyConfiguration(env.paths, env.changed, {}, env.operations)).rejects.toThrow("Core config rejected");
    expect(env.events).toEqual(["status"]);
    expect(readFileSync(env.paths.config, "utf8")).toBe(before);
    expect(env.state.running).toBe(true);
  });

  test("canceling UAC preserves the exact saved file and running worker", async () => {
    const env = firewallIntegration(), before = readFileSync(env.paths.config, "utf8");
    env.operations.syncFirewall = async () => { env.events.push("UAC"); throw new Error("UAC 已取消"); };
    await expect(panelApplyConfiguration(env.paths, env.changed, {}, env.operations)).rejects.toThrow("UAC 已取消");
    expect(env.events).toEqual(["status", "preflight", "UAC"]);
    expect(readFileSync(env.paths.config, "utf8")).toBe(before);
    expect(env.state.running).toBe(true);
  });

  test.each(["blocked", "error", "permission-required", "needs-update"] as const)("a %s firewall result preserves the previous configuration", async firewallStatus => {
    const env = firewallIntegration(); env.state.firewallStatus = firewallStatus;
    await expect(panelApplyConfiguration(env.paths, env.changed, {}, env.operations)).rejects.toThrow("已保留原配置与后台");
    expect(env.events).not.toContain("stop"); expect(env.events).not.toContain("save");
    expect(readConfig(env.paths)).toEqual(env.config);
  });

  test.each(["inactive", "unsupported"] as const)("a clearly reported %s firewall does not prevent a local start", async firewallStatus => {
    const env = firewallIntegration(); env.state.firewallStatus = firewallStatus;
    await panelApplyConfiguration(env.paths, env.changed, {}, env.operations);
    expect(env.events).toContain("start"); expect(readConfig(env.paths)).toEqual(env.changed);
  });

  test("client-address-only changes still check firewall rules without reconnecting the worker", async () => {
    const env = firewallIntegration(), candidate = structuredClone(env.config);
    candidate.nodes[0]!.address = "203.0.113.25";
    await panelApplyConfiguration(env.paths, candidate, {}, env.operations);
    expect(env.events).toEqual(["status", "firewall", "save"]);
    expect(readConfig(env.paths).nodes[0]!.address).toBe("203.0.113.25");
  });

  test("explicit restart checks the firewall even when runtime configuration is unchanged", async () => {
    const env = firewallIntegration();
    await panelApplyConfiguration(env.paths, env.config, { forceRestart: true }, env.operations);
    expect(env.events).toEqual(["status", "preflight", "firewall", "save", "startup", "stop", "start", "readiness"]);
    expect(env.events).not.toContain("cleanup");
  });

  test("concurrent edits after preflight are not overwritten", async () => {
    const env = firewallIntegration(), competing = structuredClone(env.config);
    competing.nodes[0]!.name = "Edited in another panel";
    const sync = env.operations.syncFirewall;
    env.operations.syncFirewall = async (...args) => { const result = await sync(...args); writeConfig(env.paths, competing); return result; };
    await expect(panelApplyConfiguration(env.paths, env.changed, {}, env.operations)).rejects.toThrow("准备过程中被修改");
    expect(readConfig(env.paths)).toEqual(competing); expect(env.events).not.toContain("stop");
  });

  test("failure to save compensates with the previous port plan before returning the error", async () => {
    const env = firewallIntegration();
    env.operations.save = () => { throw new Error("Storage is read-only"); };
    await expect(panelApplyConfiguration(env.paths, env.changed, {}, env.operations)).rejects.toThrow("Storage is read-only");
    expect(env.plans.map(plan => plan.nodes[0]!.port)).toEqual([8389, 8388]);
    expect(readConfig(env.paths)).toEqual(env.config); expect(env.events).not.toContain("stop");
  });

  test("disabling the last node synchronizes an empty plan and stops without starting", async () => {
    const env = firewallIntegration(); env.changed.nodes[0]!.enabled = false;
    await panelApplyConfiguration(env.paths, env.changed, {}, env.operations);
    expect(buildFirewallPlan(env.paths, env.plans[0]!).rules).toEqual([]);
    expect(env.events).toEqual(["status", "firewall", "save", "startup", "stop"]);
  });
});

describe("explicit stop and firewall ownership", () => {
  test("cleans owned rules only after the worker has stopped", async () => {
    const env = firewallIntegration();
    await panelStopAll(env.paths, env.startup, env.operations);
    expect(env.events).toEqual(["stop", "cleanup"]);
    expect(readConfig(env.paths)).toEqual(env.config);
  });

  test("a failed stop cannot remove rules from a still-running worker", async () => {
    const env = firewallIntegration(); env.operations.stop = async () => { throw new Error("Worker is still running"); };
    await expect(panelStopAll(env.paths, env.startup, env.operations)).rejects.toThrow("still running");
    expect(env.events).not.toContain("cleanup");
  });

  test("manual mode leaves existing rules alone when stopping", async () => {
    const env = firewallIntegration();
    writeConfig(env.paths, { ...env.config, firewall: { ...getFirewallSettings(env.config), mode: "manual" } });
    await panelStopAll(env.paths, env.startup, env.operations);
    expect(env.events).toEqual(["stop"]);
  });

  test("canceling cleanup never restarts a worker which has already stopped", async () => {
    const env = firewallIntegration(); env.operations.syncFirewall = async () => { throw new Error("UAC 已取消"); };
    await panelStopAll(env.paths, env.startup, env.operations);
    expect(env.state.running).toBe(false); expect(env.events).toEqual(["stop"]);
  });
});
