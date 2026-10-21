import { describe, expect, test } from "bun:test";
import { createPaths, type DaemonStatus, type AppPaths } from "../src/core.ts";
import { migrateSystemInstallation, type MigrationOperations } from "../src/migration.ts";
import type { StartupStatus } from "../src/platform.ts";

// Pure state-machine tests: every external operation is injected. These tests
// never copy to system directories, register a task/service, elevate, send a
// webhook, download an executable, or connect to Cloudflare.
type Side = "source" | "target";
interface Fault { step: string; afterEffect?: boolean }
interface ScenarioOptions {
  startup?: Partial<StartupStatus>;
  sourceRunning?: boolean;
  sourceStatusVisible?: boolean;
  readiness?: DaemonStatus | null;
  faults?: Fault[];
}

function readyStatus(): DaemonStatus {
  return {
    instanceId: "11111111-1111-4111-8111-111111111111", pid: 1001,
    startedAt: "2026-10-21T00:00:00.000Z", configHash: "1".repeat(64),
    phase: "ready", cores: { xray: { state: "running", restarts: 0, lastError: null } },
    nodes: [], links: [], lastError: null,
  };
}

function scenario(options: ScenarioOptions = {}) {
  const source = createPaths("/virtual/nexus-edge-source/nexus-edge.ts", "/virtual/portable-bun");
  const target = createPaths("/virtual/nexus-edge-system/nexus-edge.ts", "/virtual/system-bun");
  const startup: StartupStatus = {
    mode: "none", enabled: false, running: options.sourceRunning ?? true,
    detail: "Synthetic manager state", ...options.startup,
  };
  const state = {
    sourceRunning: options.sourceRunning ?? true,
    targetRunning: false,
    sourceEnabled: startup.enabled,
    targetEnabled: false,
    targetExists: false,
    targetValidated: false,
    active: false,
  };
  const events: string[] = [];
  const pendingFaults = [...(options.faults ?? [])];
  const side = (paths: AppPaths): Side => {
    if (paths === source) return "source";
    if (paths === target) return "target";
    throw new Error("Unexpected installation paths passed to migration operation");
  };
  const step = (name: string, paths: AppPaths, effect?: () => void, mode?: string): void => {
    const key = `${name}:${side(paths)}${mode ? `:${mode}` : ""}`;
    events.push(key);
    const index = pendingFaults.findIndex(fault => fault.step === key);
    const fault = index < 0 ? undefined : pendingFaults.splice(index, 1)[0];
    if (fault && !fault.afterEffect) throw new Error(`Injected failure at ${key}`);
    effect?.();
    if (fault) throw new Error(`Injected failure at ${key} after its side effect`);
  };
  const start = (paths: AppPaths): void => {
    // Source and target use the same local port. Our synthetic manager rejects
    // an unsafe overlap rather than allowing a bad transition to look healthy.
    if (side(paths) === "source") {
      if (state.targetRunning) throw new Error("Port is still owned by the target");
      state.sourceRunning = true;
    } else {
      if (state.sourceRunning) throw new Error("Port is still owned by the source");
      state.targetRunning = true;
    }
  };
  const stop = (paths: AppPaths): void => {
    if (side(paths) === "source") state.sourceRunning = false;
    else state.targetRunning = false;
  };
  const operations: MigrationOperations = {
    async getStartup(paths) { step("getStartup", paths); return { ...startup }; },
    async getStatus(paths) {
      step("getStatus", paths);
      return state.sourceRunning && options.sourceStatusVisible !== false ? readyStatus() : null;
    },
    async copy(paths) {
      step("copy", paths, () => { state.targetExists = true; });
      return target;
    },
    async preflight(paths) { step("preflight", paths, () => { state.targetValidated = true; }); },
    async enable(paths, mode) {
      step("enable", paths, () => {
        if (side(paths) === "source") state.sourceEnabled = true;
        else state.targetEnabled = true;
      }, mode);
    },
    async disable(paths) {
      step("disable", paths, () => {
        if (side(paths) === "source") state.sourceEnabled = false;
        else state.targetEnabled = false;
      });
    },
    async startManaged(paths) { step("startManaged", paths, () => start(paths)); },
    async stopManaged(paths) { step("stopManaged", paths, () => stop(paths)); },
    async startPortable(paths) { step("startPortable", paths, () => start(paths)); },
    async stopPortable(paths) { step("stopPortable", paths, () => stop(paths)); },
    async waitReady(paths) {
      step("waitReady", paths);
      if (!state.targetRunning) throw new Error("Cannot validate readiness of a stopped target");
      return options.readiness === undefined ? readyStatus() : options.readiness;
    },
    async activate(paths) { step("activate", paths, () => { state.active = true; }); },
    async deactivate(paths) { step("deactivate", paths, () => { state.active = false; }); },
  };
  return { source, target, state, events, operations };
}

function before(events: string[], first: string, second: string): void {
  expect(events).toContain(first);
  expect(events).toContain(second);
  expect(events.indexOf(first)).toBeLessThan(events.indexOf(second));
}

describe("system installation migration with injected operations", () => {
  test("prepares target firewall ownership before stopping source and cleans source only after activation", async () => {
    const s = scenario();
    s.operations.prepareFirewall = async (source, target) => {
      expect(source).toBe(s.source); expect(target).toBe(s.target); expect(s.state.sourceRunning).toBe(true);
      s.events.push("firewall:prepare");
      return {
        rollback: async () => { s.events.push("firewall:rollback"); },
        complete: async () => { expect(s.state.active).toBe(true); expect(s.state.targetRunning).toBe(true); s.events.push("firewall:complete"); },
      };
    };
    await migrateSystemInstallation(s.source, s.operations);
    before(s.events, "preflight:target", "firewall:prepare");
    before(s.events, "firewall:prepare", "stopPortable:source");
    before(s.events, "activate:target", "firewall:complete");
    expect(s.events).not.toContain("firewall:rollback");
  });

  test("failed target startup restores source firewall ownership before restarting source", async () => {
    const s = scenario({ faults: [{ step: "startManaged:target", afterEffect: true }] });
    s.operations.prepareFirewall = async () => ({
      rollback: async () => { expect(s.state.targetRunning).toBe(false); s.events.push("firewall:rollback"); },
      complete: async () => { s.events.push("firewall:complete"); },
    });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("startManaged:target");
    before(s.events, "stopManaged:target", "firewall:rollback");
    before(s.events, "firewall:rollback", "startPortable:source");
    expect(s.events).not.toContain("firewall:complete");
  });

  test("does not remove target rules while a failed target cannot be safely stopped", async () => {
    const s = scenario({ faults: [{ step: "startManaged:target", afterEffect: true }, { step: "stopManaged:target" }] });
    s.operations.prepareFirewall = async () => ({ rollback: async () => { s.events.push("firewall:rollback"); }, complete: async () => {} });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("系统副本停止失败");
    expect(s.events).not.toContain("firewall:rollback"); expect(s.events).not.toContain("startPortable:source");
  });

  test("a blocked firewall preparation never stops the existing source", async () => {
    const s = scenario();
    s.operations.prepareFirewall = async () => { throw new Error("Firewall policy blocks migration"); };
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("Firewall policy blocks migration");
    expect(s.events).not.toContain("stopPortable:source"); expect(s.state.sourceRunning).toBe(true);
  });

  test("source-rule cleanup failure leaves the ready target active", async () => {
    const s = scenario();
    s.operations.prepareFirewall = async () => ({
      rollback: async () => { s.events.push("firewall:rollback"); },
      complete: async () => { throw new Error("Old rule cleanup failed"); },
    });
    expect(await migrateSystemInstallation(s.source, s.operations)).toBe(s.target);
    expect(s.state.active).toBe(true); expect(s.state.targetRunning).toBe(true);
    expect(s.events).not.toContain("firewall:rollback");
  });

  test("validates a copy before stopping the portable source and activates only a ready target", async () => {
    const s = scenario();
    const result = await migrateSystemInstallation(s.source, s.operations);
    expect(result).toBe(s.target);
    expect(s.state).toEqual({
      sourceRunning: false, targetRunning: true, sourceEnabled: false,
      targetEnabled: true, targetExists: true, targetValidated: true, active: true,
    });
    before(s.events, "copy:source", "preflight:target");
    before(s.events, "preflight:target", "stopPortable:source");
    before(s.events, "stopPortable:source", "startManaged:target");
    before(s.events, "waitReady:target", "activate:target");
    expect(s.events).not.toContain("disable:source");
    expect(s.events).not.toContain("stopManaged:source");
  });

  test("preserves the original autostart definition until the replacement reports ready", async () => {
    const s = scenario({ startup: { mode: "windows-user", enabled: true } });
    await migrateSystemInstallation(s.source, s.operations);
    before(s.events, "preflight:target", "stopManaged:source");
    before(s.events, "waitReady:target", "disable:source");
    before(s.events, "disable:source", "activate:target");
    expect(s.state.sourceEnabled).toBe(false);
    expect(s.state.targetEnabled).toBe(true);
    expect(s.events).not.toContain("stopPortable:source");
  });

  for (const failedStep of ["copy:source", "preflight:target"]) {
    test(`${failedStep} failure leaves the original running node and autostart untouched`, async () => {
      const s = scenario({ startup: { mode: "windows-user", enabled: true }, faults: [{ step: failedStep }] });
      await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow(failedStep);
      expect(s.state.sourceRunning).toBe(true);
      expect(s.state.sourceEnabled).toBe(true);
      expect(s.state.targetRunning).toBe(false);
      expect(s.state.targetEnabled).toBe(false);
      expect(s.state.active).toBe(false);
      expect(s.events).not.toContain("stopManaged:source");
      expect(s.events).not.toContain("stopPortable:source");
      expect(s.events).not.toContain("disable:source");
      expect(s.events).not.toContain("activate:target");
    });
  }

  test("does not start the target when stopping the source fails", async () => {
    const s = scenario({ faults: [{ step: "stopPortable:source" }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("stopPortable:source");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.state.targetRunning).toBe(false);
    expect(s.state.active).toBe(false);
    expect(s.events).not.toContain("enable:target:system");
    expect(s.events).not.toContain("startManaged:target");
    expect(s.events).not.toContain("startPortable:source");
  });

  test("undoes a partially successful target registration and restores the portable source", async () => {
    const s = scenario({ faults: [{ step: "enable:target:system", afterEffect: true }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("enable:target:system");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.state.targetEnabled).toBe(false);
    expect(s.state.targetRunning).toBe(false);
    expect(s.state.active).toBe(false);
    before(s.events, "disable:target", "startPortable:source");
    expect(s.events).not.toContain("startManaged:target");
  });

  test("stops a target that started before reporting failure, then restores the source without overlapping ports", async () => {
    const s = scenario({ faults: [{ step: "startManaged:target", afterEffect: true }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("startManaged:target");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.state.targetRunning).toBe(false);
    expect(s.state.targetEnabled).toBe(false);
    expect(s.state.active).toBe(false);
    before(s.events, "stopManaged:target", "startPortable:source");
    before(s.events, "disable:target", "startPortable:source");
    before(s.events, "deactivate:target", "startPortable:source");
  });

  for (const readiness of [null, { ...readyStatus(), phase: "degraded" as const, links: [], lastError: "Synthetic tunnel unavailable" }]) {
    test(`rolls back a ${readiness === null ? "missing" : "degraded"} readiness result without disabling source autostart`, async () => {
      const s = scenario({ startup: { mode: "windows-user", enabled: true }, readiness });
      await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("尚未就绪");
      expect(s.state.sourceRunning).toBe(true);
      expect(s.state.sourceEnabled).toBe(true);
      expect(s.state.targetRunning).toBe(false);
      expect(s.state.targetEnabled).toBe(false);
      expect(s.state.active).toBe(false);
      expect(s.events).not.toContain("disable:source");
      expect(s.events).not.toContain("activate:target");
      before(s.events, "stopManaged:target", "startManaged:source");
    });
  }

  test("handles a thrown readiness error with the same target cleanup and source recovery", async () => {
    const s = scenario({ faults: [{ step: "waitReady:target" }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("waitReady:target");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.state.targetRunning).toBe(false);
    expect(s.state.targetEnabled).toBe(false);
    expect(s.state.active).toBe(false);
  });

  for (const failedStep of ["disable:source", "activate:target"]) {
    test(`restores the original user startup mode after ${failedStep} partially succeeds`, async () => {
      const s = scenario({ startup: { mode: "windows-user", enabled: true }, faults: [{ step: failedStep, afterEffect: true }] });
      await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow(failedStep);
      expect(s.state.sourceRunning).toBe(true);
      expect(s.state.sourceEnabled).toBe(true);
      expect(s.state.targetRunning).toBe(false);
      expect(s.state.targetEnabled).toBe(false);
      expect(s.state.active).toBe(false);
      before(s.events, "stopManaged:target", "startManaged:source");
      before(s.events, "disable:target", "enable:source:user");
      before(s.events, "enable:source:user", "startManaged:source");
      expect(s.events).not.toContain("enable:source:system");
      expect(s.events).not.toContain("startPortable:source");
    });
  }

  test("does not start a source that was already stopped before a failed migration", async () => {
    const s = scenario({ sourceRunning: false, startup: { mode: "windows-user", enabled: true, running: false }, faults: [{ step: "startManaged:target" }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("startManaged:target");
    expect(s.state.sourceRunning).toBe(false);
    expect(s.state.sourceEnabled).toBe(true);
    expect(s.events).not.toContain("startManaged:source");
    expect(s.events).not.toContain("startPortable:source");
  });

  test("restores a manually running managed source while keeping its original autostart disabled", async () => {
    const s = scenario({ startup: { mode: "windows-user", enabled: false }, faults: [{ step: "waitReady:target" }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("waitReady:target");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.state.sourceEnabled).toBe(false);
    expect(s.events).toContain("startManaged:source");
    expect(s.events).not.toContain("enable:source:user");
    expect(s.events).not.toContain("startPortable:source");
  });

  test("uses the system manager's running state when source IPC is temporarily unavailable", async () => {
    const s = scenario({ sourceStatusVisible: false, startup: { mode: "linux-system", enabled: true, running: true }, faults: [{ step: "enable:target:system" }] });
    await expect(migrateSystemInstallation(s.source, s.operations)).rejects.toThrow("enable:target:system");
    expect(s.state.sourceRunning).toBe(true);
    expect(s.events).toContain("startManaged:source");
  });

  for (const cleanupFailure of ["stopManaged:target", "disable:target"]) {
    test(`does not restart the source into an unconfirmed target state when ${cleanupFailure} fails`, async () => {
      const s = scenario({ faults: [{ step: "waitReady:target" }, { step: cleanupFailure }] });
      let failure: unknown;
      try { await migrateSystemInstallation(s.source, s.operations); }
      catch (error) { failure = error; }
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toContain("waitReady:target");
      expect((failure as Error).message).toContain(cleanupFailure);
      expect((failure as Error).message).toContain("恢复时遇到问题");
      expect(s.state.sourceRunning).toBe(false);
      expect(s.state.active).toBe(false);
      expect(s.events).toContain("disable:target");
      expect(s.events).toContain("deactivate:target");
      expect(s.events).not.toContain("startPortable:source");
      expect(s.events).not.toContain("startManaged:source");
    });
  }

  test("reports both the original failure and a failed source restart instead of claiming recovery", async () => {
    const s = scenario({ faults: [{ step: "waitReady:target" }, { step: "startPortable:source" }] });
    let failure: unknown;
    try { await migrateSystemInstallation(s.source, s.operations); }
    catch (error) { failure = error; }
    expect((failure as Error).message).toContain("waitReady:target");
    expect((failure as Error).message).toContain("原后台启动恢复失败");
    expect((failure as Error).message).not.toContain("已重新启动原后台");
    expect(s.state.sourceRunning).toBe(false);
    expect(s.state.targetRunning).toBe(false);
    expect(s.state.targetEnabled).toBe(false);
  });
});
