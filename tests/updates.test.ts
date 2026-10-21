import { afterEach, describe, expect, test } from "bun:test";
import * as updatesTestFs from "node:fs";
import * as updatesTestOs from "node:os";
import * as updatesTestPath from "node:path";
import { type AppConfig, type DaemonStatus, createPaths, createDefaultNode, defaultConfig, configFingerprint, runtimeConfigFingerprint, ensureDataDir } from "../src/core.ts";
import { type CoreRelease, type CoreReleaseCandidate, type CoreReleaseMap, type CoreSelectionState, readCoreSelection, coreReleaseFingerprint } from "../src/network.ts";
import { type CoreUpdateOperations, applyCoreUpdates, rollbackCoreUpdates, acquireCoreUpdateLock } from "../src/updates.ts";
import type { StartupStatus } from "../src/platform.ts";

// These tests inject the download, preflight and daemon/service boundaries.
// They never start a core, connect to Cloudflare, send notifications or register services.
const updatesTestRoots: string[] = [];
afterEach(() => { for (const path of updatesTestRoots.splice(0)) updatesTestFs.rmSync(path, { recursive: true, force: true }); });

type UpdatesTestStatus = DaemonStatus & { coreReleaseHash?: string };
interface UpdatesTestFault { at: string; afterEffect?: boolean }
interface UpdatesTestOptions {
  running?: boolean;
  startup?: Partial<StartupStatus>;
  faults?: UpdatesTestFault[];
  emptyConfig?: boolean;
  previous?: boolean;
}

function updatesTestRelease(base: CoreRelease, version = "26.10.18"): CoreRelease {
  const next = structuredClone(base);
  next.version = version; next.tag = `v${version}`; next.source = "github";
  next.prerelease = false; next.asset.sha256 = version.endsWith("18") ? "d".repeat(64) : "e".repeat(64);
  next.downloadUrl = `https://github.com/XTLS/Xray-core/releases/download/${next.tag}/${next.asset.asset}`;
  next.releaseUrl = `https://github.com/XTLS/Xray-core/releases/tag/${next.tag}`;
  return next;
}

function updatesTestScenario(options: UpdatesTestOptions = {}) {
  const root = updatesTestFs.mkdtempSync(updatesTestPath.join(updatesTestOs.tmpdir(), "nexus-updates-test-"));
  updatesTestRoots.push(root);
  const paths = createPaths(updatesTestPath.join(root, "nexus-edge.ts"));
  const original = readCoreSelection(paths);
  if (options.previous) {
    original.previous = structuredClone(original.active);
    original.previous.xray = updatesTestRelease(original.previous.xray, "26.3.26");
    original.updatedAt = "2026-10-21T00:00:00.000Z";
  }
  const config = defaultConfig();
  if (!options.emptyConfig) {
    const node = createDefaultNode("vless"); node.address = "198.51.100.4";
    config.nodes.push(node);
  }
  const state = {
    config, selection: structuredClone(original), status: null as UpdatesTestStatus | null,
    startup: { mode: "none", enabled: false, running: options.running ?? true, detail: "injected test state", ...options.startup } as StartupStatus,
    locked: false, serial: 1, hiddenWorker: false, writes: [] as CoreSelectionState[],
  };
  const events: string[] = [];
  const faults = [...(options.faults ?? [])];
  const hooks: {
    prepare?: (candidate: CoreReleaseCandidate) => void | Promise<void>;
    preflight?: (versions: CoreReleaseMap) => void | Promise<void>;
    wait?: (call: number, ready: UpdatesTestStatus) => UpdatesTestStatus | null;
  } = {};
  const status = (instance = state.serial): UpdatesTestStatus => ({
    instanceId: `00000000-0000-4000-8000-${String(instance).padStart(12, "0")}`, pid: 2000 + instance,
    startedAt: "2026-10-21T00:00:00.000Z", phase: "ready",
    configHash: configFingerprint(state.config), runtimeConfigHash: runtimeConfigFingerprint(state.config),
    coreReleaseHash: coreReleaseFingerprint(state.selection.active),
    cores: { xray: { state: "running", restarts: 0, lastError: null } }, nodes: [], links: [], lastError: null,
  });
  if (options.running !== false) state.status = status();
  const step = (at: string, effect?: () => void): void => {
    events.push(at);
    const index = faults.findIndex(fault => fault.at === at);
    const fault = index < 0 ? undefined : faults.splice(index, 1)[0];
    if (fault && !fault.afterEffect) throw new Error(`Injected ${at} failure`);
    effect?.();
    if (fault) throw new Error(`Injected ${at} failure after side effect`);
  };
  const stop = (kind: string): void => step(`stop:${kind}`, () => { state.status = null; state.startup.running = false; });
  const start = (kind: string): void => step(`start:${kind}`, () => {
    if (state.status || state.hiddenWorker) throw new Error("A running instance still owns the port");
    state.serial++; state.status = status(); state.startup.running = true;
  });
  let waitCalls = 0;
  const operations: CoreUpdateOperations = {
    acquireLock() {
      step("lock");
      if (state.locked) throw new Error("Update already locked");
      state.locked = true;
      return () => { state.locked = false; events.push("unlock"); };
    },
    readConfig() { step("readConfig"); return structuredClone(state.config); },
    readSelection() { step("readSelection"); return structuredClone(state.selection); },
    writeSelection(_paths, next) {
      const label = coreReleaseFingerprint(next.active) === coreReleaseFingerprint(original.active) ? "write:old" : "write:new";
      step(label, () => { state.selection = structuredClone(next); state.writes.push(structuredClone(next)); });
    },
    async prepare(_paths, candidate) {
      step(`prepare:${candidate.tool}`);
      await hooks.prepare?.(candidate);
      return { ...structuredClone(candidate), asset: { ...structuredClone(candidate.asset), files: structuredClone(candidate.asset.files ?? original.active[candidate.tool].asset.files) } };
    },
    async ensure(_paths, release) { step(`ensure:${release.tool}`); return updatesTestPath.join(paths.bin, release.version, release.asset.executable); },
    async preflight(_paths, _config, versions) { step("preflight"); await hooks.preflight?.(versions); },
    async getStatus() { step("getStatus"); return state.status && structuredClone(state.status); },
    async getStartup() { step("getStartup"); return { ...state.startup }; },
    async verifyStopped() { step("verifyStopped"); if (state.status || state.hiddenWorker) throw new Error("Daemon lock is still owned"); },
    async startManaged() { start("managed"); }, async stopManaged() { stop("managed"); },
    async startPortable() { start("portable"); }, async stopPortable() { stop("portable"); },
    async waitReady() {
      step("waitReady"); waitCalls++;
      if (!state.status) throw new Error("Cannot check a stopped daemon");
      return hooks.wait ? hooks.wait(waitCalls, structuredClone(state.status)) : structuredClone(state.status);
    },
  };
  const candidate = updatesTestRelease(original.active.xray);
  return { paths, state, events, hooks, operations, original, candidate };
}

function updatesTestBefore(events: string[], first: string, second: string): void {
  expect(events).toContain(first); expect(events).toContain(second);
  expect(events.indexOf(first)).toBeLessThan(events.indexOf(second));
}

function updatesTestUntouched(s: ReturnType<typeof updatesTestScenario>): void {
  expect(s.state.selection).toEqual(s.original);
  expect(s.state.status?.instanceId).toBe("00000000-0000-4000-8000-000000000001");
  expect(s.events).not.toContain("stop:portable"); expect(s.events).not.toContain("stop:managed");
  expect(s.state.writes).toHaveLength(0); expect(s.state.locked).toBe(false);
}

describe("controlled core upgrades and rollback", () => {
  test("validates before stopping, atomically selects versions and confirms a new ready portable instance", async () => {
    const s = updatesTestScenario({ previous: true });
    const result = await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    expect(result.changed).toBe(true); expect(result.restarted).toBe(true);
    expect(result.versions.xray.version).toBe(s.candidate.version);
    expect(s.state.selection.active.xray.version).toBe(s.candidate.version);
    expect(s.state.selection.previous).toEqual(s.original.active);
    expect((s.state.status as UpdatesTestStatus | null)?.coreReleaseHash).toBe(coreReleaseFingerprint(result.versions));
    expect(s.state.status?.instanceId).not.toBe("00000000-0000-4000-8000-000000000001");
    updatesTestBefore(s.events, "prepare:xray", "preflight");
    updatesTestBefore(s.events, "preflight", "stop:portable");
    updatesTestBefore(s.events, "stop:portable", "write:new");
    updatesTestBefore(s.events, "write:new", "start:portable");
    updatesTestBefore(s.events, "waitReady", "unlock");
    expect(s.events).not.toContain("start:managed");
  });

  for (const mode of ["windows-user", "windows-system", "linux-system"] as const) {
    test(`uses the existing ${mode} manager without changing automatic startup`, async () => {
      const s = updatesTestScenario({ startup: { mode, enabled: true } });
      await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
      expect(s.events).toContain("stop:managed"); expect(s.events).toContain("start:managed");
      expect(s.events).not.toContain("stop:portable"); expect(s.events).not.toContain("start:portable");
      expect(s.state.startup.enabled).toBe(true); expect(s.state.startup.mode).toBe(mode);
    });
  }

  test("an update while stopped records versions without starting or stopping any daemon", async () => {
    const s = updatesTestScenario({ running: false, startup: { mode: "windows-system", enabled: true } });
    const result = await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    expect(result.changed).toBe(true); expect(result.restarted).toBe(false);
    expect(s.state.status).toBeNull(); expect(s.state.startup.running).toBe(false);
    expect(s.events.some(event => /^(?:stop|start):/.test(event))).toBe(false);
    expect(s.events).toContain("verifyStopped"); expect(s.events).toContain("preflight");
  });

  test("an empty saved collection permits preparing a core without downloading unrelated cores or starting services", async () => {
    const s = updatesTestScenario({ running: false, emptyConfig: true });
    await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    expect(s.events.filter(event => event.startsWith("prepare:"))).toEqual(["prepare:xray"]);
    expect(s.events).not.toContain("preflight"); expect(s.state.status).toBeNull();
  });

  test("no candidates and an unchanged release selection do not restart or overwrite history", async () => {
    const s = updatesTestScenario({ previous: true });
    expect(await applyCoreUpdates(s.paths, [], () => {}, s.operations)).toEqual({ changed: false, restarted: false, versions: s.original.active });
    expect((await applyCoreUpdates(s.paths, [s.original.active.xray], () => {}, s.operations)).changed).toBe(false);
    updatesTestUntouched(s); expect(s.events).not.toContain("preflight");
  });

  test("duplicate selections and a prepared release identity mismatch cannot change running state", async () => {
    const duplicate = updatesTestScenario();
    await expect(applyCoreUpdates(duplicate.paths, [duplicate.candidate, duplicate.candidate], () => {}, duplicate.operations)).rejects.toThrow("重复");
    updatesTestUntouched(duplicate);
    const mismatch = updatesTestScenario();
    mismatch.operations.prepare = async () => mismatch.original.active.xray;
    await expect(applyCoreUpdates(mismatch.paths, [mismatch.candidate], () => {}, mismatch.operations)).rejects.toThrow("不一致");
    updatesTestUntouched(mismatch);
  });

  for (const failedAt of ["prepare:xray", "preflight"]) {
    test(`${failedAt} failure preserves original runtime, selection and rollback history`, async () => {
      const s = updatesTestScenario({ faults: [{ at: failedAt }], previous: true });
      await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow(failedAt);
      updatesTestUntouched(s);
    });
  }

  test("all requested downloads must finish before preflight or any selection switch", async () => {
    const s = updatesTestScenario({ faults: [{ at: "prepare:cloudflared" }] });
    await expect(applyCoreUpdates(s.paths, [s.candidate, s.original.active.cloudflared], () => {}, s.operations)).rejects.toThrow("prepare:cloudflared");
    updatesTestUntouched(s); expect(s.events).not.toContain("preflight");
  });

  test("pending server configuration is not applied as a hidden side effect of a core update", async () => {
    const s = updatesTestScenario(); s.state.config.nodes[0]!.port++;
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("节点配置尚未应用");
    updatesTestUntouched(s); expect(s.events).not.toContain("prepare:xray");
  });

  test("client endpoint metadata may differ from the frozen old runtime without blocking an update", async () => {
    const s = updatesTestScenario(); s.state.config.nodes[0]!.address = "198.51.100.8";
    await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    expect(s.state.selection.active.xray.version).toBe(s.candidate.version);
  });

  test("pending selected core versions and an unresponsive managed worker prevent an unsafe switch", async () => {
    const pending = updatesTestScenario(); pending.state.status!.coreReleaseHash = "f".repeat(64);
    await expect(applyCoreUpdates(pending.paths, [pending.candidate], () => {}, pending.operations)).rejects.toThrow("内核版本尚未应用");
    updatesTestUntouched(pending);
    const invisible = updatesTestScenario({ running: false, startup: { mode: "windows-system", enabled: true, running: true } });
    await expect(applyCoreUpdates(invisible.paths, [invisible.candidate], () => {}, invisible.operations)).rejects.toThrow("无法确认");
    expect(invisible.state.writes).toHaveLength(0); expect(invisible.events).not.toContain("prepare:xray");
  });

  for (const change of ["node configuration", "selected core", "runtime instance", "startup mode"] as const) {
    test(`a concurrent change to ${change} cancels before stopping the original worker`, async () => {
      const s = updatesTestScenario();
      s.hooks.preflight = () => {
        if (change === "node configuration") s.state.config.nodes[0]!.address = "198.51.100.9";
        if (change === "selected core") s.state.selection.updatedAt = "2026-10-21T00:00:01.000Z";
        if (change === "runtime instance") s.state.status!.instanceId = "00000000-0000-4000-8000-000000000009";
        if (change === "startup mode") s.state.startup.mode = "windows-user";
      };
      await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("变化");
      expect(s.events).not.toContain("stop:portable"); expect(s.events).not.toContain("stop:managed");
      expect(s.state.writes).toHaveLength(0); expect(s.state.locked).toBe(false);
    });
  }

  test("an invisible starting worker's daemon lock blocks a stopped-state selection change", async () => {
    const s = updatesTestScenario({ running: false }); s.state.hiddenWorker = true;
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("Daemon lock");
    expect(s.state.writes).toHaveLength(0); expect(s.state.locked).toBe(false);
  });

  test("a stop failure before its side effect leaves the old runtime running and does not start another", async () => {
    const s = updatesTestScenario({ faults: [{ at: "stop:portable" }], previous: true });
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("原后台仍在运行");
    expect(s.state.selection).toEqual(s.original); expect(s.state.status?.pid).toBe(2001);
    expect(s.events).not.toContain("start:portable"); expect(s.state.writes).toHaveLength(0);
  });

  test("a stop failure after its side effect restarts and confirms the original version", async () => {
    const s = updatesTestScenario({ faults: [{ at: "stop:portable", afterEffect: true }], previous: true });
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("已恢复原内核版本和原后台");
    expect(s.state.selection).toEqual(s.original); expect(s.state.status?.coreReleaseHash).toBe(coreReleaseFingerprint(s.original.active));
    expect(s.state.writes).toHaveLength(0); expect(s.events).toContain("waitReady");
  });

  for (const afterEffect of [false, true]) {
    test(`a version selection write failure (${afterEffect ? "after" : "before"} its side effect) recovers the exact original history`, async () => {
      const s = updatesTestScenario({ faults: [{ at: "write:new", afterEffect }], previous: true });
      await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("已恢复原内核版本和原后台");
      expect(s.state.selection).toEqual(s.original); expect(s.state.status?.coreReleaseHash).toBe(coreReleaseFingerprint(s.original.active));
      updatesTestBefore(s.events, "write:old", "start:portable"); expect(s.state.locked).toBe(false);
    });
  }

  for (const afterEffect of [false, true]) {
    test(`a candidate start failure (${afterEffect ? "after" : "before"} its side effect) stops it before recovering the original runtime`, async () => {
      const s = updatesTestScenario({ startup: { mode: "linux-system", enabled: true }, faults: [{ at: "start:managed", afterEffect }], previous: true });
      await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("已恢复原内核版本和原后台");
      expect(s.state.selection).toEqual(s.original); expect(s.state.status?.coreReleaseHash).toBe(coreReleaseFingerprint(s.original.active));
      const startAt = s.events.indexOf("start:managed"), oldWrite = s.events.indexOf("write:old");
      expect(s.events.slice(startAt + 1, oldWrite)).toContain("stop:managed");
      expect(s.state.startup.enabled).toBe(true);
    });
  }

  for (const unready of ["degraded", "null", "old instance", "wrong core", "missing core identity", "wrong config"] as const) {
    test(`${unready} readiness result triggers rollback rather than a false upgrade success`, async () => {
      const s = updatesTestScenario({ previous: true });
      s.hooks.wait = (call, ready) => {
        if (call > 1) return ready;
        if (unready === "null") return null;
        if (unready === "degraded") return { ...ready, phase: "degraded", lastError: "Candidate listener failed" };
        if (unready === "old instance") return { ...ready, instanceId: "00000000-0000-4000-8000-000000000001" };
        if (unready === "wrong core") return { ...ready, coreReleaseHash: "f".repeat(64) };
        if (unready === "missing core identity") { delete ready.coreReleaseHash; return ready; }
        return { ...ready, runtimeConfigHash: "f".repeat(64) };
      };
      await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("已恢复原内核版本和原后台");
      expect(s.state.selection).toEqual(s.original); expect(s.state.status?.coreReleaseHash).toBe(coreReleaseFingerprint(s.original.active));
      expect(s.events.filter(event => event === "waitReady")).toHaveLength(2);
    });
  }

  test("an initial legacy worker may omit core identity but its replacement must report the selected version", async () => {
    const s = updatesTestScenario(); delete s.state.status!.coreReleaseHash; delete s.state.status!.runtimeConfigHash;
    const result = await applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    expect(result.restarted).toBe(true);
    expect((s.state.status as UpdatesTestStatus | null)?.coreReleaseHash).toBe(coreReleaseFingerprint(result.versions));
  });

  test("failed cleanup of a candidate restores the selection but never starts an overlapping original daemon", async () => {
    const s = updatesTestScenario({ faults: [{ at: "start:portable", afterEffect: true }] });
    let stopCalls = 0;
    const originalStop = s.operations.stopPortable;
    s.operations.stopPortable = async paths => { stopCalls++; if (stopCalls === 2) { s.events.push("stop:portable:failed"); throw new Error("Cannot stop candidate"); } await originalStop(paths); };
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("候选后台停止未确认");
    expect(s.state.selection).toEqual(s.original);
    expect(s.events.filter(event => event === "start:portable")).toHaveLength(1);
    expect(s.state.status?.coreReleaseHash).not.toBe(coreReleaseFingerprint(s.original.active));
  });

  test("a failure restoring the selection is reported and prevents an unsafe restart", async () => {
    const s = updatesTestScenario({ faults: [{ at: "start:portable" }, { at: "write:old" }] });
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("原内核版本选择恢复失败");
    expect(s.state.status).toBeNull(); expect(s.events.filter(event => event === "start:portable")).toHaveLength(1);
    expect(s.state.locked).toBe(false);
  });

  test("an unready restored old runtime reports the remaining problem without claiming recovery", async () => {
    const s = updatesTestScenario(); s.hooks.wait = (_call, ready) => ({ ...ready, phase: "degraded" });
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("原版本后台恢复未就绪");
    expect(s.state.selection).toEqual(s.original);
  });

  test("concurrent server configuration changes during recovery are retained and block an unintended restart", async () => {
    const s = updatesTestScenario();
    s.hooks.wait = (_call, ready) => { s.state.config.nodes[0]!.port++; return { ...ready, phase: "degraded" }; };
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("恢复期间节点配置发生变化");
    expect(s.state.selection).toEqual(s.original); expect(s.state.status).toBeNull();
    expect(s.events.filter(event => event === "start:portable")).toHaveLength(1);
  });

  test("a failed write while stopped restores the selection and keeps the app stopped", async () => {
    const s = updatesTestScenario({ running: false, faults: [{ at: "write:new", afterEffect: true }], previous: true });
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations)).rejects.toThrow("后台保持停止");
    expect(s.state.selection).toEqual(s.original); expect(s.state.status).toBeNull();
    expect(s.events.some(event => /^(?:stop|start):/.test(event))).toBe(false);
  });

  test("rollback verifies changed cached releases, preflights and swaps history without querying releases", async () => {
    const s = updatesTestScenario({ previous: true });
    const result = await rollbackCoreUpdates(s.paths, () => {}, s.operations);
    expect(result.changed).toBe(true); expect(result.restarted).toBe(true);
    expect(s.state.selection.active).toEqual(s.original.previous!);
    expect(s.state.selection.previous).toEqual(s.original.active);
    expect(s.events.filter(event => event.startsWith("ensure:"))).toEqual(["ensure:xray"]);
    expect(s.events.some(event => event.startsWith("prepare:"))).toBe(false);
    updatesTestBefore(s.events, "ensure:xray", "preflight"); updatesTestBefore(s.events, "preflight", "stop:portable");
  });

  for (const failAt of ["ensure:xray", "preflight"]) {
    test(`rollback ${failAt} failure leaves the current version running`, async () => {
      const s = updatesTestScenario({ previous: true, faults: [{ at: failAt }] });
      await expect(rollbackCoreUpdates(s.paths, () => {}, s.operations)).rejects.toThrow(failAt);
      updatesTestUntouched(s);
    });
  }

  test("a failed rollback start recovers the newer original selection and its previous history", async () => {
    const s = updatesTestScenario({ previous: true, faults: [{ at: "start:portable" }] });
    await expect(rollbackCoreUpdates(s.paths, () => {}, s.operations)).rejects.toThrow("已恢复原内核版本和原后台");
    expect(s.state.selection).toEqual(s.original);
  });

  test("rollback without previous versions explains the absence and leaves everything untouched", async () => {
    const s = updatesTestScenario();
    await expect(rollbackCoreUpdates(s.paths, () => {}, s.operations)).rejects.toThrow("还没有可回退");
    updatesTestUntouched(s);
  });

  test("a confirmed stale upgrade cannot downgrade a version selected by another panel", async () => {
    const s = updatesTestScenario();
    const confirmed = structuredClone(s.state.selection);
    s.state.selection.active.xray = updatesTestRelease(s.original.active.xray, "26.10.19");
    s.state.status!.coreReleaseHash = coreReleaseFingerprint(s.state.selection.active);
    const changedByOtherPanel = structuredClone(s.state.selection);
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations, confirmed)).rejects.toThrow("确认期间内核版本选择发生了变化");
    expect(s.state.selection).toEqual(changedByOtherPanel);
    expect(s.events).not.toContain("prepare:xray"); expect(s.events).not.toContain("stop:portable");
    expect(s.state.writes).toHaveLength(0); expect(s.state.locked).toBe(false);
  });

  test("a confirmed rollback cannot silently use a previous version changed by another panel", async () => {
    const s = updatesTestScenario({ previous: true });
    const confirmed = structuredClone(s.state.selection);
    s.state.selection.previous!.xray = updatesTestRelease(s.original.active.xray, "26.3.25");
    const changedByOtherPanel = structuredClone(s.state.selection);
    await expect(rollbackCoreUpdates(s.paths, () => {}, s.operations, confirmed)).rejects.toThrow("确认期间内核版本选择发生了变化");
    expect(s.state.selection).toEqual(changedByOtherPanel);
    expect(s.events).not.toContain("ensure:xray"); expect(s.events).not.toContain("stop:portable");
    expect(s.state.writes).toHaveLength(0); expect(s.state.locked).toBe(false);
  });

  test("a saved node edit during stop is retained and cannot be silently applied by upgrading or recovering", async () => {
    const s = updatesTestScenario();
    const stop = s.operations.stopPortable;
    s.operations.stopPortable = async paths => { await stop(paths); s.state.config.nodes[0]!.port++; };
    const savedPort = s.state.config.nodes[0]!.port + 1;
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations, s.original)).rejects.toThrow("恢复期间节点配置发生变化");
    expect(s.state.config.nodes[0]!.port).toBe(savedPort);
    expect(s.state.selection).toEqual(s.original); expect(s.state.status).toBeNull();
    expect(s.state.writes).toHaveLength(0); expect(s.events).not.toContain("start:portable");
  });

  test("a selected version changed during stop is retained and does not cause recovery to start an unintended version", async () => {
    const s = updatesTestScenario();
    const stop = s.operations.stopPortable;
    s.operations.stopPortable = async paths => { await stop(paths); s.state.selection.active.xray = updatesTestRelease(s.original.active.xray, "26.10.19"); };
    await expect(applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations, s.original)).rejects.toThrow("恢复期间内核版本选择发生变化");
    expect(s.state.selection.active.xray.version).toBe("26.10.19"); expect(s.state.status).toBeNull();
    expect(s.state.writes).toHaveLength(0); expect(s.events).not.toContain("start:portable");
  });
});

describe("core update lock", () => {
  test("SQLite lock excludes another update and becomes reusable after release", () => {
    const s = updatesTestScenario({ running: false });
    const release = acquireCoreUpdateLock(s.paths);
    try { expect(() => acquireCoreUpdateLock(s.paths)).toThrow("更新或回退正在进行"); }
    finally { release(); release(); }
    acquireCoreUpdateLock(s.paths)();
  });

  test("a second concurrent update cannot pass the lock while the first awaits a download", async () => {
    const s = updatesTestScenario({ running: false });
    s.operations.acquireLock = acquireCoreUpdateLock;
    let unblock!: () => void, entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    s.hooks.prepare = async () => { entered(); await blocked; };
    const first = applyCoreUpdates(s.paths, [s.candidate], () => {}, s.operations);
    await started;
    await expect(rollbackCoreUpdates(s.paths, () => {}, s.operations)).rejects.toThrow("更新或回退正在进行");
    unblock(); await first;
    acquireCoreUpdateLock(s.paths)();
  });

  test("lock files cannot redirect SQLite writes through a symbolic link", () => {
    const s = updatesTestScenario({ running: false }); ensureDataDir(s.paths);
    const destination = updatesTestPath.join(s.paths.data, "unchanged.txt");
    updatesTestFs.writeFileSync(destination, "unchanged");
    updatesTestFs.symlinkSync(destination, updatesTestPath.join(s.paths.data, "core-update-lock.sqlite"));
    expect(() => acquireCoreUpdateLock(s.paths)).toThrow("不能是链接");
    expect(updatesTestFs.readFileSync(destination, "utf8")).toBe("unchanged");
  });
});
