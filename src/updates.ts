import { type AppConfig, type AppPaths, type DaemonStatus, readConfig, configFingerprint, runtimeConfigFingerprint, collectConfigSecrets, redact, errorMessage } from "./core.ts";
import { type CoreRelease, type CoreReleaseCandidate, type CoreReleaseMap, type CoreSelectionState, readCoreSelection, writeCoreSelection, coreReleaseFingerprint, prepareCoreRelease, ensureSingleCore, preflightCores, acquireCoreSelectionLock } from "./network.ts";
import { acquireDaemonLock, getDaemonStatus, startDetachedDaemon, stopDaemonGracefully, waitForReady } from "./daemon.ts";
import { type StartupStatus, getStartupStatus, startManaged, stopManaged } from "./platform.ts";

export interface CoreUpdateOperations {
  acquireLock(paths: AppPaths): () => void;
  readConfig(paths: AppPaths): AppConfig;
  readSelection(paths: AppPaths): CoreSelectionState;
  writeSelection(paths: AppPaths, selection: CoreSelectionState): void;
  prepare(paths: AppPaths, candidate: CoreReleaseCandidate, report: (message: string) => void): Promise<CoreRelease>;
  ensure(paths: AppPaths, release: CoreRelease, report: (message: string) => void): Promise<string>;
  preflight(paths: AppPaths, config: AppConfig, releases: CoreReleaseMap, report: (message: string) => void): Promise<void>;
  getStatus(paths: AppPaths): Promise<DaemonStatus | null>;
  getStartup(paths: AppPaths): Promise<StartupStatus>;
  verifyStopped(paths: AppPaths): Promise<void>;
  startManaged(paths: AppPaths): Promise<void>;
  stopManaged(paths: AppPaths): Promise<void>;
  startPortable(paths: AppPaths): Promise<void>;
  stopPortable(paths: AppPaths): Promise<void>;
  waitReady(paths: AppPaths): Promise<DaemonStatus | null>;
}

export interface CoreUpdateResult {
  changed: boolean;
  restarted: boolean;
  versions: CoreReleaseMap;
}

/** An OS-backed lock is released on process exit, including an interrupted update. */
export function acquireCoreUpdateLock(paths: AppPaths): () => void {
  return acquireCoreSelectionLock(paths);
}

const updatesDefaults: CoreUpdateOperations = {
  acquireLock: acquireCoreUpdateLock, readConfig, readSelection: readCoreSelection, writeSelection: writeCoreSelection,
  prepare: prepareCoreRelease, ensure: ensureSingleCore,
  preflight: async (paths, config, releases, report) => { await preflightCores(paths, config, { releases, publish: false, report }); },
  getStatus: getDaemonStatus, getStartup: getStartupStatus,
  verifyStopped: async paths => { const release = acquireDaemonLock(paths); release(); },
  startManaged, stopManaged, startPortable: startDetachedDaemon, stopPortable: stopDaemonGracefully,
  waitReady: paths => waitForReady(paths, 45000),
};

function updatesRuntimeMatches(status: DaemonStatus, config: AppConfig): boolean {
  return status.runtimeConfigHash
    ? status.runtimeConfigHash === runtimeConfigFingerprint(config)
    : status.configHash === configFingerprint(config);
}

function updatesReportedReleaseHash(status: DaemonStatus): string | undefined {
  // Optional when inspecting a worker launched by an older script.
  return (status as DaemonStatus & { coreReleaseHash?: string }).coreReleaseHash;
}

function updatesRuntimeIdentity(status: DaemonStatus | null): string {
  return status ? JSON.stringify([status.instanceId, status.pid, status.configHash, status.runtimeConfigHash, updatesReportedReleaseHash(status)]) : "stopped";
}

function updatesStartupIdentity(status: StartupStatus): string {
  return JSON.stringify([status.mode, status.enabled, status.running]);
}

function updatesAssertReady(status: DaemonStatus | null, config: AppConfig, versions: CoreReleaseMap, oldInstance?: string): void {
  if (!status || status.phase !== "ready") throw new Error(`后台尚未就绪${status?.lastError ? `：${status.lastError}` : "，请查看节点状态和日志"}。`);
  if (oldInstance && status.instanceId === oldInstance) throw new Error("后台仍是切换前的实例，尚未确认新内核已启动。");
  if (!updatesRuntimeMatches(status, config)) throw new Error("后台加载的节点配置与预检配置不一致。");
  const selected = updatesReportedReleaseHash(status);
  if (!selected) throw new Error("后台没有报告内核版本，无法确认切换结果。请确认后台运行的是更新后的 NexusEdge 脚本。");
  if (selected !== coreReleaseFingerprint(versions)) throw new Error("后台加载的内核版本与本次选择不一致。");
}

interface UpdatesSnapshot {
  config: AppConfig;
  selection: CoreSelectionState;
  status: DaemonStatus | null;
  startup: StartupStatus;
}

async function updatesSnapshot(paths: AppPaths, ops: CoreUpdateOperations): Promise<UpdatesSnapshot> {
  const config = structuredClone(ops.readConfig(paths));
  const selection = structuredClone(ops.readSelection(paths));
  const [status, startup] = await Promise.all([ops.getStatus(paths), ops.getStartup(paths)]);
  if (!status && startup.running) throw new Error("系统后台正在运行，但暂时无法确认其配置和状态。请等后台启动完成后再更新内核。");
  if (status?.phase === "stopping") throw new Error("后台正在停止，请等停止完成后再更新内核。");
  if (status && !updatesRuntimeMatches(status, config)) throw new Error("已保存的节点配置尚未应用。请先在主菜单启动 / 重启全部节点，再更新内核。");
  const releaseHash = status && updatesReportedReleaseHash(status);
  if (releaseHash && releaseHash !== coreReleaseFingerprint(selection.active)) throw new Error("已选择的内核版本尚未应用。请先在主菜单启动 / 重启全部节点，再进行下一次内核更新。");
  return { config, selection, status: status && structuredClone(status), startup: structuredClone(startup) };
}

function updatesAssertSavedUnchanged(paths: AppPaths, snapshot: UpdatesSnapshot, ops: CoreUpdateOperations): void {
  if (configFingerprint(ops.readConfig(paths)) !== configFingerprint(snapshot.config)) throw new Error("检查期间节点配置发生了变化，已取消切换。请重新检查内核更新。");
  if (JSON.stringify(ops.readSelection(paths)) !== JSON.stringify(snapshot.selection)) throw new Error("检查期间内核版本选择发生了变化，已取消切换。请重新检查内核更新。");
}

function updatesAssertExpectedSelection(snapshot: UpdatesSnapshot, expectedSelection?: CoreSelectionState): void {
  if (expectedSelection && JSON.stringify(snapshot.selection) !== JSON.stringify(expectedSelection)) throw new Error("确认期间内核版本选择发生了变化，已取消本次操作。请重新检查版本后再确认。");
}

async function updatesAssertUnchanged(paths: AppPaths, snapshot: UpdatesSnapshot, ops: CoreUpdateOperations): Promise<void> {
  updatesAssertSavedUnchanged(paths, snapshot, ops);
  const [status, startup] = await Promise.all([ops.getStatus(paths), ops.getStartup(paths)]);
  if (updatesRuntimeIdentity(status) !== updatesRuntimeIdentity(snapshot.status) || updatesStartupIdentity(startup) !== updatesStartupIdentity(snapshot.startup) || status?.phase === "stopping") {
    throw new Error("检查期间后台或自启状态发生了变化，已取消切换。请在状态稳定后重试。");
  }
  if (!snapshot.status) await ops.verifyStopped(paths);
}

async function updatesSwitch(paths: AppPaths, snapshot: UpdatesSnapshot, versions: CoreReleaseMap, report: (message: string) => void, ops: CoreUpdateOperations): Promise<CoreUpdateResult> {
  if (coreReleaseFingerprint(versions) === coreReleaseFingerprint(snapshot.selection.active)) return { changed: false, restarted: false, versions: snapshot.selection.active };
  if (snapshot.config.nodes.some(node => node.enabled)) {
    report("使用现有节点配置检查候选内核，当前后台继续运行……");
    await ops.preflight(paths, snapshot.config, versions, report);
  }
  await updatesAssertUnchanged(paths, snapshot, ops);
  const stop = snapshot.startup.mode === "none" ? ops.stopPortable : ops.stopManaged;
  const start = snapshot.startup.mode === "none" ? ops.startPortable : ops.startManaged;
  const wasRunning = Boolean(snapshot.status);
  const next: CoreSelectionState = { schema: 1, active: structuredClone(versions), previous: structuredClone(snapshot.selection.active), updatedAt: new Date().toISOString() };
  let stopAttempted = false, selectionAttempted = false, startAttempted = false;
  try {
    if (wasRunning) {
      report("配置检查通过，正在重启后台以应用所选内核……");
      stopAttempted = true;
      await stop(paths);
      await ops.verifyStopped(paths);
    }
    // Stopping can take seconds; another panel may have saved configuration meanwhile.
    updatesAssertSavedUnchanged(paths, snapshot, ops);
    selectionAttempted = true;
    ops.writeSelection(paths, next);
    if (wasRunning) {
      startAttempted = true;
      await start(paths);
      updatesAssertReady(await ops.waitReady(paths), snapshot.config, versions, snapshot.status?.instanceId);
      if (coreReleaseFingerprint(ops.readSelection(paths).active) !== coreReleaseFingerprint(versions)) throw new Error("后台启动期间内核选择再次发生变化，无法确认本次切换结果。");
      report("内核已切换，后台已就绪。旧版本已保留，可从内核管理回退。");
    } else report("内核版本已保存，后台保持停止。下次启动节点时使用所选版本。");
    return { changed: true, restarted: wasRunning, versions: structuredClone(versions) };
  } catch (originalError) {
    const failures: string[] = [];
    let canRestart = true, originalStillRunning = false, restoredReady = false;
    if (startAttempted) {
      try { await stop(paths); await ops.verifyStopped(paths); }
      catch (error) { canRestart = false; failures.push(`候选后台停止未确认：${errorMessage(error)}`); }
    }
    if (selectionAttempted) {
      try { ops.writeSelection(paths, structuredClone(snapshot.selection)); }
      catch (error) { canRestart = false; failures.push(`原内核版本选择恢复失败：${errorMessage(error)}`); }
    }
    if (wasRunning && stopAttempted && !startAttempted) {
      try {
        const current = await ops.getStatus(paths);
        if (current && updatesRuntimeIdentity(current) === updatesRuntimeIdentity(snapshot.status) && current.phase !== "stopping") originalStillRunning = true;
        else if (current) { canRestart = false; failures.push("后台状态仍在变化，尚未确认原实例已停止。"); }
        else await ops.verifyStopped(paths);
      } catch (error) { canRestart = false; failures.push(`原后台停止未确认：${errorMessage(error)}`); }
    }
    if (wasRunning && stopAttempted && canRestart && !originalStillRunning) {
      try {
        if (runtimeConfigFingerprint(ops.readConfig(paths)) !== runtimeConfigFingerprint(snapshot.config)) throw new Error("恢复期间节点配置发生变化，请先检查已保存配置再启动后台。");
        if (JSON.stringify(ops.readSelection(paths)) !== JSON.stringify(snapshot.selection)) throw new Error("恢复期间内核版本选择发生变化，请先检查已保存版本再启动后台。");
        await start(paths);
        updatesAssertReady(await ops.waitReady(paths), snapshot.config, snapshot.selection.active, snapshot.status?.instanceId);
        restoredReady = true;
      } catch (error) { failures.push(`原版本后台恢复未就绪：${errorMessage(error)}`); }
    }
    const recovery = failures.length
      ? `\n恢复时遇到问题：\n${failures.join("\n")}\n请查看日志和当前后台状态，再从主菜单重启；不要重复创建另一套后台。`
      : restoredReady ? "\n已恢复原内核版本和原后台，并确认后台就绪。临时隧道重连后请重新查看链接。"
      : originalStillRunning ? "\n原内核版本选择已保留，原后台仍在运行。"
      : "\n原内核版本选择已恢复，后台保持停止。";
    throw new Error(redact(`内核切换失败：${errorMessage(originalError)}${recovery}`, collectConfigSecrets(snapshot.config)));
  }
}

/** Prepare every selected download before changing any runtime selection. */
export async function applyCoreUpdates(paths: AppPaths, candidates: CoreReleaseCandidate[], report: (message: string) => void = () => {}, operations: Partial<CoreUpdateOperations> = {}, expectedSelection?: CoreSelectionState): Promise<CoreUpdateResult> {
  const ops: CoreUpdateOperations = { ...updatesDefaults, ...operations };
  const releaseLock = ops.acquireLock(paths);
  try {
    const snapshot = await updatesSnapshot(paths, ops);
    updatesAssertExpectedSelection(snapshot, expectedSelection);
    if (!candidates.length) return { changed: false, restarted: false, versions: snapshot.selection.active };
    const tools = candidates.map(candidate => candidate.tool);
    if (new Set(tools).size !== tools.length) throw new Error("一次内核更新不能重复选择同一内核。");
    const versions = structuredClone(snapshot.selection.active);
    for (const candidate of candidates) {
      const prepared = await ops.prepare(paths, candidate, report);
      if (prepared.tool !== candidate.tool || prepared.version !== candidate.version || prepared.asset.sha256 !== candidate.asset.sha256) throw new Error("准备完成的发行包与所选版本不一致，已取消更新。");
      versions[prepared.tool] = prepared;
    }
    return await updatesSwitch(paths, snapshot, versions, report, ops);
  } finally { releaseLock(); }
}

/** A rollback has the same compatibility and recovery checks as an upgrade. */
export async function rollbackCoreUpdates(paths: AppPaths, report: (message: string) => void = () => {}, operations: Partial<CoreUpdateOperations> = {}, expectedSelection?: CoreSelectionState): Promise<CoreUpdateResult> {
  const ops: CoreUpdateOperations = { ...updatesDefaults, ...operations };
  const releaseLock = ops.acquireLock(paths);
  try {
    const snapshot = await updatesSnapshot(paths, ops);
    updatesAssertExpectedSelection(snapshot, expectedSelection);
    if (!snapshot.selection.previous) throw new Error("还没有可回退的内核版本。首次成功升级后会保留上一次版本。");
    const previous = structuredClone(snapshot.selection.previous);
    for (const tool of ["singBox", "xray", "cloudflared"] as const) {
      const current = snapshot.selection.active[tool], target = previous[tool];
      if (JSON.stringify(current) !== JSON.stringify(target)) await ops.ensure(paths, target, report);
    }
    return await updatesSwitch(paths, snapshot, previous, report, ops);
  } finally { releaseLock(); }
}
