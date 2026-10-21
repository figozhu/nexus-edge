import { type AppPaths, type DaemonStatus, readConfig, errorMessage } from "./core.ts";
import { preflightCores } from "./network.ts";
import { getDaemonStatus, startDetachedDaemon, stopDaemonGracefully, waitForReady } from "./daemon.ts";
import { type StartupStatus, installSystemCopy, enableStartup, disableStartup, startManaged, stopManaged, getStartupStatus, activateSystemInstallation, deactivateSystemInstallation } from "./platform.ts";

export interface MigrationOperations {
  getStatus(paths: AppPaths): Promise<DaemonStatus | null>;
  getStartup(paths: AppPaths): Promise<StartupStatus>;
  copy(paths: AppPaths): Promise<AppPaths>;
  preflight(paths: AppPaths): Promise<void>;
  enable(paths: AppPaths, mode: "system" | "user"): Promise<void>;
  disable(paths: AppPaths): Promise<void>;
  startManaged(paths: AppPaths): Promise<void>;
  stopManaged(paths: AppPaths): Promise<void>;
  startPortable(paths: AppPaths): Promise<void>;
  stopPortable(paths: AppPaths): Promise<void>;
  waitReady(paths: AppPaths): Promise<DaemonStatus | null>;
  activate(paths: AppPaths): Promise<void>;
  deactivate(paths: AppPaths): Promise<void>;
}

const migrationDefaults: MigrationOperations = {
  getStatus: getDaemonStatus, getStartup: getStartupStatus, copy: installSystemCopy,
  preflight: async paths => { await preflightCores(paths, readConfig(paths)); }, enable: enableStartup, disable: disableStartup,
  startManaged, stopManaged, startPortable: startDetachedDaemon, stopPortable: stopDaemonGracefully,
  waitReady: paths => waitForReady(paths, 45000), activate: activateSystemInstallation, deactivate: deactivateSystemInstallation,
};

/**
 * The original node stays active during copy and validation. Once switched, the
 * old autostart definition is disabled only after the new worker reports ready.
 * Failed switches restore the old lifecycle instead of reporting a false success.
 */
export async function migrateSystemInstallation(paths: AppPaths, operations: MigrationOperations = migrationDefaults): Promise<AppPaths> {
  const sourceStartup = await operations.getStartup(paths);
  const sourceWasRunning = Boolean(await operations.getStatus(paths)) || sourceStartup.running;
  const target = await operations.copy(paths);
  await operations.preflight(target);
  let sourceStopped = false;
  let targetTouched = false;
  let targetStartAttempted = false;
  let sourceAutostartTouched = false;
  try {
    if (sourceStartup.mode === "none") await operations.stopPortable(paths);
    else await operations.stopManaged(paths);
    sourceStopped = true;
    targetTouched = true;
    await operations.enable(target, "system");
    targetStartAttempted = true;
    await operations.startManaged(target);
    const ready = await operations.waitReady(target);
    if (ready?.phase !== "ready") throw new Error(`系统副本尚未就绪${ready?.lastError ? `：${ready.lastError}` : "，请检查网络、隧道参数和日志"}。`);
    if (sourceStartup.enabled) {
      sourceAutostartTouched = true;
      await operations.disable(paths);
    }
    await operations.activate(target);
    return target;
  } catch (originalError) {
    const failures: string[] = [];
    let targetSafelyStopped = true;
    if (targetStartAttempted) {
      try { await operations.stopManaged(target); }
      catch (e) { targetSafelyStopped = false; failures.push(`系统副本停止失败：${errorMessage(e)}`); }
    }
    if (targetTouched) {
      try { await operations.disable(target); }
      catch (e) { targetSafelyStopped = false; failures.push(`系统副本自启关闭失败：${errorMessage(e)}`); }
    }
    try { await operations.deactivate(target); }
    catch (e) { failures.push(`系统副本激活标记恢复失败：${errorMessage(e)}`); }
    if (sourceAutostartTouched && sourceStartup.enabled) {
      try { await operations.enable(paths, sourceStartup.mode === "windows-user" ? "user" : "system"); }
      catch (e) { failures.push(`原自启设置恢复失败：${errorMessage(e)}`); }
    }
    let restored = false;
    if (sourceStopped && sourceWasRunning && targetSafelyStopped) {
      try {
        if (sourceStartup.mode === "none") await operations.startPortable(paths);
        else await operations.startManaged(paths);
        restored = true;
      } catch (e) { failures.push(`原后台启动恢复失败：${errorMessage(e)}`); }
    }
    const recovery = failures.length ? `\n恢复时遇到问题：\n${failures.join("\n")}\n请先检查日志和系统管理器，不要重复创建第二套后台。` : restored ? "\n已重新启动原后台，原自启设置已保留；临时隧道重连后请重新查看节点链接。" : "\n原来的自启设置已保留；原后台此前未运行时不会自动启动。";
    throw new Error(`系统安装切换失败：${errorMessage(originalError)}${recovery}`);
  }
}
