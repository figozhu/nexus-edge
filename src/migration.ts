import * as migrationFs from "node:fs";
import * as migrationPath from "node:path";
import { type AppPaths, type DaemonStatus, readConfig, validateConfig, configFingerprint, getFirewallSettings, errorMessage } from "./core.ts";
import { preflightCores } from "./network.ts";
import { getDaemonStatus, startDetachedDaemon, stopDaemonGracefully, waitForReady } from "./daemon.ts";
import { type StartupStatus, installSystemCopy, enableStartup, disableStartup, startManaged, stopManaged, getStartupStatus, activateSystemInstallation, deactivateSystemInstallation } from "./platform.ts";
import { syncFirewallBackground, syncFirewallInteractive } from "./firewall-control.ts";
import { buildFirewallPlan, readFirewallRecord, runFirewallCommand, type FirewallResult } from "./firewall.ts";
import { transferLinuxUfwOwnership, type LinuxUfwOwnershipTransfer } from "./firewall-linux.ts";

export interface MigrationFirewallTransaction {
  /** Restore the source's rule ownership before it is restarted. */
  rollback(): Promise<void>;
  /** Clean the source only after the target is active and ready. */
  complete(): Promise<void>;
}

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
  prepareFirewall?(source: AppPaths, target: AppPaths): Promise<MigrationFirewallTransaction | undefined>;
}

function migrationRequireFirewall(result: FirewallResult | null, action: string): void {
  if (result && !["synced", "inactive", "unsupported"].includes(result.status)) throw new Error(`${action}：${result.detail}`);
  if (result) {
    console.log(`${action}：${result.detail}`);
    for (const warning of result.warnings) console.log(`防火墙提示：${warning}`);
  }
}

async function migrationPrepareFirewall(source: AppPaths, target: AppPaths): Promise<MigrationFirewallTransaction | undefined> {
  // Elevation must not reset the portable user's directory ACL while reading its configuration.
  const sourceConfig = validateConfig(JSON.parse(migrationFs.readFileSync(source.config, "utf8")), { allowExpiredCertificate: true });
  const targetConfig = readConfig(target);
  const sourceHash = configFingerprint(sourceConfig);
  if (configFingerprint(targetConfig) !== sourceHash) throw new Error("复制期间原配置已被修改，尚未停止原后台。请重新执行系统安装。");
  if (getFirewallSettings(targetConfig).mode === "manual") return undefined;
  let transfer: LinuxUfwOwnershipTransfer | undefined;
  const rollback = async () => {
    // UFW cannot store duplicate rule bodies: restore the old comment before
    // cleaning the target so that the source's still-needed port is not deleted.
    if (transfer) migrationRequireFirewall(await transfer.rollback(), "恢复原安装的防火墙规则归属");
    migrationRequireFirewall(await syncFirewallInteractive(target, targetConfig, { remove: true, force: true }), "清理未启用系统副本的规则");
  };
  try {
    const sourcePlan = buildFirewallPlan(source, sourceConfig), targetPlan = buildFirewallPlan(target, targetConfig);
    if (process.platform === "linux" && sourcePlan.rules.length) {
      transfer = await transferLinuxUfwOwnership(sourcePlan, targetPlan, runFirewallCommand,
        { stateFile: migrationPath.join(source.data, "firewall-linux-state.json") },
        { stateFile: migrationPath.join(target.data, "firewall-linux-state.json") });
      migrationRequireFirewall(transfer.result, "准备防火墙归属迁移");
    }
    const ready = await syncFirewallBackground(target, targetConfig);
    migrationRequireFirewall(ready, "准备系统副本的防火墙规则");
    const latestSource = validateConfig(JSON.parse(migrationFs.readFileSync(source.config, "utf8")), { allowExpiredCertificate: true });
    if (configFingerprint(latestSource) !== sourceHash) throw new Error("准备防火墙期间原配置已被修改，尚未停止原后台。请重新执行系统安装。");
    return {
      rollback,
      complete: async () => {
        if (ready?.status === "synced" && (sourcePlan.rules.length || readFirewallRecord(source) || transfer?.result.changed)) {
          migrationRequireFirewall(await syncFirewallInteractive(source, sourceConfig, { remove: true, force: true }), "清理原安装的防火墙规则");
        }
      },
    };
  } catch (error) {
    try { await rollback(); }
    catch (rollbackError) { throw new Error(`${errorMessage(error)}\n防火墙恢复未完成：${errorMessage(rollbackError)}`); }
    throw error;
  }
}

const migrationDefaults: MigrationOperations = {
  getStatus: getDaemonStatus, getStartup: getStartupStatus, copy: installSystemCopy,
  preflight: async paths => { await preflightCores(paths, readConfig(paths)); }, enable: enableStartup, disable: disableStartup,
  startManaged, stopManaged, startPortable: startDetachedDaemon, stopPortable: stopDaemonGracefully,
  waitReady: paths => waitForReady(paths, 45000), activate: activateSystemInstallation, deactivate: deactivateSystemInstallation,
  prepareFirewall: migrationPrepareFirewall,
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
  let firewall: MigrationFirewallTransaction | undefined;
  try {
    firewall = await operations.prepareFirewall?.(paths, target);
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
    try { await firewall?.complete(); }
    catch (error) { console.log(`系统副本已就绪；原目录的防火墙规则清理未完成：${errorMessage(error)}`); }
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
    if (targetSafelyStopped && firewall) {
      try { await firewall.rollback(); }
      catch (e) { failures.push(`原防火墙规则恢复失败：${errorMessage(e)}`); }
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
