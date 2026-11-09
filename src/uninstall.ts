import * as uninstallFs from "node:fs";
import * as uninstallPath from "node:path";
import { defaultConfig, validateFirewallSettings, errorMessage, type AppConfig, type AppPaths } from "./core.ts";
import { acquireCoreSelectionLock } from "./network.ts";
import { acquireDaemonLock, stopDaemonGracefully } from "./daemon.ts";
import { assertUninstallTarget, uninstallStartup, removeInstalledProgram, isAdministrator, isSystemInstallation, runElevated } from "./platform.ts";
import { removeFirewall, type FirewallResult } from "./firewall.ts";
import { selectMenu } from "./ui.ts";

/** 卸载所需系统操作；测试替换这些依赖，避免操作宿主机服务和防火墙。 */
export interface UninstallOperations {
  validate(paths: AppPaths): void;
  lockUpdates(paths: AppPaths): () => void;
  unregister(paths: AppPaths): Promise<void>;
  stop(paths: AppPaths): Promise<void>;
  lockDaemon(paths: AppPaths): () => void;
  firewall(paths: AppPaths, config: AppConfig): Promise<FirewallResult>;
  program(paths: AppPaths): Promise<boolean>;
}

/**
 * 校验待清理目录中的每个条目，不跟随符号链接、junction 或特殊文件。
 * @param directory 已限定在当前安装数据目录内的路径。
 * @returns 验证通过时无返回值；任何链接均在开始删除前报错。
 */
function uninstallAssertTree(directory: string): void {
  const stat = uninstallFs.lstatSync(directory);
  if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new Error(`卸载拒绝链接或特殊文件：${directory}`);
  if (stat.isDirectory()) for (const name of uninstallFs.readdirSync(directory)) uninstallAssertTree(uninstallPath.join(directory, name));
}

/**
 * 仅读取卸载所需的防火墙设置，不迁移、重建或修改损坏的节点配置。
 * @param paths 卸载目标；缺失/损坏配置使用内存默认设置，由底层继续验证规则归属。
 * @returns 节点为空的配置，只传递经验证的防火墙后端选项。
 */
function uninstallFirewallConfig(paths: AppPaths): AppConfig {
  const config = defaultConfig();
  try {
    const saved = JSON.parse(uninstallFs.readFileSync(paths.config, "utf8"));
    if (saved?.firewall !== undefined) config.firewall = validateFirewallSettings(saved.firewall);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") console.log(`配置无法完整读取，将按安装归属清理防火墙：${errorMessage(error)}`);
  }
  return config;
}

/**
 * 提示卸载范围并询问配置保留方式，默认为保留，取消不产生任何写入。
 * @param paths 确认界面显示的实际目标绝对路径。
 * @returns true 保留配置及升级备份，false 删除数据，null 取消。
 */
export async function confirmUninstall(paths: AppPaths): Promise<boolean | null> {
  const choice = await selectMenu("卸载 NexusEdge", `目标：${paths.root}\n将停止全部节点、注销本安装自启、清理本工具防火墙规则及内核/日志。\n系统副本会移除程序；便携下载文件与全局 Bun 保留。\n是否保留配置文件（节点、密码、证书及配置备份）？`, ["卸载并保留配置（推荐）", "卸载并删除全部配置及数据", "取消"]);
  if (choice === 2) return null;
  if (choice === 1) {
    const confirmed = await selectMenu("确认删除配置", `将永久删除：${paths.data}\n包含节点凭据、证书、导出链接及备份。`, ["取消", "确认卸载并删除"], 0);
    if (confirmed !== 1) return null;
  }
  return choice === 0;
}

/**
 * 在用户已选择保留策略后执行卸载；需要权限时只提升无交互的执行阶段。
 * @param paths 已确认的安装；keepConfig 为确认结果；source 为提供新版卸载实现的入口；overrides 用于隔离提权测试。
 * @returns 卸载完成的 Promise。显式目标选项防止提权后转向其他安装；不调用旧版脚本的未知命令。
 */
export async function requestUninstall(paths: AppPaths, keepConfig: boolean, source = paths, overrides: Partial<{ admin: typeof isAdministrator; system: typeof isSystemInstallation; elevate: typeof runElevated }> = {}): Promise<void> {
  const ops = { admin: isAdministrator, system: isSystemInstallation, elevate: runElevated, ...overrides };
  if (!ops.admin()) {
    await ops.elevate(source, ["--uninstall", ops.system(paths) ? "--system" : "--local", keepConfig ? "--keep-config" : "--remove-config"]);
    console.log(`卸载操作完成：${paths.root}${keepConfig ? `\n配置及备份保留在：${paths.data}` : ""}`);
  } else await uninstallApplication(paths, keepConfig);
}

/**
 * 执行卸载：先核对归属和停止状态，清理规则成功后才删除数据。
 * @param paths 当前安装的标准路径，keepConfig 决定保留配置与 updates 备份。
 * @param overrides 测试注入的系统操作；生产默认调用真实平台 API。
 * @returns Windows 专用 Bun 是否正在等待当前面板退出后清理。
 * 停止或规则清理失败会保留数据。便携根目录、用户源代码和全局 Bun 均不递归删除。
 */
export async function uninstallApplication(paths: AppPaths, keepConfig: boolean, overrides: Partial<UninstallOperations> = {}): Promise<boolean> {
  const ops: UninstallOperations = { validate: assertUninstallTarget, lockUpdates: acquireCoreSelectionLock, unregister: uninstallStartup, stop: stopDaemonGracefully, lockDaemon: acquireDaemonLock, firewall: removeFirewall, program: removeInstalledProgram, ...overrides };
  if (uninstallPath.resolve(paths.data) !== uninstallPath.join(uninstallPath.resolve(paths.root), ".nexus-edge")) throw new Error("卸载数据路径与安装目录不匹配。");
  ops.validate(paths);
  if (uninstallFs.existsSync(paths.data)) uninstallAssertTree(paths.data);
  const config = uninstallFirewallConfig(paths);
  const releaseUpdates = ops.lockUpdates(paths);
  let releaseDaemon: (() => void) | undefined;
  // 锁文件永久保留：释放后删除会让其他进程锁住旧 inode，破坏 Linux 单实例互斥。
  const isLock = (name: string): boolean => /^(?:daemon-lock|core-update-lock)\.sqlite(?:-journal|-wal|-shm)?$/.test(name);
  let pending = false;
  try {
    await ops.unregister(paths);
    await ops.stop(paths);
    releaseDaemon = ops.lockDaemon(paths);
    const result = await ops.firewall(paths, config);
    const hasFirewallRecord = ["firewall-state.json", "firewall-linux-state.json"].some(name => uninstallFs.existsSync(uninstallPath.join(paths.data, name)));
    if (result.status !== "synced" && !(result.status === "unsupported" && result.backend === "none" && !hasFirewallRecord)) throw new Error(`卸载已停止，数据和防火墙归属记录保留。无法确认规则清理完成：${result.detail}`);
    if (uninstallFs.existsSync(paths.data)) {
      uninstallAssertTree(paths.data);
      const names = uninstallFs.readdirSync(paths.data);
      // 配置放在最后删除；若先前清理失败，尽可能留下可恢复的节点资料。
      names.sort((a, b) => Number(a.startsWith("config.json")) - Number(b.startsWith("config.json")));
      for (const name of names) {
        if (isLock(name) || (keepConfig && (name === "config.json" || name.startsWith("config.json.") || name === "updates"))) continue;
        uninstallFs.rmSync(uninstallPath.join(paths.data, name), { recursive: true, force: true });
      }
    }
    // 程序入口也在持锁期间移除，防止清理期间其他入口重启后台或执行内核更新。
    pending = await ops.program(paths);
  } finally { try { releaseDaemon?.(); } finally { releaseUpdates(); } }
  console.log(`卸载完成：后台已停止，自启已注销。${keepConfig ? `\n配置及已有备份保留在：${paths.data}` : "\n配置及运行数据已删除。"}${pending ? "\nWindows 专用 Bun 将在面板退出后自动清理；失败详情写入安装目录 uninstall-error.log。" : ""}`);
  return pending;
}
