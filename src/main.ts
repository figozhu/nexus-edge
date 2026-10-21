import * as mainUrl from "node:url";
import * as mainPath from "node:path";
import { APP_VERSION, assertSupportedPlatform, createPaths, atomicWrite, errorMessage, type AppPaths } from "./core.ts";
import { runDaemonWorker, runCoreHost, stopDaemonGracefully } from "./daemon.ts";
import { isAdministrator, discoverSystemInstallation, isSystemInstallation, runElevated, installedScriptVersion, updateSystemEntry } from "./platform.ts";
import { migrateSystemInstallation } from "./migration.ts";
import { UserCancelledError, UiExitRequestedError, selectMenu } from "./ui.ts";
import { runPanel } from "./panel.ts";

export async function nexusMain(args = process.argv.slice(2), entry = mainUrl.fileURLToPath(import.meta.url)): Promise<number> {
  if (args[0] === "--help" || args[0] === "-h") {
    console.log(`NexusEdge ${APP_VERSION}\n\n运行：bun nexus-edge.ts\n多协议节点管理：VLESS / VMess / SS / Trojan / Hysteria2 / TUIC / AnyTLS / SOCKS5 / Naive。\n隧道按节点可选：关闭 / 临时 / 固定。首次进入面板后添加节点。\n内核管理：检查官方更新、按需升级、预发布 / 指定版本、回退。\n支持 Windows x64、Linux x64 / arm64，Bun >= 1.4.3。\n\n--help / --version  查看说明或版本\n其他 --worker / --core-host / --stop-worker / --install-system / --update-system 参数由程序内部使用。`);
    return 0;
  }
  if (args[0] === "--version") { console.log(APP_VERSION); return 0; }
  assertSupportedPlatform();
  const version = Bun.version.split(".").map(Number);
  if ((version[0] ?? 0) < 1 || (version[0] === 1 && ((version[1] ?? 0) < 4 || (version[1] === 4 && (version[2] ?? 0) < 3)))) throw new Error("请使用 Bun 1.4.3 或更新版本。");
  const paths = createPaths(entry);
  if (args[0] === "--core-host") return runCoreHost(args[1] ?? "", args.slice(2));
  if (args[0] === "--worker") { await runDaemonWorker(paths); return 0; }
  if (args[0] === "--stop-worker") { await stopDaemonGracefully(paths); return 0; }
  if (args[0] === "--update-system") {
    const result = await updateSystemEntry(paths);
    console.log(`已更新系统脚本，原脚本备份：${result.backup}${result.configBackup ? `\n对应原配置备份：${result.configBackup}` : ""}\n现有后台保持运行；请在新版面板选择“启动 / 重启全部节点”应用新版本。\n如需回退旧版，请先停止后台，再同时恢复对应的脚本和配置。`);
    return 0;
  }
  if (args[0] === "--install-system") {
    if (!await isAdministrator()) throw new Error("系统安装需要管理员权限。");
    const requestId = args[1];
    if (requestId && !/^[0-9a-f-]{36}$/.test(requestId)) throw new Error("无效的安装请求 ID。");
    try {
      const installed = await migrateSystemInstallation(paths);
      if (requestId) atomicWrite(mainPath.join(paths.data, "installation-result.json"), JSON.stringify({ requestId, ok: true }) + "\n");
      console.log(`系统自启已注册并启动：${installed.root}`);
      return 0;
    } catch (e) {
      if (requestId) {
        try { atomicWrite(mainPath.join(paths.data, "installation-result.json"), JSON.stringify({ requestId, ok: false, message: errorMessage(e) }) + "\n"); } catch { /* Preserve the installation error. */ }
      }
      throw e;
    }
  }
  if (args.length) throw new Error(`不识别的参数：${args[0]}。直接运行 bun nexus-edge.ts 即可打开面板。`);
  let current: AppPaths = paths;
  const system = discoverSystemInstallation();
  if (system && !isSystemInstallation(paths)) {
    const installedVersion = installedScriptVersion(system.entry);
    if (installedVersion !== APP_VERSION) {
      const choice = await selectMenu("检测到不同版本的系统副本", `当前脚本：${APP_VERSION}；系统副本：${installedVersion ?? "未知版本"}。\n升级保留系统副本的配置、UUID、密钥及运行中的后台。`, ["使用当前脚本升级系统副本并打开面板", "打开已安装版本", "退出"]);
      if (choice === 2) return 0;
      if (choice === 0) await runElevated(paths, ["--update-system"]);
    }
    console.log("打开系统副本的管理面板……");
    await runElevated(createPaths(system.entry, system.runtime), []);
    return 0;
  }
  if (isSystemInstallation(current) && !await isAdministrator()) {
    console.log("系统副本由管理员管理；正在请求 UAC / sudo 授权……");
    await runElevated(current, []); return 0;
  }
  const result = await runPanel(current);
  if (result === "handoff") {
    const target = discoverSystemInstallation();
    if (!target) throw new Error("无法定位系统副本。");
    current = createPaths(target.entry, target.runtime);
    await runElevated(current, []);
  } else console.log("已退出面板，后台运行状态保持不变。");
  return 0;
}

if (import.meta.main) {
  try { process.exitCode = await nexusMain(); }
  catch (e) {
    if (e instanceof UserCancelledError || e instanceof UiExitRequestedError) { console.log("\n已退出面板，后台运行状态保持不变。"); process.exitCode = 0; }
    else { console.error(`\nNexusEdge：${errorMessage(e)}`); process.exitCode = 1; }
  } finally {
    if (process.stdin.isTTY && process.stdin.isRaw) process.stdin.setRawMode(false);
    if (process.stdout.isTTY) process.stdout.write("\x1b[?25h");
    process.stdin.pause();
  }
  // Worker shutdown has already awaited owned children. Explicit exit also clears
  // aborted readiness/retry timers and makes scheduled-task exit codes reliable.
  process.exit(process.exitCode ?? 0);
}
