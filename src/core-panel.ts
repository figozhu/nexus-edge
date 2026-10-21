import { type AppPaths, type AppConfig, type DaemonStatus, nodeEngine, readConfig, errorMessage } from "./core.ts";
import { type BinaryKind, type CoreRelease, type CoreReleaseCandidate, type CoreReleaseMap, type CoreSelectionState, readCoreSelection, checkCoreUpdates, fetchCoreRelease, compareCoreVersions, coreReleaseFingerprint } from "./network.ts";
import { getDaemonStatus } from "./daemon.ts";
import { applyCoreUpdates, rollbackCoreUpdates } from "./updates.ts";
import { selectMenu, promptInput, uiPause, UiExitRequestedError, UserCancelledError } from "./ui.ts";

export interface CorePanelServices {
  selection: typeof readCoreSelection;
  config: typeof readConfig;
  status: typeof getDaemonStatus;
  check: typeof checkCoreUpdates;
  release: typeof fetchCoreRelease;
  apply: typeof applyCoreUpdates;
  rollback: typeof rollbackCoreUpdates;
  menu: typeof selectMenu;
  input: typeof promptInput;
  pause: typeof uiPause;
  report: (message: string) => void;
}

const corePanelTools: BinaryKind[] = ["singBox", "xray", "cloudflared"];
const corePanelNames: Record<BinaryKind, string> = { singBox: "sing-box", xray: "Xray", cloudflared: "cloudflared" };

function corePanelServices(overrides: Partial<CorePanelServices>): CorePanelServices {
  return { selection: readCoreSelection, config: readConfig, status: getDaemonStatus, check: checkCoreUpdates,
    release: fetchCoreRelease, apply: applyCoreUpdates, rollback: rollbackCoreUpdates,
    menu: selectMenu, input: promptInput, pause: uiPause, report: message => console.log(message), ...overrides };
}

/** Reading the menu must also work while an expired certificate awaits repair. */
function corePanelRequired(config: AppConfig): Set<BinaryKind> {
  const nodes = config.nodes.filter(node => node.enabled);
  const tools = new Set<BinaryKind>(nodes.map(nodeEngine));
  if (nodes.some(node => node.tunnel.mode !== "none")) tools.add("cloudflared");
  return tools;
}

function corePanelSameContent(current: CoreRelease, candidate: CoreReleaseCandidate): boolean {
  return current.version === candidate.version && current.platform === candidate.platform && current.asset.asset === candidate.asset.asset && current.asset.sha256 === candidate.asset.sha256;
}

function corePanelSummary(state: CoreSelectionState, required: Set<BinaryKind>, status: DaemonStatus | null): string {
  const confirmed = status?.coreReleaseHash === coreReleaseFingerprint(state.active);
  const lines = corePanelTools.map(tool => {
    const release = state.active[tool];
    const usage = !required.has(tool) ? "当前配置未使用" : confirmed ? "后台已采用" : "下次启动使用";
    return `${corePanelNames[tool]}：${release.version}${release.prerelease ? "（预发布版）" : ""} · ${usage}`;
  });
  lines.push("", "启动时使用上次选定版本。进入此菜单或检查更新不会中断节点。",
    "默认检查稳定版，只升级当前节点需要的内核；没有隧道就不需要 cloudflared。");
  if (status && !confirmed) lines.push("当前后台尚未确认以上版本；应用更新后会重新启动并确认。");
  return lines.join("\n");
}

function corePanelChangeLines(current: CoreReleaseMap, candidates: CoreReleaseCandidate[]): string[] {
  return candidates.map(candidate => {
    const comparison = compareCoreVersions(candidate.version, current[candidate.tool].version);
    const labels = [candidate.prerelease ? "预发布版" : "", comparison < 0 ? "降级" : ""].filter(Boolean);
    return `${corePanelNames[candidate.tool]}：${current[candidate.tool].version} → ${candidate.version}${labels.length ? `（${labels.join("，")}）` : ""}`;
  });
}

async function corePanelConfirmChange(paths: AppPaths, services: CorePanelServices, current: CoreReleaseMap, candidates: CoreReleaseCandidate[], rollback = false): Promise<boolean> {
  const status = await services.status(paths);
  const config = services.config(paths);
  const information = [...corePanelChangeLines(current, candidates), "", "先下载、校验文件，并用现有节点配置做兼容性检查。检查失败保留原版本。"];
  if (rollback) information.push("回退使用当前节点配置，已有 UUID、密码、端口等设置保留。");
  if (status) {
    information.push("确认后会重启后台，现有连接会短暂断开；启动失败会尝试恢复原版本。");
    if (config.nodes.some(node => node.enabled && node.tunnel.mode === "quick")) information.push("临时隧道域名可能改变，完成后请重新查看链接。");
  } else information.push("后台当前未运行：只切换已选版本，下次启动生效。");
  if (candidates.some(candidate => candidate.prerelease)) information.push("预发布版可能改变配置和客户端兼容性，建议仅在需要新功能时选用。");
  const choice = await services.menu(rollback ? "确认回退内核" : "确认更新内核", information.join("\n"), [rollback ? "确认回退" : "确认更新", "取消"]);
  return choice === 0;
}

async function corePanelInstall(paths: AppPaths, services: CorePanelServices, candidates: CoreReleaseCandidate[], explicitVersion = false): Promise<void> {
  const selection = services.selection(paths), current = selection.active;
  const changed = candidates.filter(candidate => !corePanelSameContent(current[candidate.tool], candidate) && (explicitVersion || compareCoreVersions(candidate.version, current[candidate.tool].version) > 0));
  if (!changed.length) { services.report("已是所选版本，无需重新下载或重启。"); await services.pause(); return; }
  if (!await corePanelConfirmChange(paths, services, current, changed)) return;
  const result = await services.apply(paths, changed, services.report, {}, selection);
  services.report(!result.changed ? "版本没有变化。" : result.restarted ? "内核更新完成，后台已重新启动。可从主菜单查看节点链接。" : "内核版本已更新，后台保持停止。下次启动时生效。");
  await services.pause();
}

async function corePanelCheck(paths: AppPaths, services: CorePanelServices, channel: "stable" | "preview"): Promise<void> {
  services.report(channel === "stable" ? "正在检查三个组件的官方稳定版……" : "正在检查官方版本（包含预发布版）……");
  const checks = await services.check(paths, channel);
  const required = corePanelRequired(services.config(paths));
  const available = checks.flatMap(check => check.updateAvailable && check.latest ? [check.latest] : []);
  const needed = available.filter(candidate => required.has(candidate.tool));
  const details = checks.map(check => {
    const prefix = `${corePanelNames[check.tool]}：当前 ${check.current.version}`;
    if (check.error) return `${prefix} · 检查失败：${check.error}`;
    if (!check.latest) return `${prefix} · 未找到适配当前系统的版本`;
    if (check.updateAvailable) return `${prefix} → ${check.latest.version}${check.latest.prerelease ? "（预发布版）" : ""}${required.has(check.tool) ? "" : " · 当前配置未使用"}`;
    if (compareCoreVersions(check.current.version, check.latest.version) > 0) return `${prefix} · 比本通道最新 ${check.latest.version} 更新，保持当前版本`;
    return `${prefix} · 本通道暂无更新`;
  });
  if (channel === "stable" && checks.some(check => check.current.prerelease)) details.push("", "当前使用的预发布版不会自动降级；需要继续跟进预发布版时，进入“高级选项”。");
  if (!required.size) details.push("", "尚无启用的节点，不需要自动下载内核。需要时可单独选择。");
  const actions: { text: string; run: () => Promise<void> }[] = [];
  if (needed.length) actions.push({ text: `更新所需内核（${needed.map(candidate => corePanelNames[candidate.tool]).join("、")}）`, run: () => corePanelInstall(paths, services, needed) });
  if (available.length) actions.push({ text: "单独选择内核更新", run: async () => {
    const selected = await services.menu("选择内核", "只列出本次检查发现的更新。", [...available.map(candidate => `${corePanelNames[candidate.tool]} → ${candidate.version}${required.has(candidate.tool) ? "" : "（当前未使用）"}`), "返回"]);
    if (selected < available.length) await corePanelInstall(paths, services, [available[selected]!]);
  } });
  const selected = await services.menu(channel === "stable" ? "稳定版检查结果" : "预发布版检查结果", details.join("\n"), [...actions.map(action => action.text), "返回"], needed.length ? 0 : actions.length);
  if (selected < actions.length) await actions[selected]!.run();
}

async function corePanelAdvanced(paths: AppPaths, services: CorePanelServices): Promise<void> {
  const choice = await services.menu("内核高级选项", "只在需要预发布功能或指定官方版本时使用；选定后仍会校验与预检。", ["检查预发布版（同时包含稳定版）", "指定官方版本", "返回"]);
  if (choice === 0) await corePanelCheck(paths, services, "preview");
  if (choice !== 1) return;
  const index = await services.menu("选择要指定版本的内核", "版本号来自相应项目的 GitHub Releases。", [...corePanelTools.map(tool => corePanelNames[tool]), "返回"]);
  if (index === corePanelTools.length) return;
  const tool = corePanelTools[index]!;
  const version = await services.input(`${corePanelNames[tool]} 官方版本号（可带 v；留空取消）`);
  if (!version.trim()) return;
  services.report(`正在查询 ${corePanelNames[tool]} 官方版本 ${version}……`);
  const candidate = await services.release(tool, version);
  await corePanelInstall(paths, services, [candidate], true);
}

export async function runCorePanel(paths: AppPaths, overrides: Partial<CorePanelServices> = {}): Promise<void> {
  const services = corePanelServices(overrides);
  for (;;) {
    const state = services.selection(paths);
    const required = corePanelRequired(services.config(paths));
    const status = await services.status(paths);
    const choice = await services.menu("内核管理 / 更新", corePanelSummary(state, required, status), ["检查更新（稳定版，推荐）", "回退上次内核版本", "高级选项（预发布 / 指定版本）", "返回"]);
    if (choice === 3) return;
    try {
      if (choice === 0) await corePanelCheck(paths, services, "stable");
      else if (choice === 1) {
        const latest = services.selection(paths);
        if (!latest.previous || coreReleaseFingerprint(latest.previous) === coreReleaseFingerprint(latest.active)) { services.report("暂无可回退的版本。完成一次更新后会保留上一次版本。"); await services.pause(); continue; }
        const changed = corePanelTools.filter(tool => !corePanelSameContent(latest.active[tool], latest.previous![tool])).map(tool => latest.previous![tool]);
        if (!await corePanelConfirmChange(paths, services, latest.active, changed, true)) continue;
        const result = await services.rollback(paths, services.report, {}, latest);
        services.report(!result.changed ? "版本没有变化。" : result.restarted ? "内核已回退，后台已重新启动。" : "内核已回退，后台保持停止。下次启动时生效。");
        await services.pause();
      } else if (choice === 2) await corePanelAdvanced(paths, services);
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      if (error instanceof UserCancelledError) continue;
      services.report(errorMessage(error));
      await services.pause();
    }
  }
}
