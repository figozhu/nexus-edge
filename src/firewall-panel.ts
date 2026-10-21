import { type AppConfig, type AppPaths, type FirewallSettings, configFingerprint, getFirewallSettings, readConfig, validateFirewallSettings, writeConfig } from "./core.ts";
import { buildFirewallPlan, readFirewallRecord, type FirewallResult, type FirewallRule } from "./firewall.ts";
import { syncFirewallInteractive } from "./firewall-control.ts";
import { selectMenu, uiPause, uiValidatedInput, UserCancelledError, UiExitRequestedError } from "./ui.ts";
import { errorMessage } from "./core.ts";

const firewallPanelLabels: Record<FirewallResult["status"], string> = {
  synced: "规则已同步", "needs-update": "规则待更新", "permission-required": "需要管理员权限",
  inactive: "当前无需本机放行", unsupported: "需要手动处理", blocked: "被系统策略阻止", error: "未完成",
};

export function firewallPortSummary(rules: FirewallRule[]): string {
  const ports = [...new Set(rules.map(rule => `${rule.protocol.toUpperCase()} ${rule.port}`))];
  return ports.length ? ports.join("、") : "无须开放入站端口";
}

export function printFirewallResult(result: FirewallResult): void {
  console.log(`防火墙：${firewallPanelLabels[result.status]}${result.backend === "none" ? "" : `（${result.backend}）`}。${result.detail}`);
  for (const warning of result.warnings) console.log(`防火墙提示：${warning}`);
}

/** A saved receipt is labeled as such; it never substitutes for an OS policy check. */
export function firewallPanelSummary(paths: AppPaths, config: AppConfig): string {
  if (getFirewallSettings(config).mode === "manual") return "防火墙：手动管理（可在防火墙菜单同步或清理规则）";
  const plan = buildFirewallPlan(paths, config), record = readFirewallRecord(paths);
  if (!record) return `防火墙：自动管理，应用时检查（${firewallPortSummary(plan.rules)}）`;
  if (record.fingerprint !== plan.fingerprint) return "防火墙：自动管理，当前节点规则待同步";
  return `防火墙：自动管理，上次检查：${firewallPanelLabels[record.result.status]}`;
}

export function requireFirewallApply(result: FirewallResult | null): void {
  if (result && ["blocked", "error", "permission-required", "needs-update"].includes(result.status)) {
    throw new Error(`防火墙尚未完成放行，已保留原配置与后台：${result.detail}\n可在“防火墙 / 端口放行”中重试；已有独立防火墙方案时可切换为手动管理。`);
  }
}

async function firewallPanelSave(paths: AppPaths, before: AppConfig, settings: FirewallSettings): Promise<void> {
  const hash = configFingerprint(before), candidate = { ...before, firewall: settings };
  if (settings.mode === "auto") {
    const result = await syncFirewallInteractive(paths, candidate, { expectedConfigHash: hash, report: printFirewallResult });
    requireFirewallApply(result);
  }
  if (configFingerprint(readConfig(paths)) !== hash) throw new Error("配置已在另一处修改，请重新打开防火墙设置。");
  writeConfig(paths, candidate);
}

async function firewallPanelAdvanced(paths: AppPaths, config: AppConfig): Promise<void> {
  const settings = getFirewallSettings(config);
  const backends: FirewallSettings["linuxBackend"][] = ["auto", "ufw", "firewalld", "iptables"];
  const index = await selectMenu("Linux 防火墙管理器 · 高级", "默认自动识别。只有服务器使用多个管理器或指定网络区域时才需要调整。\n不会启动未启用的防火墙，也不会改变系统默认策略。", ["自动识别（推荐）", "UFW", "firewalld", "iptables / ip6tables", "返回"], backends.indexOf(settings.linuxBackend));
  if (index === 4) return;
  settings.linuxBackend = backends[index]!;
  if (settings.linuxBackend === "firewalld") {
    settings.firewalldZone = await uiValidatedInput("firewalld 区域名称（留空自动选择；输入 - 清除）", settings.firewalldZone, value => validateFirewallSettings({ ...settings, firewalldZone: value }).firewalldZone, { clearable: true });
  } else settings.firewalldZone = "";
  await firewallPanelSave(paths, config, settings);
  console.log("防火墙设置已保存。节点协议、端口和认证信息保持原值。");
}

export async function runFirewallPanel(paths: AppPaths): Promise<void> {
  for (;;) {
    const config = readConfig(paths), settings = getFirewallSettings(config), plan = buildFirewallPlan(paths, config);
    const information = [firewallPanelSummary(paths, config), `按已启用直连节点放行：${firewallPortSummary(plan.rules)}`,
      "使用本机监听端口；仅隧道和回环监听不开放入站端口。",
      "自动模式在保存并应用、启动及重启时同步，必要时请求 UAC / sudo。",
      "云服务器安全组、路由器映射及第三方安全软件需在对应位置设置。",
      ...plan.warnings].join("\n");
    const options = ["立即检查 / 放行已启用节点端口", settings.mode === "auto" ? "改为手动管理（保留现有规则）" : "开启自动管理（推荐）", "清理本工具规则，并改为手动管理", ...(process.platform === "linux" ? ["高级设置（管理器 / firewalld 区域）"] : []), "返回"];
    const choice = await selectMenu("防火墙 / 端口放行", information, options);
    if (choice === options.length - 1) return;
    try {
      if (choice === 0) await syncFirewallInteractive(paths, config, { force: true, expectedConfigHash: configFingerprint(config), report: printFirewallResult });
      else if (choice === 1) {
        await firewallPanelSave(paths, config, { ...settings, mode: settings.mode === "auto" ? "manual" : "auto" });
        console.log(settings.mode === "auto" ? "已改为手动管理，现有规则保留。启动、停止及更新节点均不会自动改动防火墙。" : "已开启自动管理。");
      } else if (choice === 2) {
        if (await selectMenu("清理 NexusEdge 防火墙规则", "仅删除本安装目录创建的放行规则；你手工设置及其他软件的规则会保留。\n正在运行的直连节点可能失去外部连接，隧道及后台进程继续运行。", ["返回", "清理并改为手动管理"]) === 0) continue;
        const result = await syncFirewallInteractive(paths, config, { force: true, remove: true, expectedConfigHash: configFingerprint(config), report: printFirewallResult });
        if (result?.status === "synced") {
          await firewallPanelSave(paths, config, { ...settings, mode: "manual" });
          console.log("已改为手动管理，后续启动不会重新创建规则。");
        }
      } else await firewallPanelAdvanced(paths, config);
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      if (error instanceof UserCancelledError) continue;
      console.log(errorMessage(error));
    }
    await uiPause();
  }
}
