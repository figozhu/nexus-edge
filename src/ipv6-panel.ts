import { errorMessage, type AppPaths } from "./core.ts";
import { isAdministrator, runElevated } from "./platform.ts";
import { inspectHostIpv6, setHostIpv6Enabled, type HostIpv6Status } from "./ipv6.ts";
import { selectMenu, uiPause, UserCancelledError, UiExitRequestedError } from "./ui.ts";

/** 菜单依赖可替换，便于验证确认/取消/UAC 行为且不碰真实网络。 */
export interface HostIpv6PanelServices {
  inspect: () => Promise<HostIpv6Status>;
  apply: (enabled: boolean) => Promise<HostIpv6Status>;
  isAdministrator: () => boolean;
  elevate: (paths: AppPaths, args: string[]) => Promise<void>;
  menu: typeof selectMenu;
  pause: typeof uiPause;
  report: (message: string) => void;
}

/** 将实际接口状态格式化为菜单说明，明确区分接口开关、地址可达性及核心开关。 */
export function hostIpv6Summary(status: HostIpv6Status): string {
  const labels = { enabled: "全部开启", disabled: "全部禁用", mixed: "部分开启", unavailable: "当前无法管理" };
  const lines = [`本机接口 IPv6：${labels[status.state]}`, ...status.interfaces.map(item => `  ${item.name}：${item.enabled ? "开启" : "禁用"}`)];
  if (status.defaultEnabled !== null) lines.push(`新接口默认值：${status.defaultEnabled ? "开启" : "禁用"}`);
  if (status.platform === "linux") lines.push(`本工具重启策略：${status.persistedEnabled === null ? "未设置或已被手工调整" : status.persistedEnabled ? "开启" : "禁用"}`);
  lines.push(status.detail, "本机接口开关与“核心 IPv6”设置相互独立；开启接口不等于已取得可用的 IPv6 地址。");
  return lines.join("\n");
}

/**
 * 显示本机网络菜单。paths 只用于已验证单文件的 UAC/sudo 入口，不传给特权网络写入。
 * 每次切换先明确确认，提权后重新查询实际接口；取消、权限不足均不伪报成功。
 */
export async function runHostIpv6Panel(paths: AppPaths, overrides: Partial<HostIpv6PanelServices> = {}): Promise<void> {
  const services: HostIpv6PanelServices = { inspect: inspectHostIpv6, apply: setHostIpv6Enabled, isAdministrator, elevate: runElevated, menu: selectMenu, pause: uiPause, report: console.log, ...overrides };
  for (;;) {
    let status: HostIpv6Status;
    try { status = await services.inspect(); }
    catch (error) { services.report(`读取本机 IPv6 状态失败：${errorMessage(error)}`); await services.pause(); return; }
    const choice = await services.menu("本机 IPv6 网络接口", hostIpv6Summary(status), ["禁用本机 IPv6 接口", "开启本机 IPv6 接口", "刷新状态", "返回"], 3);
    if (choice === 3) return;
    if (choice === 2) continue;
    if (status.state === "unavailable") { services.report(status.detail); await services.pause(); continue; }
    const enabled = choice === 1;
    try {
      const confirmed = await services.menu(enabled ? "开启本机 IPv6 接口" : "禁用本机 IPv6 接口", [
        `将${enabled ? "开启" : "禁用"}此机器所有可管理接口的 IPv6，影响其他应用并保存到系统。`,
        "网卡可能重连；当前 IPv6 远程管理或代理连接可能中断。禁用后原 IPv6 地址可能需要网络管理器重新配置。",
        "需要管理员 / root 权限。此操作不自动改变核心 IPv6 设置。",
      ].join("\n"), ["返回", `确认${enabled ? "开启" : "禁用"}`]);
      if (confirmed === 0) continue;
      if (services.isAdministrator()) status = await services.apply(enabled);
      else { await services.elevate(paths, ["--host-ipv6", enabled ? "enable" : "disable"]); status = await services.inspect(); }
      if (status.state !== (enabled ? "enabled" : "disabled") || (status.platform === "linux" && status.defaultEnabled !== enabled)) throw new Error("系统返回后，接口状态仍与目标不一致，请刷新检查网络管理器或系统策略。");
      services.report(`已${enabled ? "开启" : "禁用"}本机 IPv6 网络接口。\n${hostIpv6Summary(status)}`);
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      if (error instanceof UserCancelledError) continue;
      services.report(`本机 IPv6 操作未完成：${errorMessage(error)}`);
    }
    await services.pause();
  }
}
