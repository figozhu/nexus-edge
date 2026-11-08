import * as hostIpv6Fs from "node:fs";
import * as hostIpv6Path from "node:path";
import { atomicWrite, errorMessage } from "./core.ts";
import { isAdministrator, platformPowerShell } from "./platform.ts";

/** 本机接口的 IPv6 开关状态；不代表该接口已获取地址或具有公网连通性。 */
export interface HostIpv6Interface { name: string; enabled: boolean }
/** 操作系统实际读取的状态；Linux 的新接口默认值与持久化值单独展示。 */
export interface HostIpv6Status {
  platform: NodeJS.Platform;
  state: "enabled" | "disabled" | "mixed" | "unavailable";
  interfaces: HostIpv6Interface[];
  defaultEnabled: boolean | null;
  persistedEnabled: boolean | null;
  detail: string;
}
/** Linux sysctl 快照包含 all、default 及每个接口，便于失败时恢复不同的原值。 */
export type HostIpv6LinuxSnapshot = Record<string, 0 | 1>;
/** 所有系统写操作均可注入；自动测试不得修改宿主机的真实网络接口。 */
export interface HostIpv6Dependencies {
  platform: NodeJS.Platform;
  isAdministrator: () => boolean;
  powerShell: (script: string) => Promise<string>;
  linuxRead: () => HostIpv6LinuxSnapshot;
  linuxWrite: (name: string, disabled: 0 | 1) => void;
  linuxReadPolicy: () => string | null;
  linuxWritePolicy: (content: string | null) => void;
}

const hostIpv6ProcRoot = "/proc/sys/net/ipv6/conf";
const hostIpv6PolicyFile = "/etc/sysctl.d/99-nexus-edge-ipv6.conf";
const hostIpv6PolicyMarker = "# NexusEdge managed IPv6 interface policy";

/**
 * 校验内核返回的接口名，返回安全的 procfs 文件路径。
 * name 不是命令片段；拒绝目录跳转、控制字符和分隔符后仅作为路径段使用。
 */
function hostIpv6ProcFile(name: string): string {
  if (!name || name.length > 128 || name === "." || name === ".." || /[\\/\x00-\x1f\x7f]/.test(name)) throw new Error("Linux 返回了无法安全管理的网络接口名称。");
  return hostIpv6Path.posix.join(hostIpv6ProcRoot, name, "disable_ipv6");
}

/** 读取全部真实接口以及 all/default；目录不存在表示内核未提供 IPv6 控制接口。 */
function hostIpv6ReadLinux(): HostIpv6LinuxSnapshot {
  if (!hostIpv6Fs.existsSync(hostIpv6ProcRoot)) return {};
  const snapshot: HostIpv6LinuxSnapshot = {};
  for (const name of hostIpv6Fs.readdirSync(hostIpv6ProcRoot).sort()) {
    const file = hostIpv6ProcFile(name), stat = hostIpv6Fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`IPv6 控制文件不是普通 procfs 文件：${file}`);
    const value = hostIpv6Fs.readFileSync(file, "utf8").trim();
    if (value !== "0" && value !== "1") throw new Error(`IPv6 控制值无效：${name}`);
    Object.defineProperty(snapshot, name, { value: Number(value), enumerable: true, writable: true, configurable: true });
  }
  return snapshot;
}

/** 将确定的 0/1 写入已有 procfs 文件，不创建文件、不调用 shell 或修改其他 sysctl。 */
function hostIpv6WriteLinux(name: string, disabled: 0 | 1): void {
  const file = hostIpv6ProcFile(name), stat = hostIpv6Fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`IPv6 控制文件无效：${file}`);
  hostIpv6Fs.writeFileSync(file, `${disabled}\n`, { flag: "r+" });
}

/**
 * 检查持久化目录及文件的所有者/权限，返回文件内容或 null。
 * 只接受本工具标记的普通单链接文件，避免覆盖管理员已有的同名配置。
 */
function hostIpv6ReadPolicy(): string | null {
  for (const directory of ["/", "/etc", "/etc/sysctl.d"]) {
    const stat = hostIpv6Fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) throw new Error(`sysctl 目录必须由 root 管理且不可由普通用户写入：${directory}`);
  }
  let stat: ReturnType<typeof hostIpv6Fs.lstatSync>;
  try { stat = hostIpv6Fs.lstatSync(hostIpv6PolicyFile); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== 0 || (stat.mode & 0o022) !== 0 || stat.size > 4096) throw new Error(`拒绝覆盖不安全的 IPv6 持久化文件：${hostIpv6PolicyFile}`);
  const text = hostIpv6Fs.readFileSync(hostIpv6PolicyFile, "utf8");
  if (!text.startsWith(hostIpv6PolicyMarker + "\n")) throw new Error(`同名 sysctl 文件不属于 NexusEdge，请先由管理员检查：${hostIpv6PolicyFile}`);
  return text;
}

/** 仅原子替换或移除本工具的 sysctl 文件；content 为 null 表示回滚到原本不存在。 */
function hostIpv6WritePolicy(content: string | null): void {
  const before = hostIpv6ReadPolicy();
  if (content === null) { if (before !== null) hostIpv6Fs.unlinkSync(hostIpv6PolicyFile); }
  else atomicWrite(hostIpv6PolicyFile, content, 0o644);
}

/** 生成最小持久化策略：all 作用于现有接口，default 作用于之后出现的接口。 */
function hostIpv6Policy(enabled: boolean): string {
  const value = enabled ? 0 : 1;
  return `${hostIpv6PolicyMarker}\nnet.ipv6.conf.all.disable_ipv6 = ${value}\nnet.ipv6.conf.default.disable_ipv6 = ${value}\n`;
}

/** 合并生产实现与测试替身；调用方不传路径，特权写入位置固定在模块内部。 */
function hostIpv6Dependencies(overrides: Partial<HostIpv6Dependencies>): HostIpv6Dependencies {
  return { platform: process.platform, isAdministrator, powerShell: platformPowerShell,
    linuxRead: hostIpv6ReadLinux, linuxWrite: hostIpv6WriteLinux,
    linuxReadPolicy: hostIpv6ReadPolicy, linuxWritePolicy: hostIpv6WritePolicy, ...overrides };
}

/** 根据各接口真实开关计算状态；不根据 Linux conf/all 的读值推断接口状态。 */
function hostIpv6State(interfaces: HostIpv6Interface[]): HostIpv6Status["state"] {
  if (!interfaces.length) return "unavailable";
  if (interfaces.every(item => item.enabled)) return "enabled";
  if (interfaces.every(item => !item.enabled)) return "disabled";
  return "mixed";
}

/**
 * 构造 Windows 查询/切换脚本。enabled 缺省时严格只读。
 * 网卡由系统枚举后通过 CIM 对象传给 cmdlet，名称不会进入命令代码或通配符参数。
 * 更新失败时逐个恢复快照中的绑定开关，并将回滚失败作为具体错误返回。
 */
function hostIpv6WindowsScript(enabled?: boolean): string {
  const query = `
function Get-IPv6Bindings {
  @(Get-NetAdapterBinding -Name '*' -ComponentID 'ms_tcpip6' -IncludeHidden -AllBindings -ErrorAction Stop)
}
function Write-IPv6Status {
  $items = @(Get-IPv6Bindings | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled } })
  ConvertTo-Json -InputObject $items -Compress -Depth 4
}
`;
  if (enabled === undefined) return query + "Write-IPv6Status\n";
  return query + `
$desired = ${enabled ? "$true" : "$false"}
$before = @(Get-IPv6Bindings | ForEach-Object { [pscustomobject]@{ binding = $_; enabled = [bool]$_.Enabled } })
if ($before.Count -eq 0) { throw '未找到支持 ms_tcpip6 绑定的网络接口。' }
try {
  foreach ($item in $before) {
    if ($item.enabled -ne $desired) { Set-NetAdapterBinding -InputObject $item.binding -Enabled $desired -Confirm:$false -ErrorAction Stop }
  }
  $after = @(Get-IPv6Bindings)
  if ($after.Count -eq 0 -or @($after | Where-Object { [bool]$_.Enabled -ne $desired }).Count -gt 0) { throw '部分网络接口的 IPv6 绑定未达到目标状态。' }
} catch {
  $originalError = $_.Exception.Message
  $rollbackErrors = @()
  foreach ($item in $before) {
    try { Set-NetAdapterBinding -InputObject $item.binding -Enabled $item.enabled -Confirm:$false -ErrorAction Stop }
    catch { $rollbackErrors += ([string]$item.binding.Name + ': ' + $_.Exception.Message) }
  }
  if ($rollbackErrors.Count) { throw ($originalError + '；部分开关回滚失败：' + ($rollbackErrors -join '；')) }
  throw ($originalError + '；已恢复操作前的接口开关，请检查网络管理器和原 IPv6 地址配置。')
}
Write-IPv6Status
`;
}

/** 校验系统 PowerShell 返回的 JSON，不接受字符串布尔值或缺失名称。 */
function hostIpv6WindowsStatus(text: string): HostIpv6Status {
  let raw: unknown;
  try { raw = JSON.parse(text.replace(/^\uFEFF/, "").trim()); }
  catch { throw new Error("Windows IPv6 接口查询未返回有效 JSON。"); }
  if (!Array.isArray(raw) || raw.length > 4096 || raw.some(item => !item || typeof item.name !== "string" || !item.name || typeof item.enabled !== "boolean")) throw new Error("Windows IPv6 接口查询返回了无效状态。");
  const interfaces = raw.map(item => ({ name: item.name as string, enabled: item.enabled as boolean }));
  return { platform: "win32", state: hostIpv6State(interfaces), interfaces, defaultEnabled: null, persistedEnabled: null,
    detail: "管理当前网卡的 ms_tcpip6 绑定（包括隐藏网卡），开关由 Windows 保存；不改变 IPv4、回环 IPv6 或系统注册表。新增网卡需重新检查。" };
}

/** 将 Linux 快照及持久化内容转换为状态；缺少 all/default 时不能执行全局切换。 */
function hostIpv6LinuxStatus(snapshot: HostIpv6LinuxSnapshot, policy: string | null): HostIpv6Status {
  const interfaces = Object.entries(snapshot).filter(([name]) => name !== "all" && name !== "default").map(([name, disabled]) => ({ name, enabled: disabled === 0 }));
  const persistedEnabled = policy === hostIpv6Policy(true) ? true : policy === hostIpv6Policy(false) ? false : null;
  return { platform: "linux", state: hostIpv6State(interfaces), interfaces, defaultEnabled: snapshot.default === undefined ? null : snapshot.default === 0, persistedEnabled,
    detail: interfaces.length ? `通过内核 sysctl 管理所有接口（含回环）及新接口默认值；持久化文件：${hostIpv6PolicyFile}。其他 sysctl 配置或网络管理器仍可能覆盖，重连后可在此重新检查。`
      : "内核未提供 IPv6 接口控制项；可能未加载 IPv6 或使用 ipv6.disable=1 启动，无法通过此菜单开启。" };
}

/** 只读查询本机 IPv6 开关；返回接口、默认值和持久化状态，失败时抛出具体系统错误。 */
export async function inspectHostIpv6(overrides: Partial<HostIpv6Dependencies> = {}): Promise<HostIpv6Status> {
  const deps = hostIpv6Dependencies(overrides);
  if (deps.platform === "win32") return hostIpv6WindowsStatus(await deps.powerShell(hostIpv6WindowsScript()));
  if (deps.platform === "linux") {
    const snapshot = deps.linuxRead();
    return hostIpv6LinuxStatus(snapshot, Object.keys(snapshot).length ? deps.linuxReadPolicy() : null);
  }
  return { platform: deps.platform, state: "unavailable", interfaces: [], defaultEnabled: null, persistedEnabled: null, detail: "本机 IPv6 接口管理仅支持 Windows / Linux。" };
}

/**
 * 设置全部本机接口的 IPv6 开关，enabled 必须为布尔值；返回重新读取的实际状态。
 * 需要管理员/root 权限。Linux 先写自有持久化文件再改内核，失败恢复原策略及逐接口开关。
 * 开关回滚不承诺恢复已被内核移除的静态地址或既有 TCP 连接。
 */
export async function setHostIpv6Enabled(enabled: boolean, overrides: Partial<HostIpv6Dependencies> = {}): Promise<HostIpv6Status> {
  if (typeof enabled !== "boolean") throw new Error("IPv6 开关必须为 true 或 false。");
  const deps = hostIpv6Dependencies(overrides);
  if (deps.platform !== "win32" && deps.platform !== "linux") throw new Error("本机 IPv6 接口管理仅支持 Windows / Linux。");
  if (!deps.isAdministrator()) throw new Error("修改本机 IPv6 网络接口需要管理员 / root 权限。");
  if (deps.platform === "win32") {
    const status = hostIpv6WindowsStatus(await deps.powerShell(hostIpv6WindowsScript(enabled)));
    if (status.state !== (enabled ? "enabled" : "disabled")) throw new Error("Windows 返回的接口状态与目标不一致，请重新检查网卡或系统策略。");
    return status;
  }
  const before = deps.linuxRead(), previousPolicy = deps.linuxReadPolicy();
  if (before.all === undefined || before.default === undefined || !Object.keys(before).some(name => name !== "all" && name !== "default")) throw new Error("内核未提供完整 IPv6 控制项，未修改持久化配置。请检查 IPv6 模块及内核启动参数。");
  const value = enabled ? 0 : 1;
  let liveAttempted = false;
  try {
    // 先确认持久化可写；即使原子写入在重命名之后报错，也尝试恢复原文件。
    deps.linuxWritePolicy(hostIpv6Policy(enabled));
    liveAttempted = true;
    deps.linuxWrite("all", value);
    deps.linuxWrite("default", value);
    const actual = deps.linuxRead();
    if (Object.keys(actual).length < 3 || Object.values(actual).some(disabled => disabled !== value)) throw new Error("部分接口的 IPv6 开关未达到目标状态，可能被网络管理器覆盖。");
    return hostIpv6LinuxStatus(actual, deps.linuxReadPolicy());
  } catch (error) {
    const failures: string[] = [];
    // all 会同步覆盖其他接口，因此先恢复 all，再恢复 default 和每个接口的原值。
    const ordered = liveAttempted ? ["all", "default", ...Object.keys(before).filter(name => name !== "all" && name !== "default")] : [];
    for (const name of ordered) {
      try { deps.linuxWrite(name, before[name]!); }
      catch (rollbackError) { failures.push(`${name}：${errorMessage(rollbackError)}`); }
    }
    try { deps.linuxWritePolicy(previousPolicy); }
    catch (rollbackError) { failures.push(`持久化策略：${errorMessage(rollbackError)}`); }
    throw new Error(`IPv6 切换失败：${errorMessage(error)}；${failures.length ? `部分开关回滚失败：${failures.join("；")}` : "已恢复原接口开关和持久化策略，请检查原 IPv6 地址配置。"}`);
  }
}

/**
 * 特权辅助入口只接受一个 enable/disable 参数；无外部路径、接口名或配置读取。
 * args 为 --host-ipv6 之后的参数，返回成功退出码 0，错误由主入口统一报告。
 */
export async function runHostIpv6Helper(args: string[], overrides: Partial<HostIpv6Dependencies> = {}): Promise<number> {
  if (args.length !== 1 || !["enable", "disable"].includes(args[0]!)) throw new Error("IPv6 辅助程序仅接受 enable 或 disable。");
  const status = await setHostIpv6Enabled(args[0] === "enable", overrides);
  console.log(`本机 IPv6 接口已${status.state === "enabled" ? "开启" : "禁用"}。`);
  return 0;
}

/** 纯脚本与解析器供测试使用；不直接执行任何系统操作。 */
export const hostIpv6Internals = { windowsScript: hostIpv6WindowsScript, windowsStatus: hostIpv6WindowsStatus, linuxStatus: hostIpv6LinuxStatus, policy: hostIpv6Policy, procFile: hostIpv6ProcFile };
