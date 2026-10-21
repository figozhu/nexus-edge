import * as controlFs from "node:fs";
import * as controlPath from "node:path";
import * as controlCrypto from "node:crypto";
import { configFingerprint, errorMessage, getFirewallSettings, validateConfig, type AppConfig, type AppPaths } from "./core.ts";
import { isAdministrator, runElevated } from "./platform.ts";
import { applyFirewallPlan, buildFirewallPlan, firewallScope, inspectFirewallPlan, readFirewallRecord, validateFirewallPlan, writeFirewallRecord, type FirewallOperationOptions, type FirewallOptions, type FirewallPlan, type FirewallRecord, type FirewallResult } from "./firewall.ts";

export interface FirewallInteractiveOptions {
  /** Explicit management actions also work when automatic management is disabled. */
  force?: boolean;
  remove?: boolean;
  expectedConfigHash?: string;
  report?: (result: FirewallResult) => void;
}

/** Every privileged/OS operation is injectable; the test suite never changes a host firewall. */
export interface FirewallControlDependencies {
  platform: NodeJS.Platform;
  isAdministrator: () => boolean;
  inspect: (paths: AppPaths, plan: FirewallPlan, options?: FirewallOperationOptions) => Promise<FirewallResult>;
  apply: (paths: AppPaths, plan: FirewallPlan, options?: FirewallOperationOptions) => Promise<FirewallResult>;
  elevate: (paths: AppPaths, args: string[]) => Promise<void>;
  readRecord: (paths: AppPaths) => FirewallRecord | null;
  writeRecord: (paths: AppPaths, plan: FirewallPlan, result: FirewallResult) => void;
  now: () => number;
}

interface FirewallRequest {
  schema: 1;
  nonce: string;
  scope: string;
  createdAt: number;
  expectedConfigHash: string;
  plan: FirewallPlan;
  options: FirewallOptions;
}
interface FirewallReceipt {
  schema: 1;
  nonce: string;
  scope: string;
  fingerprint: string;
  result: FirewallResult;
}

const CONTROL_IPC_LIMIT = 256 * 1024;
const CONTROL_CONFIG_LIMIT = 8 * 1024 * 1024;
const CONTROL_REQUEST_AGE = 30 * 60 * 1000;
const CONTROL_NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL_HASH = /^[0-9a-f]{64}$/;

function controlDependencies(overrides: Partial<FirewallControlDependencies>): FirewallControlDependencies {
  return { platform: process.platform, isAdministrator, inspect: inspectFirewallPlan, apply: applyFirewallPlan, elevate: runElevated, readRecord: readFirewallRecord, writeRecord: writeFirewallRecord, now: Date.now, ...overrides };
}

function controlObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("防火墙请求或回执格式无效。");
  return value as Record<string, unknown>;
}

function controlExactKeys(value: Record<string, unknown>, keys: string[]): void {
  if (Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key))) throw new Error("防火墙请求或回执包含不支持的字段。");
}

function controlDataDirectory(paths: AppPaths): void {
  const stat = controlFs.lstatSync(paths.data);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("防火墙请求必须位于当前安装已有的数据目录中。");
}

/** Open first, verify identity, then read/write through the descriptor. Never replace a caller-owned receipt as root. */
function controlOpenRegular(file: string, writable = false, limit = CONTROL_IPC_LIMIT): number {
  const before = controlFs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > limit) throw new Error("防火墙文件不是独立的普通文件，或文件过大。");
  const flags = (writable ? controlFs.constants.O_RDWR : controlFs.constants.O_RDONLY) | (controlFs.constants.O_NOFOLLOW ?? 0);
  const fd = controlFs.openSync(file, flags);
  try {
    const opened = controlFs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size > limit || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("防火墙文件在打开时发生变化。");
    return fd;
  } catch (error) { controlFs.closeSync(fd); throw error; }
}

function controlReadJsonFd(fd: number, limit = CONTROL_IPC_LIMIT): unknown {
  const buffer = Buffer.alloc(limit + 1);
  let bytes = 0;
  while (bytes < buffer.length) {
    const count = controlFs.readSync(fd, buffer, bytes, buffer.length - bytes, bytes);
    if (!count) break;
    bytes += count;
  }
  if (bytes > limit) throw new Error("防火墙文件超过大小限制。");
  try { return JSON.parse(buffer.subarray(0, bytes).toString("utf8")); }
  catch { throw new Error("防火墙请求、回执或已保存配置不是有效的 JSON；原文件已保留。"); }
}

function controlReadJson(file: string, limit = CONTROL_IPC_LIMIT): unknown {
  const fd = controlOpenRegular(file, false, limit);
  try { return controlReadJsonFd(fd, limit); }
  finally { controlFs.closeSync(fd); }
}

function controlSavedHash(paths: AppPaths): string {
  controlDataDirectory(paths);
  // Do not call readConfig here: a sudo/UAC child must neither migrate the user's
  // configuration nor replace its ownership/Windows ACLs while opening a port.
  const saved = validateConfig(controlReadJson(paths.config, CONTROL_CONFIG_LIMIT), { allowExpiredCertificate: true });
  return configFingerprint(saved);
}

function controlAssertSaved(paths: AppPaths, expected: string): void {
  if (!CONTROL_HASH.test(expected)) throw new Error("防火墙请求的配置校验值无效。");
  if (controlSavedHash(paths) !== expected) throw new Error("配置已在其他位置修改，请刷新后重新应用。原配置不会被此次操作覆盖；如已执行端口操作，请重新同步防火墙。");
}

function controlSettings(value: unknown): FirewallOptions {
  const raw = controlObject(value);
  controlExactKeys(raw, ["linuxBackend", "firewalldZone"]);
  if (typeof raw.linuxBackend !== "string" || !["auto", "ufw", "firewalld", "iptables"].includes(raw.linuxBackend) || typeof raw.firewalldZone !== "string" || (raw.firewalldZone !== "" && !/^[a-zA-Z0-9_-]{1,32}$/.test(raw.firewalldZone))) throw new Error("防火墙后端或 firewalld 区域名称无效。");
  return { linuxBackend: raw.linuxBackend as FirewallOptions["linuxBackend"], firewalldZone: raw.firewalldZone };
}

function controlResult(value: unknown, plan: FirewallPlan): FirewallResult {
  const raw = controlObject(value);
  controlExactKeys(raw, ["backend", "status", "changed", "detail", "warnings", "rules"]);
  if (typeof raw.backend !== "string" || !["windows", "ufw", "firewalld", "iptables", "none"].includes(raw.backend) || typeof raw.status !== "string" || !["synced", "needs-update", "permission-required", "inactive", "unsupported", "blocked", "error"].includes(raw.status) || typeof raw.changed !== "boolean" || typeof raw.detail !== "string" || raw.detail.length > 4096 || !Array.isArray(raw.warnings) || raw.warnings.length > 64 || raw.warnings.some(item => typeof item !== "string" || item.length > 600) || JSON.stringify(raw.rules) !== JSON.stringify(plan.rules)) throw new Error("防火墙回执内容无效，未确认本机规则状态。");
  return { backend: raw.backend as FirewallResult["backend"], status: raw.status as FirewallResult["status"], changed: raw.changed, detail: raw.detail, warnings: [...raw.warnings] as string[], rules: plan.rules };
}

function controlError(plan: FirewallPlan, platform: NodeJS.Platform, error: unknown): FirewallResult {
  return { backend: platform === "win32" ? "windows" : "none", status: "error", changed: false, detail: `防火墙操作未完成：${errorMessage(error).slice(0, 1800)}`, warnings: plan.warnings, rules: plan.rules };
}

function controlEmpty(plan: FirewallPlan): FirewallResult {
  return { backend: "none", status: "synced", changed: false, detail: "当前没有需要放行的直连监听端口，也没有本工具记录的旧规则。", warnings: plan.warnings, rules: [] };
}

function controlRemember(paths: AppPaths, plan: FirewallPlan, result: FirewallResult, deps: FirewallControlDependencies): FirewallResult {
  try { deps.writeRecord(paths, plan, result); return result; }
  catch {
    return { ...result, warnings: [...new Set([...result.warnings.slice(0, 63), "端口操作结果已返回，但无法保存状态记录；下次使用时会重新检查实际防火墙规则。"])] };
  }
}

function controlRequestFiles(paths: AppPaths, nonce: string): { request: string; result: string } {
  if (!CONTROL_NONCE.test(nonce)) throw new Error("无效的防火墙请求 ID。");
  return { request: controlPath.join(paths.data, `firewall-request-${nonce}.json`), result: controlPath.join(paths.data, `firewall-result-${nonce}.json`) };
}

/** Synchronize only the requested finite port plan; configuration is always written by the ordinary panel afterwards. */
export async function syncFirewallInteractive(paths: AppPaths, candidate: AppConfig, options: FirewallInteractiveOptions = {}, overrides: Partial<FirewallControlDependencies> = {}): Promise<FirewallResult | null> {
  const settings = getFirewallSettings(candidate);
  if (settings.mode === "manual" && !options.force && !options.remove) return null;
  const deps = controlDependencies(overrides);
  const plan = buildFirewallPlan(paths, options.remove ? { ...candidate, nodes: [] } : candidate, deps.platform);
  const firewallOptions = controlSettings({ linuxBackend: settings.linuxBackend, firewalldZone: settings.firewalldZone });
  const expected = options.expectedConfigHash ?? controlSavedHash(paths);
  controlAssertSaved(paths, expected);
  if (!options.force && !options.remove && !plan.rules.length && !deps.readRecord(paths)) {
    const result = controlEmpty(plan);
    options.report?.(result);
    return result;
  }
  let result: FirewallResult;
  if (deps.isAdministrator()) {
    result = controlResult(await deps.apply(paths, plan, { ...firewallOptions, platform: deps.platform }), plan);
    controlAssertSaved(paths, expected);
  } else {
    const inspected = controlResult(await deps.inspect(paths, plan, { ...firewallOptions, platform: deps.platform }), plan);
    controlAssertSaved(paths, expected);
    if (!["needs-update", "permission-required"].includes(inspected.status)) result = inspected;
    else {
      const nonce = controlCrypto.randomUUID(), files = controlRequestFiles(paths, nonce);
      const request: FirewallRequest = { schema: 1, nonce, scope: plan.scope, createdAt: deps.now(), expectedConfigHash: expected, plan, options: firewallOptions };
      const requestText = JSON.stringify(request) + "\n";
      if (Buffer.byteLength(requestText, "utf8") > CONTROL_IPC_LIMIT) throw new Error("防火墙请求过大。");
      controlDataDirectory(paths);
      let createdRequest = false, createdResult = false;
      try {
        controlFs.writeFileSync(files.request, requestText, { flag: "wx", mode: 0o600 }); createdRequest = true;
        // A privileged child writes to this descriptor in place, preserving the
        // original caller's uid/gid and avoiding unreadable root-owned receipts.
        controlFs.writeFileSync(files.result, JSON.stringify({ schema: 1, nonce, scope: plan.scope, pending: true }) + "\n", { flag: "wx", mode: 0o600 }); createdResult = true;
        controlAssertSaved(paths, expected);
        await deps.elevate(paths, ["--firewall-request", nonce]);
        controlAssertSaved(paths, expected);
        const receipt = controlObject(controlReadJson(files.result));
        controlExactKeys(receipt, ["schema", "nonce", "scope", "fingerprint", "result"]);
        if (receipt.schema !== 1 || receipt.nonce !== nonce || receipt.scope !== plan.scope || receipt.fingerprint !== plan.fingerprint) throw new Error("防火墙回执与本次请求不匹配，请重新同步。");
        result = controlResult(receipt.result, plan);
      } finally {
        if (createdRequest) try { controlFs.unlinkSync(files.request); } catch { /* Preserve the operation/UAC error. */ }
        if (createdResult) try { controlFs.unlinkSync(files.result); } catch { /* Preserve the operation/UAC error. */ }
      }
    }
  }
  result = controlRemember(paths, plan, result, deps);
  options.report?.(result);
  return result;
}

/** Internal UAC/sudo entry. It never redirects installations or reads/mutates node secrets beyond validating the saved hash. */
export async function runFirewallRequest(paths: AppPaths, requestId: string, overrides: Partial<FirewallControlDependencies> = {}): Promise<number> {
  const deps = controlDependencies(overrides), files = controlRequestFiles(paths, requestId);
  controlDataDirectory(paths);
  const raw = controlObject(controlReadJson(files.request));
  controlExactKeys(raw, ["schema", "nonce", "scope", "createdAt", "expectedConfigHash", "plan", "options"]);
  const scope = firewallScope(paths, deps.platform);
  if (raw.schema !== 1 || raw.nonce !== requestId || raw.scope !== scope || typeof raw.createdAt !== "number" || !Number.isFinite(raw.createdAt) || raw.createdAt > deps.now() + 60000 || deps.now() - raw.createdAt > CONTROL_REQUEST_AGE || typeof raw.expectedConfigHash !== "string" || !CONTROL_HASH.test(raw.expectedConfigHash)) throw new Error("防火墙请求无效、已过期或不属于当前安装目录。");
  const plan = validateFirewallPlan(raw.plan, scope), settings = controlSettings(raw.options);
  const resultFd = controlOpenRegular(files.result, true);
  try {
    const placeholder = controlObject(controlReadJsonFd(resultFd));
    controlExactKeys(placeholder, ["schema", "nonce", "scope", "pending"]);
    if (placeholder.schema !== 1 || placeholder.nonce !== requestId || placeholder.scope !== scope || placeholder.pending !== true) throw new Error("防火墙请求已执行，或回执文件与请求不匹配。");
    let result: FirewallResult;
    try {
      if (!deps.isAdministrator()) result = { ...controlError(plan, deps.platform, "需要管理员 / root 权限。"), status: "permission-required" };
      else {
        controlAssertSaved(paths, raw.expectedConfigHash);
        result = controlResult(await deps.apply(paths, plan, { ...settings, platform: deps.platform }), plan);
        controlAssertSaved(paths, raw.expectedConfigHash);
      }
    } catch (error) { result = controlError(plan, deps.platform, error); }
    const receipt: FirewallReceipt = { schema: 1, nonce: requestId, scope, fingerprint: plan.fingerprint, result };
    const text = JSON.stringify(receipt) + "\n";
    if (Buffer.byteLength(text, "utf8") > CONTROL_IPC_LIMIT) throw new Error("防火墙回执过大。");
    // Write at an explicit offset: reading the pending receipt must not advance
    // the subsequent output position. No rename/chmod/chown of user files.
    const output = Buffer.from(text, "utf8");
    let written = 0;
    while (written < output.length) {
      const count = controlFs.writeSync(resultFd, output, written, output.length - written, written);
      if (!count) throw new Error("防火墙回执未能完整写入。");
      written += count;
    }
    controlFs.ftruncateSync(resultFd, output.length);
    controlFs.fsyncSync(resultFd);
    return 0;
  } finally { controlFs.closeSync(resultFd); }
}

/** Worker startup may inspect/sync with its current privileges, but it can never display UAC or ask for sudo. */
export async function syncFirewallBackground(paths: AppPaths, config: AppConfig, overrides: Partial<FirewallControlDependencies> = {}): Promise<FirewallResult | null> {
  const settings = getFirewallSettings(config);
  if (settings.mode === "manual") return null;
  const deps = controlDependencies(overrides), plan = buildFirewallPlan(paths, config, deps.platform);
  if (!plan.rules.length && !deps.readRecord(paths)) return controlEmpty(plan);
  let result: FirewallResult;
  try {
    controlAssertSaved(paths, configFingerprint(config));
    const firewallOptions = { ...controlSettings({ linuxBackend: settings.linuxBackend, firewalldZone: settings.firewalldZone }), platform: deps.platform };
    const admin = deps.isAdministrator();
    result = controlResult(await (admin ? deps.apply(paths, plan, firewallOptions) : deps.inspect(paths, plan, firewallOptions)), plan);
    controlAssertSaved(paths, configFingerprint(config));
    if (!admin && result.status === "needs-update") result = { ...result, status: "permission-required", detail: "本机防火墙规则需要更新。后台不会请求提权；请在管理面板中同步端口白名单。" };
  } catch (error) { result = controlError(plan, deps.platform, error); }
  return controlRemember(paths, plan, result, deps);
}
