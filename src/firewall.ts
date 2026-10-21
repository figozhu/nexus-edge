import * as firewallCrypto from "node:crypto";
import * as firewallFs from "node:fs";
import * as firewallPath from "node:path";
import * as firewallNet from "node:net";
import * as firewallCp from "node:child_process";
import { atomicWrite, errorMessage, nodeListenNetworks, type AppConfig, type AppPaths } from "./core.ts";
import { readCoreSelection, coreBinaryPath } from "./network.ts";
import { inspectLinuxFirewall, applyLinuxFirewall } from "./firewall-linux.ts";

/** Only finite, local inbound ports belong in a firewall plan. No node credentials are retained. */
export interface FirewallRule { key: string; protocol: "tcp" | "udp"; port: number; family: 4 | 6; destination: string }
export interface FirewallPlan { scope: string; fingerprint: string; rules: FirewallRule[]; warnings: string[] }
export type FirewallBackend = "windows" | "ufw" | "firewalld" | "iptables" | "none";
export type FirewallStatus = "synced" | "needs-update" | "permission-required" | "inactive" | "unsupported" | "blocked" | "error";
export interface FirewallResult { backend: FirewallBackend; status: FirewallStatus; /** True also when a failed mutation may have made partial changes. */ changed: boolean; detail: string; warnings: string[]; rules: FirewallRule[] }
export interface FirewallOptions { linuxBackend: "auto" | "ufw" | "firewalld" | "iptables"; firewalldZone: string }
export interface FirewallCommandOptions { stdin?: string; timeoutMs?: number; env?: Record<string, string> }
export interface FirewallCommandResult { code: number; stdout: string; stderr: string }
export type FirewallCommandRunner = (executable: string, args: string[], options?: FirewallCommandOptions) => Promise<FirewallCommandResult>;
export interface FirewallOperationOptions extends Partial<FirewallOptions> { platform?: NodeJS.Platform; runner?: FirewallCommandRunner }
export interface FirewallRecord { schema: 1; scope: string; fingerprint: string; updatedAt: string; result: FirewallResult }

const FIREWALL_MAX_RULES = 128;
const FIREWALL_MAX_OUTPUT = 1024 * 1024;
const FIREWALL_STATUSES: readonly FirewallStatus[] = ["synced", "needs-update", "permission-required", "inactive", "unsupported", "blocked", "error"];
const FIREWALL_BACKENDS: readonly FirewallBackend[] = ["windows", "ufw", "firewalld", "iptables", "none"];

function firewallHash(value: unknown): string { return firewallCrypto.createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function firewallText(value: unknown, max = 1200): string { return String(value ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").slice(0, max); }
function firewallWarnings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, 256).map(item => firewallText(item, 600)).filter(Boolean))].slice(0, 64);
}

export function firewallScope(paths: AppPaths, platform: NodeJS.Platform = process.platform): string {
  const root = platform === "win32" ? firewallPath.win32.resolve(paths.root).replace(/\\+$/, "").toLowerCase() : firewallPath.resolve(paths.root);
  return firewallHash(["nexus-edge-firewall-v1", platform, root]).slice(0, 20);
}

/** IPv6 normalization also makes all spellings of mapped IPv4 loopback recognizable. */
function firewallIp(value: string): { family: 4 | 6; address: string; loopback: boolean; wildcard: boolean } {
  if (typeof value !== "string" || value.includes("%") || value.length > 80 || value !== value.trim()) throw new Error("防火墙监听地址必须是有效的 IPv4 或 IPv6 地址。");
  const family = firewallNet.isIP(value);
  if (family === 4) return { family: 4, address: value, loopback: value.startsWith("127."), wildcard: value === "0.0.0.0" };
  if (family !== 6) throw new Error("防火墙监听地址必须是有效的 IPv4 或 IPv6 地址。");
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1).toLowerCase();
  const mapped = canonical.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const high = parseInt(mapped[1]!, 16), low = parseInt(mapped[2]!, 16);
    const address = `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
    return firewallIp(address);
  }
  return { family: 6, address: canonical, loopback: canonical === "::1", wildcard: canonical === "::" };
}

function firewallRule(protocol: "tcp" | "udp", port: number, family: 4 | 6, destination: string): FirewallRule {
  return { key: firewallHash([protocol, port, family, destination]).slice(0, 16), protocol, port, family, destination };
}
function firewallSortRules(rules: FirewallRule[]): FirewallRule[] {
  const compareText = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
  return [...rules].sort((a, b) => compareText(a.protocol, b.protocol) || a.port - b.port || a.family - b.family || compareText(a.destination, b.destination));
}
function firewallMakePlan(scope: string, rules: FirewallRule[], warnings: string[] = []): FirewallPlan {
  const sorted = firewallSortRules([...new Map(rules.map(rule => [rule.key, rule])).values()]);
  if (sorted.length > FIREWALL_MAX_RULES) throw new Error(`单次最多管理 ${FIREWALL_MAX_RULES} 条有限端口规则。`);
  return { scope, fingerprint: firewallHash([scope, sorted]), rules: sorted, warnings: firewallWarnings(warnings) };
}

export function buildFirewallPlan(paths: AppPaths, config: AppConfig, platform: NodeJS.Platform = process.platform): FirewallPlan {
  if (!Array.isArray(config.nodes) || config.nodes.length > 32) throw new Error("防火墙计划最多支持 32 个节点。");
  const rules: FirewallRule[] = [], warnings: string[] = [];
  for (const node of config.nodes) {
    if (!node.enabled || !node.direct) continue;
    const address = firewallIp(node.listen);
    if (address.loopback) continue;
    if (!Number.isInteger(node.port) || node.port < 1 || node.port > 65535) throw new Error("防火墙只接受 1–65535 范围内的本地监听端口。");
    const destinations: { family: 4 | 6; destination: string }[] = address.wildcard
      ? address.family === 6 ? [{ family: 4, destination: "0.0.0.0/0" }, { family: 6, destination: "::/0" }] : [{ family: 4, destination: "0.0.0.0/0" }]
      : [{ family: address.family, destination: address.address }];
    for (const protocol of nodeListenNetworks(node)) for (const destination of destinations) rules.push(firewallRule(protocol, node.port, destination.family, destination.destination));
    if (node.protocol === "socks") warnings.push(`SOCKS5 ${node.port} 只自动放行 TCP 控制端口；UDP 转发使用动态端口，需按实际网络方案另外配置。`);
    if (node.publicPort !== node.port) warnings.push(`已按本地监听端口 ${node.port} 放行；对外端口 ${node.publicPort} 的 NAT/路由器映射需在对应设备上配置。`);
  }
  return firewallMakePlan(firewallScope(paths, platform), rules, warnings);
}

/** Validate untrusted helper IPC again; do not accept arbitrary addresses, ranges or command text. */
export function validateFirewallPlan(input: unknown, expectedScope: string): FirewallPlan {
  if (!input || typeof input !== "object" || Array.isArray(input) || !/^[a-f0-9]{20}$/.test(expectedScope)) throw new Error("防火墙计划格式无效。");
  const plan = input as Record<string, unknown>;
  if (plan.scope !== expectedScope || !Array.isArray(plan.rules) || plan.rules.length > FIREWALL_MAX_RULES || !Array.isArray(plan.warnings) || plan.warnings.length > 64) throw new Error("防火墙计划不属于当前安装目录，或规则数量无效。");
  const rules: FirewallRule[] = [];
  for (const item of plan.rules) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("防火墙规则格式无效。");
    const rule = item as Record<string, unknown>;
    if (!(["tcp", "udp"] as unknown[]).includes(rule.protocol) || !Number.isInteger(rule.port) || Number(rule.port) < 1 || Number(rule.port) > 65535 || ![4, 6].includes(Number(rule.family)) || typeof rule.family !== "number" || typeof rule.destination !== "string") throw new Error("防火墙规则只允许有限的 TCP/UDP 监听端口。");
    if (rule.destination !== (rule.family === 4 ? "0.0.0.0/0" : "::/0")) {
      const ip = firewallIp(rule.destination);
      if (ip.family !== rule.family || ip.loopback || ip.wildcard || ip.address !== rule.destination) throw new Error("防火墙规则的 IP 范围无效。");
    }
    const normalized = firewallRule(rule.protocol as "tcp" | "udp", rule.port as number, rule.family as 4 | 6, rule.destination);
    if (rule.key !== normalized.key) throw new Error("防火墙规则校验失败。");
    rules.push(normalized);
  }
  if (plan.warnings.some(warning => typeof warning !== "string" || warning.length > 600)) throw new Error("防火墙提示格式无效。");
  const normalized = firewallMakePlan(expectedScope, rules, plan.warnings as string[]);
  if (normalized.rules.length !== rules.length || normalized.fingerprint !== plan.fingerprint || JSON.stringify(normalized.rules) !== JSON.stringify(rules)) throw new Error("防火墙计划已损坏或顺序不规范。");
  return normalized;
}

export const runFirewallCommand: FirewallCommandRunner = async (executable, args, options = {}) => {
  if (options.stdin !== undefined && Buffer.byteLength(options.stdin, "utf8") > 256 * 1024) throw new Error("防火墙命令输入超出限制。");
  return await new Promise<FirewallCommandResult>((resolve, reject) => {
    const child = firewallCp.spawn(executable, args, { shell: false, windowsHide: true, stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"], env: { ...process.env, LC_ALL: "C", LANG: "C", ...options.env } });
    let stdout = "", stderr = "", bytes = 0, finished = false;
    const finish = (error?: Error, code = -1) => { if (finished) return; finished = true; clearTimeout(timer); if (error) reject(error); else resolve({ code, stdout, stderr }); };
    const timer = setTimeout(() => { child.kill(); finish(new Error("防火墙命令超时；实际规则可能已部分更新，请重新检查。")); }, Math.max(100, Math.min(options.timeoutMs ?? 30000, 300000)));
    const collect = (chunk: string, stream: "stdout" | "stderr") => {
      bytes += Buffer.byteLength(chunk, "utf8");
      if (bytes > FIREWALL_MAX_OUTPUT) { child.kill(); finish(new Error("防火墙命令输出超出限制，请检查系统防火墙状态。")); return; }
      if (stream === "stdout") stdout += chunk; else stderr += chunk;
    };
    child.stdout?.setEncoding("utf8").on("data", chunk => collect(chunk as string, "stdout"));
    child.stderr?.setEncoding("utf8").on("data", chunk => collect(chunk as string, "stderr"));
    child.on("error", error => finish(error));
    child.on("close", code => finish(undefined, code ?? -1));
    child.stdin?.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "EPIPE") finish(error); });
    if (options.stdin !== undefined) child.stdin?.end(options.stdin, "utf8");
  });
};

function firewallResult(plan: FirewallPlan, backend: FirewallBackend, status: FirewallStatus, detail: string, changed = false, warnings: string[] = []): FirewallResult {
  return { backend, status, changed, detail: firewallText(detail), warnings: firewallWarnings([...warnings, ...plan.warnings]), rules: plan.rules };
}

function firewallOptions(options: FirewallOperationOptions): FirewallOptions {
  const linuxBackend = options.linuxBackend ?? "auto", firewalldZone = options.firewalldZone ?? "";
  if (!["auto", "ufw", "firewalld", "iptables"].includes(linuxBackend) || typeof firewalldZone !== "string" || (firewalldZone !== "" && !/^[a-zA-Z0-9_-]{1,32}$/.test(firewalldZone))) throw new Error("防火墙后端或 firewalld 区域名称无效。");
  return { linuxBackend, firewalldZone };
}

function firewallConfigOptions(config: AppConfig, options: FirewallOperationOptions): FirewallOperationOptions {
  const saved = (config as AppConfig & { firewall?: Partial<FirewallOptions> }).firewall;
  return { linuxBackend: saved?.linuxBackend ?? "auto", firewalldZone: saved?.firewalldZone ?? "", ...options };
}

async function firewallDispatch(paths: AppPaths, input: FirewallPlan, operation: "inspect" | "apply", options: FirewallOperationOptions = {}): Promise<FirewallResult> {
  const platform = options.platform ?? process.platform;
  const plan = validateFirewallPlan(input, firewallScope(paths, platform)), settings = firewallOptions(options);
  const runner = options.runner ?? runFirewallCommand;
  try {
    if (platform === "win32") return await firewallWindows(paths, plan, operation, runner);
    if (platform === "linux") {
      const context = { stateFile: firewallPath.join(paths.data, "firewall-linux-state.json") };
      const result = operation === "apply" ? await applyLinuxFirewall(plan, settings, runner, context) : await inspectLinuxFirewall(plan, settings, runner, context);
      return firewallResult(plan, result.backend, result.status, result.detail, result.changed, result.warnings);
    }
    return firewallResult(plan, "none", "unsupported", platform === "darwin" ? "macOS 的应用防火墙不提供本工具所需的端口白名单接口；请在系统设置中允许对应内核接收入站连接。" : `此操作系统暂不支持自动配置端口白名单：${platform}。`);
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return firewallResult(plan, platform === "win32" ? "windows" : "none", missing ? "unsupported" : "error", missing ? "系统缺少所需的防火墙管理工具。" : `防火墙操作未完成：${firewallText(errorMessage(error))}${operation === "apply" ? "；实际规则可能已部分更新，请重新检查。" : ""}`, !missing && operation === "apply");
  }
}

export function inspectFirewallPlan(paths: AppPaths, plan: FirewallPlan, options: FirewallOperationOptions = {}): Promise<FirewallResult> { return firewallDispatch(paths, plan, "inspect", options); }
export function applyFirewallPlan(paths: AppPaths, plan: FirewallPlan, options: FirewallOperationOptions = {}): Promise<FirewallResult> { return firewallDispatch(paths, plan, "apply", options); }
export function inspectFirewall(paths: AppPaths, config: AppConfig, options: FirewallOperationOptions = {}): Promise<FirewallResult> { return inspectFirewallPlan(paths, buildFirewallPlan(paths, config, options.platform), firewallConfigOptions(config, options)); }
export function applyFirewall(paths: AppPaths, config: AppConfig, options: FirewallOperationOptions = {}): Promise<FirewallResult> { return applyFirewallPlan(paths, buildFirewallPlan(paths, config, options.platform), firewallConfigOptions(config, options)); }
export function removeFirewall(paths: AppPaths, config: AppConfig, options: FirewallOperationOptions = {}): Promise<FirewallResult> { return applyFirewallPlan(paths, firewallMakePlan(firewallScope(paths, options.platform), []), firewallConfigOptions(config, options)); }

export function writeFirewallRecord(paths: AppPaths, plan: FirewallPlan, result: FirewallResult): void {
  const normalized = validateFirewallPlan(plan, plan.scope);
  if (!FIREWALL_STATUSES.includes(result.status) || !FIREWALL_BACKENDS.includes(result.backend) || typeof result.changed !== "boolean") throw new Error("防火墙状态格式无效。");
  const record: FirewallRecord = { schema: 1, scope: normalized.scope, fingerprint: normalized.fingerprint, updatedAt: new Date().toISOString(), result: firewallResult(normalized, result.backend, result.status, result.detail, result.changed, result.warnings) };
  // The parent directory already has the installation's private ACL. In particular,
  // never reset Windows ACLs to an alternate UAC administrator's account here.
  atomicWrite(firewallPath.join(paths.data, "firewall-state.json"), JSON.stringify(record, null, 2) + "\n", 0o644);
}

export function readFirewallRecord(paths: AppPaths): FirewallRecord | null {
  try {
    const file = firewallPath.join(paths.data, "firewall-state.json"), stat = firewallFs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024) return null;
    const raw: unknown = JSON.parse(firewallFs.readFileSync(file, "utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    const record = raw as FirewallRecord;
    if (record.schema !== 1 || record.scope !== firewallScope(paths) || typeof record.updatedAt !== "string" || !Number.isFinite(Date.parse(record.updatedAt)) || !record.result || !FIREWALL_STATUSES.includes(record.result.status) || !FIREWALL_BACKENDS.includes(record.result.backend) || typeof record.result.changed !== "boolean") return null;
    const plan = validateFirewallPlan({ scope: record.scope, fingerprint: record.fingerprint, rules: record.result.rules, warnings: record.result.warnings }, record.scope);
    return { schema: 1, scope: plan.scope, fingerprint: plan.fingerprint, updatedAt: record.updatedAt, result: firewallResult(plan, record.result.backend, record.result.status, record.result.detail, record.result.changed) };
  } catch { return null; }
}

// NetSecurity is queried in both PersistentStore and ActiveStore: a saved rule
// alone is not evidence that Group Policy lets the current connection use it.
// All installation data travels in JSON over stdin, never in executable syntax.
// The tiny encoded loader also keeps 128-rule plans below Windows' argv limit.
const FIREWALL_WINDOWS_SCRIPT = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$script:changed = $false
$script:warnings = @($p.warnings)
$script:matchedPersistent = @()
$script:matchedActive = @()
$script:staleCount = 0
$script:policyChecked = $false
$script:serviceRunning = $false
$script:ownershipConflicts = 0
$mutex = $null
$locked = $false
function Finish([string]$status, [string]$detail) {
  $result = @{schema=1; scope=$p.scope; fingerprint=$p.fingerprint; status=$status; changed=$changed; detail=$detail; warnings=@($warnings); matchedPersistent=@($matchedPersistent); matchedActive=@($matchedActive); staleCount=$staleCount; policyChecked=$policyChecked; serviceRunning=$serviceRunning; ownershipConflicts=$ownershipConflicts}
  [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 8 -Compress))
  exit 0
}
function Is-True($value) { return [string]$value -in @('True', '1') }
function Is-False($value) { return [string]$value -in @('False', '0') }
function Is-Any($value) { return @($value).Count -eq 1 -and [string]@($value)[0] -eq 'Any' }
function Is-AllProfiles($value) {
  $text = [string]$value
  if ($text -in @('Any', '7', '2147483647')) { return $true }
  $names = @($text.Split(',') | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
  return ($names -join ',') -eq 'Domain,Private,Public'
}
function Marker([string]$key) { return ('NexusEdge managed inbound v1; scope=' + $p.scope + '; key=' + $key) }
function Is-Owned($rule) {
  $name = [string]$rule.Name
  if ($name -cnotmatch ('^' + [regex]::Escape($p.prefix) + '[a-f0-9]{16}$')) { return $false }
  $key = $name.Substring($p.prefix.Length)
  return [string]$rule.Group -ceq [string]$p.group -and [string]$rule.Description -ceq (Marker $key)
}
function Candidates($all) {
  return @($all | Where-Object { ([string]$_.Name).StartsWith($p.prefix, [StringComparison]::OrdinalIgnoreCase) -or [string]$_.Group -eq [string]$p.group })
}
function Windows-Address([string]$destination) {
  if ($destination -eq '0.0.0.0/0') { return '0.0.0.0-255.255.255.255' }
  if ($destination -eq '::/0') { return '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' }
  return $destination
}
function Same-Address($values, [string]$destination) {
  if (@($values).Count -ne 1) { return $false }
  $value = [string]@($values)[0]
  if ($value -eq $destination -or $value -eq (Windows-Address $destination)) { return $true }
  if ($destination -in @('0.0.0.0/0', '::/0') -or $value -eq 'Any') { return $false }
  $a = $null; $b = $null
  $parts = $value.Split('/')
  if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$a) -or -not [Net.IPAddress]::TryParse($destination, [ref]$b)) { return $false }
  if ($parts.Count -eq 2 -and $parts[1] -ne $(if ($b.AddressFamily -eq 'InterNetwork') { '32' } else { '128' })) { return $false }
  return $a.Equals($b)
}
function Matches($rule, $desired) {
  if (-not (Is-Owned $rule) -or -not (Is-True $rule.Enabled) -or [string]$rule.Direction -ne 'Inbound' -or [string]$rule.Action -ne 'Allow' -or -not (Is-AllProfiles $rule.Profile) -or [string]$rule.EdgeTraversalPolicy -ne 'Block') { return $false }
  $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
  $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
  $app = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
  $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
  $interface = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
  $interfaceType = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
  $security = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
  if ($port.Count -ne 1 -or $address.Count -ne 1 -or $app.Count -ne 1 -or $service.Count -ne 1 -or $interface.Count -ne 1 -or $interfaceType.Count -ne 1 -or $security.Count -ne 1) { return $false }
  $protocols = if ($desired.protocol -eq 'tcp') { @('TCP', '6') } else { @('UDP', '17') }
  return [string]$port[0].Protocol -in $protocols -and @($port[0].LocalPort).Count -eq 1 -and [string]$port[0].LocalPort -eq [string]$desired.port -and (Is-Any $port[0].RemotePort) -and (Same-Address $address[0].LocalAddress $desired.destination) -and (Is-Any $address[0].RemoteAddress) -and [string]$app[0].Program -eq 'Any' -and [string]$app[0].Package -in @('', 'Any') -and [string]$service[0].Service -eq 'Any' -and (Is-Any $interface[0].InterfaceAlias) -and [string]$interfaceType[0].InterfaceType -eq 'Any' -and [string]$security[0].Authentication -eq 'NotRequired' -and [string]$security[0].Encryption -eq 'NotRequired' -and -not (Is-True $security[0].OverrideBlockRules)
}
function Profile-Applies($profile) {
  if (Is-AllProfiles $profile) { return $true }
  foreach ($name in ([string]$profile).Split(',')) { if ($name.Trim() -in $activeProfiles) { return $true } }
  return $false
}
function Port-Overlaps($values, [int]$port) {
  foreach ($value in @($values)) {
    $text = [string]$value
    if ($text -eq 'Any' -or $text -eq [string]$port) { return $true }
    if ($text -match '^(\\d+)-(\\d+)$' -and $port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { return $true }
  }
  return $false
}
function Bytes-Compare([byte[]]$a, [byte[]]$b) {
  for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -lt $b[$i]) { return -1 }; if ($a[$i] -gt $b[$i]) { return 1 } }
  return 0
}
function Address-Overlaps($values, $desired) {
  foreach ($value in @($values)) {
    $text = [string]$value
    if ($text -eq 'Any') { return $true }
    $pieces = $text -split '[/\\-]'
    $network = $null
    if (-not [Net.IPAddress]::TryParse($pieces[0], [ref]$network)) { return $true }
    $family = if ($network.AddressFamily -eq 'InterNetwork') { 4 } else { 6 }
    if ($family -ne [int]$desired.family) { continue }
    if ($desired.destination -in @('0.0.0.0/0', '::/0')) { return $true }
    $local = [Net.IPAddress]::Parse($desired.destination).GetAddressBytes()
    $start = $network.GetAddressBytes()
    if ($text.Contains('/')) {
      $bits = 0
      if ($pieces.Count -ne 2 -or -not [int]::TryParse($pieces[1], [ref]$bits) -or $bits -lt 0 -or $bits -gt ($local.Length * 8)) { return $true }
      $same = $true
      for ($i = 0; $i -lt $local.Length; $i++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits - $i * 8))
        $mask = if ($take -eq 0) { 0 } else { (255 -shl (8 - $take)) -band 255 }
        if (($local[$i] -band $mask) -ne ($start[$i] -band $mask)) { $same = $false; break }
      }
      if ($same) { return $true }
    } elseif ($text.Contains('-')) {
      $end = $null
      if ($pieces.Count -ne 2 -or -not [Net.IPAddress]::TryParse($pieces[1], [ref]$end) -or $end.AddressFamily -ne $network.AddressFamily) { return $true }
      if ((Bytes-Compare $local $start) -ge 0 -and (Bytes-Compare $local $end.GetAddressBytes()) -le 0) { return $true }
    } elseif ((Bytes-Compare $local $start) -eq 0) { return $true }
  }
  return $false
}
function Blocking-Rules($all) {
  $names = @()
  $reported = 0
  foreach ($rule in @($all | Where-Object { (Is-True $_.Enabled) -and [string]$_.Direction -eq 'Inbound' -and [string]$_.Action -eq 'Block' })) {
    if (-not (Profile-Applies $rule.Profile)) { continue }
    $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    if ([string]$app.Package -notin @('', 'Any') -or [string]$service.Service -notin @('', 'Any')) { continue }
    $program = [Environment]::ExpandEnvironmentVariables([string]$app.Program)
    if ($program -ne 'Any') {
      try { $program = [IO.Path]::GetFullPath($program) } catch { continue }
      if (-not $program.StartsWith($p.binRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($program) -notin @('xray.exe', 'sing-box.exe')) { continue }
      # Cached versions do not determine whether the selected core can connect.
      if (@($p.programs).Count -gt 0 -and $program -notin @($p.programs)) { continue }
    }
    $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    foreach ($desired in @($p.rules)) {
      $protocols = if ($desired.protocol -eq 'tcp') { @('Any', '256', 'TCP', '6') } else { @('Any', '256', 'UDP', '17') }
      if ([string]$port.Protocol -in $protocols -and (Port-Overlaps $port.LocalPort $desired.port) -and (Address-Overlaps $address.LocalAddress $desired)) {
        $display = ([string]$rule.DisplayName).Substring(0, [Math]::Min(120, ([string]$rule.DisplayName).Length))
        $interface = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $security = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
        $coversLocal = (Is-Any $address.LocalAddress) -or (Same-Address $address.LocalAddress $desired.destination) -or ($desired.destination -notin @('0.0.0.0/0', '::/0'))
        $ruleProfiles = @(([string]$rule.Profile).Split(',') | ForEach-Object { $_.Trim() })
        $coversProfiles = (Is-AllProfiles $rule.Profile) -or @($activeProfiles | Where-Object { $_ -notin $ruleProfiles }).Count -eq 0
        $unrestrictedSecurity = [string]$security.Authentication -eq 'NotRequired' -and [string]$security.Encryption -eq 'NotRequired' -and [string]$security.LocalUserAuthorizedList -in @('', 'Any') -and [string]$security.RemoteUserAuthorizedList -in @('', 'Any') -and [string]$security.RemoteMachineAuthorizedList -in @('', 'Any')
        $unrestricted = $program -eq 'Any' -and (Is-Any $port.RemotePort) -and (Is-Any $address.RemoteAddress) -and (Is-Any $interface.InterfaceAlias) -and [string]$interfaceType.InterfaceType -eq 'Any' -and $coversLocal -and $coversProfiles -and $unrestrictedSecurity
        if ($unrestricted) { $names += $display }
        elseif ($reported -lt 8) {
          $script:warnings += ('检测到可能影响 ' + $desired.protocol.ToUpperInvariant() + '/' + $desired.port + ' 的现有阻止规则「' + $display + '」' + $(if ($program -ne 'Any') { '（程序：' + $program + '）' } else { '（仅针对部分来源、地址或网络接口）' }) + '。端口允许规则不会覆盖显式阻止规则；如连接失败，请在 Windows 高级防火墙中核对该规则。')
          $reported++
        }
        break
      }
    }
    if ($names.Count -ge 5) { break }
  }
  return $names
}
function Read-State {
  $script:persistentAll = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  $script:activeAll = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
  $script:owned = @(Candidates $persistentAll)
  $activeCandidates = @(Candidates $activeAll)
  if ($owned.Count -gt 512 -or $activeCandidates.Count -gt 512) { Finish 'blocked' '当前安装目录的防火墙规则数量异常；已停止自动修改。' }
  $script:ownershipConflicts = @(@($owned) + @($activeCandidates) | Where-Object { -not (Is-Owned $_) }).Count
  if ($ownershipConflicts -gt 0) { Finish 'blocked' '存在与本工具同名但所有权标记不同的防火墙规则；请先人工检查，工具不会覆盖它们。' }
  $script:matchedPersistent = @()
  $script:matchedActive = @()
  foreach ($desired in @($p.rules)) {
    $name = $p.prefix + $desired.key
    $saved = @($owned | Where-Object { [string]$_.Name -ceq $name })
    $effective = @($activeCandidates | Where-Object { [string]$_.Name -ceq $name })
    if ($saved.Count -eq 1 -and (Matches $saved[0] $desired)) { $script:matchedPersistent += $desired.key }
    if ($effective.Count -eq 1 -and (Matches $effective[0] $desired)) { $script:matchedActive += $desired.key }
  }
  $savedStale = @($owned | Where-Object { ([string]$_.Name).Substring($p.prefix.Length) -notin @($p.rules.key) }).Count
  $activeStale = @($activeCandidates | Where-Object { ([string]$_.Name).Substring($p.prefix.Length) -notin @($p.rules.key) }).Count
  $script:staleCount = [Math]::Max($savedStale, $activeStale)
}
function Check-Policy {
  if (@($p.rules).Count -eq 0) { $script:policyChecked = $true; return }
  if (-not $serviceRunning) { Finish 'inactive' 'Windows 防火墙服务未运行；工具没有启用服务或改变全局策略，无法确认端口规则生效。' }
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  $connections = @(Get-NetConnectionProfile -ErrorAction Stop)
  $script:activeProfiles = @($connections | ForEach-Object { if ([string]$_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { [string]$_.NetworkCategory } } | Sort-Object -Unique)
  if ($activeProfiles.Count -eq 0) { $script:activeProfiles = @('Domain', 'Private', 'Public'); $script:warnings += '当前没有可识别的活动网络，已检查三个网络配置文件；连接建立后请再次检查。' }
  if (@($activeProfiles | Where-Object { $_ -notin @('Domain', 'Private', 'Public') }).Count -gt 0) { Finish 'error' '无法识别当前 Windows 网络配置文件。' }
  $enabledProfiles = 0
  foreach ($name in $activeProfiles) {
    $profile = @($profiles | Where-Object { [string]$_.Name -eq $name })
    if ($profile.Count -ne 1) { Finish 'error' '无法读取当前网络的有效防火墙策略。' }
    if (Is-False $profile[0].Enabled) { $script:warnings += ('当前 ' + $name + ' 网络的防火墙已关闭，工具没有改变此设置。'); continue }
    $enabledProfiles++
    if (Is-False $profile[0].AllowLocalFirewallRules) { Finish 'blocked' ('当前 ' + $name + ' 网络的组织策略不允许合并本地防火墙规则；需由管理员在组织策略中放行端口。') }
    if (Is-False $profile[0].AllowInboundRules) {
      if ([string]$profile[0].DefaultInboundAction -eq 'Allow') { Finish 'inactive' ('当前 ' + $name + ' 网络忽略入站规则并默认允许入站；本工具的端口规则不参与放行。') }
      Finish 'blocked' ('当前 ' + $name + ' 网络启用了忽略入站允许规则的策略；新增本地规则无法覆盖该策略。')
    }
  }
  if ($enabledProfiles -eq 0) { Finish 'inactive' '当前网络的 Windows 防火墙已关闭；工具没有改变全局设置。' }
  $blocks = @(Blocking-Rules $activeAll)
  if ($blocks.Count -gt 0) { $script:warnings += ('可能冲突的现有阻止规则：' + ($blocks -join '；')); Finish 'blocked' '检测到可能覆盖本地端口的显式阻止规则（例如之前拒绝过内核的联网提示）。阻止规则优先于允许规则，请在 Windows 高级防火墙中检查列出的规则；工具不会删除其他程序或系统创建的规则。' }
  $script:policyChecked = $true
}
try {
  foreach ($command in @('Get-NetFirewallRule', 'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule', 'Get-NetFirewallPortFilter', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter', 'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallSecurityFilter', 'Get-NetFirewallProfile', 'Get-NetConnectionProfile')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { Finish 'unsupported' '此 Windows 环境缺少 NetSecurity 防火墙管理接口。' }
  }
  $firewallService = Get-Service -Name MpsSvc -ErrorAction Stop
  $script:serviceRunning = [string]$firewallService.Status -eq 'Running'
  if (@($p.rules).Count -gt 0 -and -not $serviceRunning) { Finish 'inactive' 'Windows 防火墙服务未运行；工具没有启用服务或改变全局策略，无法确认端口规则生效。' }
  if ($p.operation -eq 'apply') {
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Finish 'permission-required' '需要管理员权限才能添加、修复或清理 Windows 防火墙规则。' }
    $mutex = [Threading.Mutex]::new($false, ('Global\\NexusEdge-Firewall-' + $p.scope))
    try { $locked = $mutex.WaitOne(15000) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { Finish 'error' '另一个进程正在同步此安装目录的防火墙规则，请稍后重试。' }
  }
  Read-State
  Check-Policy
  if ($p.operation -eq 'inspect') {
    if ($matchedPersistent.Count -eq @($p.rules).Count -and $matchedActive.Count -eq @($p.rules).Count -and $staleCount -eq 0) { Finish 'synced' '本工具管理的本地端口允许规则已进入有效策略；请同时查看应用程序阻止规则等提示。公网连接仍取决于云安全组、路由器和运营商网络。' }
    Finish 'needs-update' '本地防火墙规则需要同步（包括新增端口、规则修复或清理已停用端口）。'
  }
  foreach ($desired in @($p.rules)) {
    if ($desired.key -in $matchedPersistent) { continue }
    $name = $p.prefix + $desired.key
    $parameters = @{PolicyStore='PersistentStore'; Name=$name; DisplayName=('NexusEdge ' + $desired.protocol.ToUpperInvariant() + ' ' + $desired.port + ' IPv' + $desired.family); Group=$p.group; Description=(Marker $desired.key); Enabled='True'; Direction='Inbound'; Action='Allow'; Profile='Any'; Protocol=$desired.protocol.ToUpperInvariant(); LocalPort=[string]$desired.port; RemotePort='Any'; LocalAddress=(Windows-Address $desired.destination); RemoteAddress='Any'; Program='Any'; Service='Any'; InterfaceAlias='Any'; InterfaceType='Any'; EdgeTraversalPolicy='Block'; Authentication='NotRequired'; Encryption='NotRequired'; OverrideBlockRules=$false; LooseSourceMapping=$false; LocalOnlyMapping=$false}
    $existing = @($owned | Where-Object { [string]$_.Name -ceq $name })
    if ($existing.Count -gt 1) { Finish 'blocked' '检测到重复的防火墙规则标识，已停止修改。' }
    if ($existing.Count -eq 0) { New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null }
    else {
      $parameters.Remove('DisplayName'); $parameters.Remove('Group')
      $parameters['NewDisplayName'] = 'NexusEdge ' + $desired.protocol.ToUpperInvariant() + ' ' + $desired.port + ' IPv' + $desired.family
      Set-NetFirewallRule @parameters -ErrorAction Stop | Out-Null
    }
    $script:changed = $true
  }
  # Verify every new desired rule in both stores BEFORE deleting any old owned rule.
  Read-State
  Check-Policy
  if ($matchedPersistent.Count -ne @($p.rules).Count -or $matchedActive.Count -ne @($p.rules).Count) { Finish 'blocked' '新端口规则尚未全部进入有效策略，旧规则已保留；请检查组织策略或安全软件。' }
  foreach ($old in @($owned)) {
    $key = ([string]$old.Name).Substring($p.prefix.Length)
    if ($key -notin @($p.rules.key)) {
      # Re-read and re-check ownership immediately before deleting this single name.
      $current = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $old.Name -ErrorAction Stop)
      if ($current.Count -ne 1 -or -not (Is-Owned $current[0])) { Finish 'blocked' '清理前检测到规则所有权变化，剩余旧规则已保留。' }
      Remove-NetFirewallRule -PolicyStore PersistentStore -Name $old.Name -ErrorAction Stop
      $script:changed = $true
    }
  }
  Read-State
  Check-Policy
  if ($matchedPersistent.Count -ne @($p.rules).Count -or $matchedActive.Count -ne @($p.rules).Count -or $staleCount -ne 0) { Finish 'error' '防火墙规则已部分更新，但最终核验未通过；请重新检查。' }
  Finish 'synced' $(if (@($p.rules).Count -eq 0) { '已清理当前安装目录拥有的端口规则。' } else { '本地端口允许规则已进入有效策略，适用于域、专用和公用网络；应用程序阻止规则仍可能拦截连接，请查看提示。公网连接还需云安全组和网络路由允许。' })
} catch {
  $exception = $_.Exception
  $message = [string]$exception.Message
  $denied = $exception -is [UnauthorizedAccessException] -or ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|Unauthorized|PermissionDenied') -or ($exception.HResult -band 65535) -eq 5
  if ($denied) { Finish 'permission-required' '系统拒绝了防火墙操作；需要管理员权限，或由组织管理员调整对应策略。' }
  Finish 'error' ('防火墙操作未完成：' + $message.Substring(0, [Math]::Min(800, $message.Length)))
} finally {
  if ($locked -and $null -ne $mutex) { $mutex.ReleaseMutex() }
  if ($null -ne $mutex) { $mutex.Dispose() }
}
`;

const FIREWALL_WINDOWS_LOADER = String.raw`$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$e=[Console]::In.ReadToEnd()|ConvertFrom-Json;$p=$e.payload;& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($e.script))))`;

function firewallWindowsCommand(paths: AppPaths, plan: FirewallPlan, operation: "inspect" | "apply") {
  const programs: string[] = [], warnings: string[] = [];
  try {
    const selection = readCoreSelection(paths);
    for (const core of [selection.active.xray, selection.active.singBox]) programs.push(firewallPath.win32.resolve(coreBinaryPath(paths, core)));
  } catch { warnings.push("无法读取当前内核版本记录；应用程序级阻止规则只能按安装目录进行提示，请结合实际启动的内核检查。"); }
  const payload = { schema: 1, operation, scope: plan.scope, fingerprint: plan.fingerprint, group: `NexusEdge-${plan.scope}`, prefix: `NexusEdge-${plan.scope}-`, binRoot: firewallPath.win32.resolve(paths.bin).replace(/\\+$/, "") + "\\", rules: plan.rules, programs, warnings };
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  return {
    executable: firewallPath.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(FIREWALL_WINDOWS_LOADER, "utf16le").toString("base64")],
    options: { stdin: JSON.stringify({ script: Buffer.from(FIREWALL_WINDOWS_SCRIPT, "utf8").toString("base64"), payload }), timeoutMs: Math.min(300000, 90000 + plan.rules.length * 1200) },
  };
}

function firewallWindowsResponse(plan: FirewallPlan, response: FirewallCommandResult, operation: "inspect" | "apply" = "inspect"): FirewallResult {
  if (response.code !== 0) return firewallResult(plan, "windows", "error", `Windows 防火墙命令失败（退出码 ${response.code}）：${firewallText(response.stderr || response.stdout, 800)}${operation === "apply" ? "；实际规则可能已部分更新，请重新检查。" : ""}`, operation === "apply");
  try {
    if (Buffer.byteLength(response.stdout, "utf8") > FIREWALL_MAX_OUTPUT) throw new Error("output too large");
    const raw: unknown = JSON.parse(response.stdout.replace(/^\uFEFF/, "").trim());
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid response");
    const value = raw as Record<string, unknown>;
    if (value.schema !== 1 || value.scope !== plan.scope || value.fingerprint !== plan.fingerprint || !FIREWALL_STATUSES.includes(value.status as FirewallStatus) || typeof value.changed !== "boolean" || typeof value.detail !== "string" || !Array.isArray(value.warnings)) throw new Error("mismatched response");
    if (value.status === "synced") {
      const expected = plan.rules.map(rule => rule.key).sort();
      const equalKeys = (keys: unknown) => Array.isArray(keys) && keys.every(key => typeof key === "string") && JSON.stringify([...keys].sort()) === JSON.stringify(expected);
      if (!equalKeys(value.matchedPersistent) || !equalKeys(value.matchedActive) || value.staleCount !== 0 || value.ownershipConflicts !== 0 || value.policyChecked !== true || (plan.rules.length > 0 && value.serviceRunning !== true)) throw new Error("missing active verification");
    }
    return firewallResult(plan, "windows", value.status as FirewallStatus, value.detail, value.changed, firewallWarnings(value.warnings));
  } catch {
    return firewallResult(plan, "windows", "error", "Windows 防火墙没有返回可核验的完整结果；请重新检查实际规则，不能据此认定端口已放行。", operation === "apply");
  }
}

async function firewallWindows(paths: AppPaths, plan: FirewallPlan, operation: "inspect" | "apply", runner: FirewallCommandRunner): Promise<FirewallResult> {
  const command = firewallWindowsCommand(paths, plan, operation);
  return firewallWindowsResponse(plan, await runner(command.executable, command.args, command.options), operation);
}

export const firewallInternals = { ip: firewallIp, makePlan: firewallMakePlan, makeRule: firewallRule, windowsCommand: firewallWindowsCommand, windowsResponse: firewallWindowsResponse, windowsScript: FIREWALL_WINDOWS_SCRIPT, windowsLoader: FIREWALL_WINDOWS_LOADER };
