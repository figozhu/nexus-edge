import * as platformFs from "node:fs";
import * as platformPath from "node:path";
import * as platformCp from "node:child_process";
import * as platformCrypto from "node:crypto";
import { createPaths, atomicWrite, type AppPaths } from "./core";

export interface StartupStatus {
  mode: "none" | "windows-system" | "windows-user" | "linux-system";
  enabled: boolean;
  running: boolean;
  detail: string;
}

const platformUnitName = "nexus-edge.service";
const platformUnitFile = `/etc/systemd/system/${platformUnitName}`;
const platformInstallMarker = "installation.json";
let platformCachedInstallRoot: string | undefined;

function platformError(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function platformDelay(ms: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, ms)); }

interface PlatformCommandResult { code: number; stdout: string; stderr: string }

/** No shell expansion. Elevation deliberately has no timeout: its child may be the interactive panel. */
async function platformCommand(executable: string, args: string[], options: { cwd?: string; inherit?: boolean; timeoutMs?: number } = {}): Promise<PlatformCommandResult> {
  return new Promise((resolve, reject) => {
    const child = platformCp.spawn(executable, args, {
      cwd: options.cwd, shell: false, windowsHide: !options.inherit,
      stdio: options.inherit ? "inherit" : ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "", settled = false;
    const timer = options.timeoutMs ? setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error(`命令超时：${platformPath.basename(executable)}`));
    }, options.timeoutMs) : undefined;
    child.stdout?.on("data", chunk => { stdout = (stdout + chunk.toString("utf8")).slice(-1024 * 1024); });
    child.stderr?.on("data", chunk => { stderr = (stderr + chunk.toString("utf8")).slice(-1024 * 1024); });
    child.once("error", error => { clearTimeout(timer); if (!settled) { settled = true; reject(error); } });
    child.once("close", code => { clearTimeout(timer); if (!settled) { settled = true; resolve({ code: code ?? 1, stdout, stderr }); } });
  });
}

function platformRequireSuccess(result: PlatformCommandResult, context: string): string {
  if (result.code !== 0) throw new Error(`${context}失败（退出码 ${result.code}）：${result.stderr.trim() || result.stdout.trim() || "请查看系统日志。"}`);
  return result.stdout.trim().replace(/^\uFEFF/, "");
}

function platformPowerShellExe(): string {
  return platformPath.win32.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

function platformEncodePowerShell(script: string): string { return Buffer.from(script, "utf16le").toString("base64"); }

/** Paths, Unicode and quotes travel as JSON data, never as interpolated PowerShell code. */
function platformPowerShellPayload(value: unknown): string {
  return `$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(JSON.stringify(value), "utf8").toString("base64")}')) | ConvertFrom-Json;\n`;
}

function platformPowerShellProgram(script: string): string {
  return `$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\ntry {\n${script}\n} catch {\n [Console]::Error.WriteLine($_.Exception.Message)\n exit 1\n}\n`;
}

async function platformPowerShell(script: string, timeoutMs = 60000): Promise<string> {
  const result = await platformCommand(platformPowerShellExe(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", platformEncodePowerShell(platformPowerShellProgram(script))], { timeoutMs });
  return platformRequireSuccess(result, "Windows 系统操作");
}

function platformPowerShellSync(script: string): string {
  const result = platformCp.spawnSync(platformPowerShellExe(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", platformEncodePowerShell(platformPowerShellProgram(script))], { encoding: "utf8", windowsHide: true, timeout: 20000 });
  if (result.error) throw result.error;
  return platformRequireSuccess({ code: result.status ?? 1, stdout: result.stdout || "", stderr: result.stderr || "" }, "Windows 系统查询");
}

export function isAdministrator(): boolean {
  if (process.platform === "linux") return process.getuid?.() === 0;
  if (process.platform !== "win32") return false;
  return platformPowerShellSync("$id = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($id); $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)").toLowerCase() === "true";
}

function platformRequireAdministrator(): void {
  if (!isAdministrator()) throw new Error("此操作需要管理员权限。请通过面板自动 UAC 提权，或在 Linux 通过 sudo 重新打开面板。");
}

export function systemInstallRoot(): string {
  if (platformCachedInstallRoot) return platformCachedInstallRoot;
  if (process.platform === "linux") return platformCachedInstallRoot = "/opt/nexus-edge";
  if (process.platform !== "win32") throw new Error("系统托管仅支持 Windows / Linux。");
  const programData = platformPowerShellSync("[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)");
  if (!platformPath.win32.isAbsolute(programData) || /[\r\n\0]/.test(programData)) throw new Error("无法确定 Windows ProgramData 系统目录。");
  return platformCachedInstallRoot = platformPath.win32.join(programData, "NexusEdge");
}

function platformSystemPaths(): AppPaths {
  const root = systemInstallRoot();
  return createPaths(platformPath.join(root, "nexus-edge.ts"), platformPath.join(root, "runtime", process.platform === "win32" ? "bun.exe" : "bun"));
}

function platformSamePath(a: string, b: string, os = process.platform): boolean {
  return os === "win32" ? platformPath.win32.resolve(a).toLowerCase() === platformPath.win32.resolve(b).toLowerCase() : platformPath.resolve(a) === platformPath.resolve(b);
}

function platformIsSystemPath(paths: AppPaths): boolean {
  const installed = platformSystemPaths();
  return platformSamePath(paths.root, installed.root) && platformSamePath(paths.entry, installed.entry) && platformSamePath(paths.runtime, installed.runtime);
}

/** Location/runtime identity only; elevated operations independently verify the protected ACLs. */
export function isSystemInstallation(paths: AppPaths): boolean { return platformIsSystemPath(paths); }

function platformAssertNoLink(path: string): void {
  const stat = platformFs.lstatSync(path);
  if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new Error(`系统安装不接受链接或特殊文件：${path}`);
}

function platformAssertNoLinkAncestors(path: string): void {
  let current = platformPath.resolve(path);
  for (;;) {
    if (platformFs.existsSync(current)) platformAssertNoLink(current);
    const parent = platformPath.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function platformAssertTree(path: string): void {
  platformAssertNoLink(path);
  if (platformFs.lstatSync(path).isDirectory()) for (const name of platformFs.readdirSync(path)) platformAssertTree(platformPath.join(path, name));
}

function platformLinuxProtected(path: string): boolean {
  try {
    let current = platformPath.resolve(path);
    for (;;) {
      const stat = platformFs.lstatSync(current);
      if (stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) return false;
      const parent = platformPath.dirname(current);
      if (parent === current) return true;
      current = parent;
    }
  } catch { return false; }
}

/** Verify actual DACLs. Merely using ProgramData, or adding an admin ACE, is insufficient. */
const platformWindowsAclVerifier = `
function Assert-ProtectedPath([string]$itemPath) {
  $item = Get-Item -LiteralPath $itemPath -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "系统安装路径不能是重解析点：$itemPath" }
  $acl = Get-Acl -LiteralPath $itemPath
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "系统安装所有者不安全：$itemPath" }
  $writeMask = [int64]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -and (([int64]$rule.FileSystemRights -band $writeMask) -ne 0)) { throw "系统安装允许普通账户修改：$itemPath" }
  }
}
`;

function platformVerifyPublicInstall(paths: AppPaths): boolean {
  try {
    const publicPaths = [paths.root, paths.entry, platformPath.dirname(paths.runtime), paths.runtime, platformPath.join(paths.root, platformInstallMarker)];
    for (const path of publicPaths) platformAssertNoLinkAncestors(path);
    if (process.platform === "linux") return publicPaths.every(platformLinuxProtected);
    if (process.platform === "win32") {
      platformPowerShellSync(platformPowerShellPayload({ paths: publicPaths }) + platformWindowsAclVerifier + "foreach ($itemPath in $p.paths) { Assert-ProtectedPath $itemPath }");
      return true;
    }
  } catch { /* An invalid or unreadable installation is never elevated automatically. */ }
  return false;
}

function platformMakeInstallMarker(paths: AppPaths, active: boolean): { schema: 1; app: "NexusEdge"; entry: string; runtime: string; active: boolean } {
  return { schema: 1, app: "NexusEdge", entry: paths.entry, runtime: paths.runtime, active };
}

function platformInstallMarkerMatches(value: unknown, paths: AppPaths): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const marker = value as Record<string, unknown>;
  return marker.app === "NexusEdge" && marker.schema === 1 && typeof marker.entry === "string" && typeof marker.runtime === "string" && platformSamePath(marker.entry, paths.entry) && platformSamePath(marker.runtime, paths.runtime);
}

function platformInstallMarkerActive(value: unknown, paths: AppPaths): boolean {
  return platformInstallMarkerMatches(value, paths) && (value as Record<string, unknown>).active === true;
}

export function discoverSystemInstallation(): { entry: string; runtime: string } | null {
  try {
    const paths = platformSystemPaths();
    const markerFile = platformPath.join(paths.root, platformInstallMarker);
    if (!platformFs.existsSync(markerFile) || !platformFs.existsSync(paths.entry) || !platformFs.existsSync(paths.runtime)) return null;
    const marker = JSON.parse(platformFs.readFileSync(markerFile, "utf8"));
    if (!platformInstallMarkerActive(marker, paths) || !platformVerifyPublicInstall(paths)) return null;
    return { entry: paths.entry, runtime: paths.runtime };
  } catch { return null; }
}

/** CommandLineToArgvW / CRT quoting, also used for Start-Process's single ArgumentList string. */
function platformQuoteWindowsArg(value: string): string {
  if (/[\0\r\n]/.test(value)) throw new Error("命令参数不能包含 NUL 或换行。");
  return '"' + value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1') + '"';
}

function platformWindowsArguments(args: string[]): string { return args.map(platformQuoteWindowsArg).join(" "); }

function platformAssertStandaloneEntry(paths: AppPaths): void {
  if (platformPath.basename(paths.entry).toLowerCase() !== "nexus-edge.ts") throw new Error("提权和系统托管必须使用已构建的单文件 nexus-edge.ts；请先执行 bun run build，再从项目根目录运行 bun nexus-edge.ts。");
  platformAssertNoLink(paths.entry);
  if (!platformFs.lstatSync(paths.entry).isFile()) throw new Error("入口必须是普通 TypeScript 文件。");
  // A relative module dependency would be lost when the standalone script is copied.
  const source = platformFs.readFileSync(paths.entry, "utf8");
  if (/\b(?:from\s*|import\s*\(\s*|require\s*\(\s*)["']\.{1,2}\//.test(source) || /\bimport\s*["']\.{1,2}\//.test(source)) throw new Error("入口仍包含相对模块依赖，请使用构建后的完整单文件 nexus-edge.ts。");
}

export async function runElevated(paths: AppPaths, args: string[]): Promise<void> {
  platformAssertStandaloneEntry(paths);
  let result: PlatformCommandResult;
  if (isAdministrator()) {
    result = await platformCommand(paths.runtime, [paths.entry, ...args], { cwd: paths.root, inherit: true });
  } else if (process.platform === "win32") {
    const script = platformPowerShellPayload({ runtime: paths.runtime, arguments: platformWindowsArguments([paths.entry, ...args]), root: paths.root }) + `
try {
  $child = Start-Process -FilePath $p.runtime -ArgumentList $p.arguments -WorkingDirectory $p.root -Verb RunAs -PassThru -Wait
  exit $child.ExitCode
} catch {
  if ($_.Exception.NativeErrorCode -eq 1223 -or $_.Exception.InnerException.NativeErrorCode -eq 1223) { [Console]::Error.WriteLine('UAC 已取消，需要管理员权限的操作未执行。'); exit 1223 }
  throw
}`;
    result = await platformCommand(platformPowerShellExe(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", platformEncodePowerShell(platformPowerShellProgram(script))], { cwd: paths.root });
  } else if (process.platform === "linux") {
    result = await platformCommand("sudo", ["--", paths.runtime, paths.entry, ...args], { cwd: paths.root, inherit: true });
  } else throw new Error("自动提权仅支持 Windows / Linux。");
  platformRequireSuccess(result, "提权后的操作");
}

/** Copy only regular files. Configuration and executable inputs may never redirect protected writes. */
function platformCopyRegularTree(source: string, destination: string): void {
  platformAssertNoLink(source);
  if (platformFs.existsSync(destination)) platformAssertNoLink(destination);
  const stat = platformFs.lstatSync(source);
  if (stat.isDirectory()) {
    platformFs.mkdirSync(destination, { recursive: true, mode: 0o700 });
    for (const name of platformFs.readdirSync(source)) platformCopyRegularTree(platformPath.join(source, name), platformPath.join(destination, name));
  } else {
    platformFs.mkdirSync(platformPath.dirname(destination), { recursive: true, mode: 0o700 });
    const temporary = `${destination}.${platformCrypto.randomBytes(8).toString("hex")}.new`;
    try {
      platformFs.copyFileSync(source, temporary, platformFs.constants.COPYFILE_EXCL);
      if (process.platform !== "win32") platformFs.chmodSync(temporary, stat.mode & 0o111 ? 0o700 : 0o600);
      platformFs.renameSync(temporary, destination);
    } finally { if (platformFs.existsSync(temporary)) platformFs.unlinkSync(temporary); }
  }
}

async function platformProtectInstallation(paths: AppPaths, selectedPath = paths.root): Promise<void> {
  platformAssertTree(selectedPath);
  if (process.platform === "linux") {
    const protect = (path: string): void => {
      const stat = platformFs.lstatSync(path);
      platformFs.chownSync(path, 0, 0);
      const privateData = path === paths.data || path.startsWith(paths.data + platformPath.sep);
      platformFs.chmodSync(path, stat.isDirectory() ? (privateData ? 0o700 : 0o755) : privateData ? (stat.mode & 0o111 ? 0o700 : 0o600) : path === paths.runtime ? 0o755 : 0o644);
      if (stat.isDirectory()) for (const name of platformFs.readdirSync(path)) protect(platformPath.join(path, name));
    };
    protect(selectedPath);
    return;
  }
  await platformPowerShell(platformPowerShellPayload({ selectedPath, data: paths.data }) + `
$admin = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
function Protect-Item([string]$itemPath) {
  $item = Get-Item -LiteralPath $itemPath -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "不接受重解析点：$itemPath" }
  $privateData = $itemPath.Equals($p.data, [StringComparison]::OrdinalIgnoreCase) -or $itemPath.StartsWith($p.data + '\\', [StringComparison]::OrdinalIgnoreCase)
  if ($item.PSIsContainer) { $acl = New-Object Security.AccessControl.DirectorySecurity; $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
  else { $acl = New-Object Security.AccessControl.FileSecurity; $inherit = [Security.AccessControl.InheritanceFlags]::None }
  $acl.SetOwner($admin)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($admin, $system)) { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))) }
  if (-not $privateData) { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, [Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))) }
  Set-Acl -LiteralPath $itemPath -AclObject $acl
  if ($item.PSIsContainer) { foreach ($child in Get-ChildItem -LiteralPath $itemPath -Force) { Protect-Item $child.FullName } }
}
Protect-Item $p.selectedPath
`);
}

async function platformAssertProtectedInstallation(paths: AppPaths): Promise<void> {
  if (!platformIsSystemPath(paths) || !platformVerifyPublicInstall(paths)) throw new Error("SYSTEM / root 自启只能从受保护的系统安装目录启用；请使用面板的“安装系统自启”。");
  // Runtime state, SQLite journals and logs are replaced while the worker runs.
  // Validate the directory boundary and all executable/configuration inputs, not transient files.
  const fixedPaths = [paths.root, paths.entry, platformPath.dirname(paths.runtime), paths.runtime, paths.data, paths.config, platformPath.join(paths.root, platformInstallMarker)];
  for (const path of fixedPaths) platformAssertNoLinkAncestors(path);
  platformAssertTree(paths.bin);
  if (process.platform === "linux") {
    const check = (path: string): void => {
      if (!platformLinuxProtected(path)) throw new Error(`系统安装目录存在非 root 所有者或可被普通用户修改：${path}`);
      if (platformFs.lstatSync(path).isDirectory()) for (const name of platformFs.readdirSync(path)) check(platformPath.join(path, name));
    };
    for (const path of fixedPaths) if (!platformLinuxProtected(path)) throw new Error(`系统安装路径允许普通用户修改：${path}`);
    check(paths.bin);
  } else await platformPowerShell(platformPowerShellPayload({ paths: fixedPaths, bin: paths.bin }) + platformWindowsAclVerifier + `
function Check-Tree([string]$itemPath) {
  Assert-ProtectedPath $itemPath
  $item = Get-Item -LiteralPath $itemPath -Force
  if ($item.PSIsContainer) { foreach ($child in Get-ChildItem -LiteralPath $itemPath -Force) { Check-Tree $child.FullName } }
}
foreach ($itemPath in $p.paths) { Assert-ProtectedPath $itemPath }
Check-Tree $p.bin
`);
}

export async function installSystemCopy(paths: AppPaths): Promise<AppPaths> {
  platformRequireAdministrator();
  platformAssertStandaloneEntry(paths);
  const target = platformSystemPaths();
  if (platformIsSystemPath(paths)) { await deactivateSystemInstallation(paths); return target; }
  if (!platformFs.existsSync(paths.config) || !platformFs.existsSync(paths.bin)) throw new Error("请先在便携目录完成配置和内核下载、校验，再安装系统自启。");
  platformAssertTree(paths.bin);
  platformAssertNoLink(paths.config);
  platformAssertNoLinkAncestors(target.root);
  if (process.platform === "linux" && !platformLinuxProtected(platformPath.dirname(target.root))) throw new Error("/opt 必须归 root 所有且不可被普通用户修改。");
  // Never replace a running managed instance or the Bun executable it holds open.
  const existing = await getStartupStatus(target);
  if (existing.running) throw new Error("已有系统托管实例正在运行，请先从系统面板停止它，再更新系统安装。");
  platformFs.mkdirSync(target.root, { recursive: true, mode: 0o755 });
  await platformProtectInstallation(target);
  // Deactivate before the first replacement, including upgrades of a previous installation.
  // Failed preparation must never redirect the source panel to a partial system copy.
  const markerFile = platformPath.join(target.root, platformInstallMarker);
  atomicWrite(markerFile, JSON.stringify(platformMakeInstallMarker(target, false), null, 2) + "\n", 0o644);
  await platformProtectInstallation(target, markerFile);
  platformFs.mkdirSync(platformPath.dirname(target.runtime), { recursive: true, mode: 0o755 });
  platformFs.mkdirSync(target.data, { recursive: true, mode: 0o700 });
  platformFs.mkdirSync(target.bin, { recursive: true, mode: 0o700 });
  // Private directories must have their final ACL before secrets are copied into them.
  await platformProtectInstallation(target);
  platformCopyRegularTree(paths.entry, target.entry);
  platformCopyRegularTree(platformFs.realpathSync(paths.runtime), target.runtime);
  platformCopyRegularTree(paths.bin, target.bin);
  if (platformFs.existsSync(target.config)) platformCopyRegularTree(target.config, target.config + ".bak");
  platformCopyRegularTree(paths.config, target.config);
  await platformProtectInstallation(target);
  await platformAssertProtectedInstallation(target);
  return target;
}

export function installedScriptVersion(entry: string): string | null {
  try {
    const source = platformFs.readFileSync(entry, "utf8");
    return source.match(/\bexport\s+const\s+APP_VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']/)?.[1] ?? null;
  } catch { return null; }
}

/** Update only the protected script; keep the installed runtime, config and
 * active process untouched. Existing processes have already loaded their code.
 * The new panel migrates config and applies it through an explicit restart. */
export async function updateSystemEntry(source: AppPaths): Promise<{ target: AppPaths; backup: string; configBackup?: string }> {
  platformRequireAdministrator();
  platformAssertStandaloneEntry(source);
  const discovered = discoverSystemInstallation();
  if (!discovered) throw new Error("没有可升级的已激活系统副本。");
  const target = createPaths(discovered.entry, discovered.runtime);
  if (platformPath.resolve(source.entry) === platformPath.resolve(target.entry)) throw new Error("请从下载的新脚本发起升级。");
  await platformAssertProtectedInstallation(target);
  const oldSource = platformFs.readFileSync(target.entry, "utf8");
  const newSource = platformFs.readFileSync(source.entry, "utf8");
  const backupDirectory = platformPath.join(target.data, "updates");
  platformFs.mkdirSync(backupDirectory, { recursive: true, mode: 0o700 });
  await platformProtectInstallation(target, backupDirectory);
  const backup = platformPath.join(backupDirectory, `nexus-edge-${Date.now()}-${platformCrypto.randomBytes(4).toString("hex")}.ts`);
  atomicWrite(backup, oldSource);
  await platformProtectInstallation(target, backup);
  const configBackup = platformFs.existsSync(target.config) ? backup.replace(/\.ts$/, ".config.json") : undefined;
  if (configBackup) {
    platformAssertNoLink(target.config);
    atomicWrite(configBackup, platformFs.readFileSync(target.config));
    await platformProtectInstallation(target, configBackup);
  }
  try {
    atomicWrite(target.entry, newSource, 0o644);
    await platformProtectInstallation(target, target.entry);
    await platformAssertProtectedInstallation(target);
  } catch (error) {
    try { atomicWrite(target.entry, oldSource, 0o644); await platformProtectInstallation(target, target.entry); }
    catch (recoveryError) { throw new Error(`更新失败：${platformError(error)}；脚本恢复也失败：${platformError(recoveryError)}。原脚本备份：${backup}`); }
    throw new Error(`更新失败，原脚本已恢复：${platformError(error)}`);
  }
  return { target, backup, ...(configBackup ? { configBackup } : {}) };
}

async function platformSetInstallationActive(paths: AppPaths, active: boolean): Promise<void> {
  platformRequireAdministrator();
  await platformAssertProtectedInstallation(paths);
  const markerFile = platformPath.join(paths.root, platformInstallMarker);
  const marker: unknown = JSON.parse(platformFs.readFileSync(markerFile, "utf8"));
  if (!platformInstallMarkerMatches(marker, paths)) throw new Error("系统安装标记与固定安装路径不匹配，未更改启用状态。");
  atomicWrite(markerFile, JSON.stringify(platformMakeInstallMarker(paths, active), null, 2) + "\n", 0o644);
  // The worker can already be running here: touch only the public marker, not live runtime files.
  await platformProtectInstallation(paths, markerFile);
  if (!platformVerifyPublicInstall(paths)) throw new Error("系统安装标记写入后的权限验证失败。");
}

/** Route subsequent panel launches to the system copy only after the caller confirms a successful handoff. */
export async function activateSystemInstallation(paths: AppPaths): Promise<void> { await platformSetInstallationActive(paths, true); }
export async function deactivateSystemInstallation(paths: AppPaths): Promise<void> { await platformSetInstallationActive(paths, false); }

interface PlatformTaskSpec { name: string; marker: string; mode: "system" | "user"; runtime: string; arguments: string; root: string }
interface PlatformTaskSnapshot {
  name: string; description: string; state: string; taskEnabled: boolean;
  actions: { execute: string; arguments: string; workingDirectory: string }[];
  principal: { userId: string; logonType: string; runLevel: string };
  triggers: { type: string; enabled: boolean; userId?: string }[];
  executionTimeLimit: string; allowBattery: boolean; keepOnBattery: boolean; multipleInstances: string;
  lastResult?: number; currentSid?: string; currentIsAdmin?: boolean;
}

function platformTaskSpec(paths: AppPaths, mode: "system" | "user"): PlatformTaskSpec {
  const identity = platformCrypto.createHash("sha256").update(platformPath.win32.resolve(paths.root).toLowerCase()).digest("hex").slice(0, 16);
  return { name: mode === "system" ? "NexusEdge-System" : `NexusEdge-User-${identity}`, marker: `NexusEdge/v1/${identity}/${mode}`, mode, runtime: paths.runtime, arguments: platformWindowsArguments([paths.entry, "--worker"]), root: paths.root };
}

const platformGetTaskCode = `$t = Get-ScheduledTask -TaskPath '\\' | Where-Object { $_.TaskName -ieq $p.name } | Select-Object -First 1\n`;

const platformAssertTaskOwnerCode = `
if ($t) {
  if ($t.Description -ne $p.marker -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -ine $p.runtime -or $t.Actions[0].Arguments -cne $p.arguments -or $t.Actions[0].WorkingDirectory -ine $p.root) { throw "同名计划任务与此 NexusEdge 安装不匹配，已保留原任务。" }
}
`;

function platformBuildTaskScript(spec: PlatformTaskSpec): string {
  return platformPowerShellPayload(spec) + platformGetTaskCode + platformAssertTaskOwnerCode + `
$action = New-ScheduledTaskAction -Execute $p.runtime -Argument $p.arguments -WorkingDirectory $p.root
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
${spec.mode === "system" ? `$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest` : `$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($t) {
  # Rollback can run under a different UAC administrator. Preserve the original login identity.
  if ([string]$t.Principal.LogonType -notin @('Interactive', '3') -or [string]$t.Principal.RunLevel -notin @('Limited', '0') -or -not $t.Principal.UserId) { throw '已有用户任务的登录身份不匹配，已保留原任务。' }
  $principal = $t.Principal
  $sid = $principal.UserId
} else {
  $principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
}
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid`}
$definition = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $p.marker
Register-ScheduledTask -TaskName $p.name -TaskPath '\\' -InputObject $definition -Force | Out-Null
`;
}

async function platformReadTask(spec: PlatformTaskSpec): Promise<PlatformTaskSnapshot | null> {
  const json = await platformPowerShell(platformPowerShellPayload(spec) + platformGetTaskCode + `
function Get-Sid([string]$id) {
  if ($id -match '^S-1-') { return $id }
  try { return (New-Object Security.Principal.NTAccount($id)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $id }
}
if (-not $t) { 'null' } else {
  $info = Get-ScheduledTaskInfo -TaskName $p.name -TaskPath '\\'
  [ordered]@{
    name = $t.TaskName; description = $t.Description; state = [string]$t.State; taskEnabled = [bool]$t.Settings.Enabled
    actions = @($t.Actions | ForEach-Object { @{ execute = $_.Execute; arguments = $_.Arguments; workingDirectory = $_.WorkingDirectory } })
    principal = @{ userId = (Get-Sid $t.Principal.UserId); logonType = [string]$t.Principal.LogonType; runLevel = [string]$t.Principal.RunLevel }
    triggers = @($t.Triggers | ForEach-Object { @{ type = $_.CimClass.CimClassName; enabled = [bool]$_.Enabled; userId = (Get-Sid $_.UserId) } })
    executionTimeLimit = [string]$t.Settings.ExecutionTimeLimit
    allowBattery = -not $t.Settings.DisallowStartIfOnBatteries; keepOnBattery = -not $t.Settings.StopIfGoingOnBatteries
    multipleInstances = [string]$t.Settings.MultipleInstances; lastResult = $info.LastTaskResult
    currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    currentIsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } | ConvertTo-Json -Depth 8 -Compress
}
`);
  return JSON.parse(json);
}

function platformTaskOwnership(spec: PlatformTaskSpec, task: PlatformTaskSnapshot): boolean {
  const action = task.actions[0];
  return !!action && task.name.toLowerCase() === spec.name.toLowerCase() && task.description === spec.marker && task.actions.length === 1 && platformSamePath(action.execute, spec.runtime, "win32") && action.arguments === spec.arguments && platformSamePath(action.workingDirectory, spec.root, "win32");
}

function platformTaskProblems(spec: PlatformTaskSpec, task: PlatformTaskSnapshot): string[] {
  const problems: string[] = [];
  if (!platformTaskOwnership(spec, task)) return ["任务归属或实际执行路径不匹配"];
  const system = spec.mode === "system";
  // UAC may use another administrator's credentials; that administrator can stop the original user's owned task.
  const userMatches = task.principal.userId === task.currentSid || (task.currentIsAdmin && /^S-1-/.test(task.principal.userId) && !/^S-1-5-(?:18|19|20|32)(?:-|$)/.test(task.principal.userId));
  if (system ? task.principal.userId !== "S-1-5-18" : !userMatches) problems.push("任务运行账户不匹配");
  if (!(system ? ["ServiceAccount", "5"] : ["Interactive", "3"]).includes(task.principal.logonType)) problems.push("任务登录类型不匹配");
  if (!(system ? ["Highest", "1"] : ["Limited", "0"]).includes(task.principal.runLevel)) problems.push("任务权限级别不匹配");
  if (!/^P(?=.*0)[0DT HMS.]*$/.test(task.executionTimeLimit) && task.executionTimeLimit !== "00:00:00") problems.push("任务执行时间未设置为无限");
  if (!task.allowBattery || !task.keepOnBattery) problems.push("任务电池电源策略不匹配");
  if (!["IgnoreNew", "2"].includes(task.multipleInstances)) problems.push("任务单实例策略不是 IgnoreNew");
  const triggerType = system ? "MSFT_TaskBootTrigger" : "MSFT_TaskLogonTrigger";
  if (task.triggers.some(trigger => trigger.type !== triggerType || (!system && trigger.userId !== task.principal.userId))) problems.push(system ? "触发器不是开机启动" : "触发器不是当前用户登录");
  return problems;
}

function platformAssessTask(spec: PlatformTaskSpec, task: PlatformTaskSnapshot | null): StartupStatus {
  if (!task) return { mode: "none", enabled: false, running: false, detail: "尚未注册计划任务。" };
  const problems = platformTaskProblems(spec, task);
  const running = ["Running", "4"].includes(task.state);
  const enabled = task.taskEnabled && task.triggers.some(trigger => trigger.enabled) && problems.length === 0;
  return {
    mode: spec.mode === "system" ? "windows-system" : "windows-user", enabled, running: platformTaskOwnership(spec, task) && running,
    detail: problems.length ? `计划任务配置异常：${problems.join("；")}。` : `${spec.mode === "system" ? "SYSTEM 开机启动，无需登录" : "当前用户登录后启动"}；${enabled ? "自启已启用" : "自启已关闭，可手动启动"}；${running ? "运行中" : `未运行（上次结果 ${task.lastResult ?? "未知"}）`}。`,
  };
}

function platformQuoteSystemd(value: string, environmentExpansion: boolean): string {
  if (/[\x00-\x1f\x7f]/.test(value)) throw new Error("systemd 路径不能包含控制字符。");
  let result = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/%/g, "%%");
  if (environmentExpansion) result = result.replace(/\$/g, "$$$$");
  return `"${result}"`;
}

function platformSystemdWorkingDirectory(value: string): string {
  if (!platformPath.posix.isAbsolute(value) || /[\x00-\x1f\x7f]/.test(value)) throw new Error("systemd 工作目录必须是不含控制字符的绝对路径。");
  // WorkingDirectory consumes one whole path, not an argv word; outer quotes become literal characters.
  return value.replace(/%/g, "%%");
}

function platformSystemdUnit(paths: AppPaths): string {
  return `# NexusEdge managed unit v1
[Unit]
Description=NexusEdge tunnel supervisor
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=${platformSystemdWorkingDirectory(paths.root)}
ExecStart=${[paths.runtime, paths.entry, "--worker"].map(value => platformQuoteSystemd(value, true)).join(" ")}
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStopSec=20
UMask=0077

[Install]
WantedBy=multi-user.target
`;
}

function platformSystemdAvailable(): boolean { return platformFs.existsSync("/run/systemd/system"); }

async function platformSystemctl(args: string[]): Promise<string> {
  if (!platformSystemdAvailable()) throw new Error("当前 Linux 没有运行 systemd，无法安装系统托管。请在支持 systemd 的主机中使用此功能。");
  return platformRequireSuccess(await platformCommand("systemctl", args, { timeoutMs: 45000 }), "systemd 操作");
}

function platformAssertUnitOwner(paths: AppPaths): void {
  if (!platformFs.existsSync(platformUnitFile)) return;
  platformAssertNoLink(platformUnitFile);
  if (!platformLinuxProtected(platformUnitFile)) throw new Error("systemd unit 或其父目录不是受保护的 root 所有文件。");
  const text = platformFs.readFileSync(platformUnitFile, "utf8");
  const expected = platformSystemdUnit(paths);
  if (text !== expected) throw new Error("同名 systemd unit 与此 NexusEdge 安装的完整定义不匹配，已保留原文件。请检查是否手工修改了 unit。");
}

async function platformLinuxStatus(paths: AppPaths): Promise<StartupStatus> {
  if (!platformSystemdAvailable()) return { mode: "none", enabled: false, running: false, detail: "当前环境未运行 systemd。" };
  if (!platformIsSystemPath(paths)) return { mode: "none", enabled: false, running: false, detail: "便携目录尚未安装系统托管。" };
  if (!platformFs.existsSync(platformUnitFile)) return { mode: "none", enabled: false, running: false, detail: "尚未安装 systemd unit。" };
  platformAssertUnitOwner(paths);
  const text = await platformSystemctl(["show", platformUnitName, "--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload", "--no-pager"]);
  const state = Object.fromEntries(text.split(/\r?\n/).map(line => { const at = line.indexOf("="); return [line.slice(0, at), line.slice(at + 1)]; }));
  if (state.FragmentPath !== platformUnitFile || state.DropInPaths) throw new Error("systemd 实际加载了其他 unit 路径或额外覆盖配置，请检查后再管理。");
  if (state.NeedDaemonReload === "yes") throw new Error("systemd 的已加载定义与磁盘不一致，请重新启用系统自启以刷新定义。");
  return {
    mode: "linux-system", enabled: state.LoadState === "loaded" && ["enabled", "enabled-runtime"].includes(state.UnitFileState ?? ""), running: ["active", "activating", "reloading"].includes(state.ActiveState ?? ""),
    detail: `systemd：${state.ActiveState || "unknown"}/${state.SubState || "unknown"}；自启 ${state.UnitFileState || "unknown"}。`,
  };
}

export async function getStartupStatus(paths: AppPaths): Promise<StartupStatus> {
  if (process.platform === "win32") {
    const spec = platformTaskSpec(paths, platformIsSystemPath(paths) ? "system" : "user");
    return platformAssessTask(spec, await platformReadTask(spec));
  }
  if (process.platform === "linux") return platformLinuxStatus(paths);
  return { mode: "none", enabled: false, running: false, detail: "此系统不支持托管。" };
}

export async function enableStartup(paths: AppPaths, mode: "system" | "user"): Promise<void> {
  platformAssertStandaloneEntry(paths);
  if (mode === "system") { platformRequireAdministrator(); await platformAssertProtectedInstallation(paths); }
  if (process.platform === "win32") {
    if (mode === "user" && platformIsSystemPath(paths)) throw new Error("系统安装应使用 SYSTEM 开机启动；用户登录模式请从便携目录启用。");
    const spec = platformTaskSpec(paths, mode);
    await platformPowerShell(platformBuildTaskScript(spec));
    const status = platformAssessTask(spec, await platformReadTask(spec));
    if (!status.enabled) throw new Error(`计划任务注册后验证失败：${status.detail}`);
  } else if (process.platform === "linux") {
    if (mode !== "system") throw new Error("Linux 当前仅支持 systemd 系统自启；请使用系统安装模式。");
    if (!platformSystemdAvailable()) throw new Error("当前 Linux 未运行 systemd，未写入任何 unit。");
    platformAssertUnitOwner(paths);
    atomicWrite(platformUnitFile, platformSystemdUnit(paths), 0o644);
    platformFs.chownSync(platformUnitFile, 0, 0);
    await platformSystemctl(["daemon-reload"]);
    await platformSystemctl(["enable", platformUnitName]);
    const status = await platformLinuxStatus(paths);
    if (!status.enabled) throw new Error(`systemd 自启验证失败：${status.detail}`);
  } else throw new Error("自启仅支持 Windows / Linux。");
}

async function platformOwnedWindowsTask(paths: AppPaths): Promise<PlatformTaskSpec> {
  const system = platformIsSystemPath(paths);
  if (system) { platformRequireAdministrator(); await platformAssertProtectedInstallation(paths); }
  const spec = platformTaskSpec(paths, system ? "system" : "user");
  const task = await platformReadTask(spec);
  if (!task) throw new Error("尚未注册计划任务，请先启用一次自启。");
  const problems = platformTaskProblems(spec, task);
  if (problems.length) throw new Error(`无法管理计划任务：${problems.join("；")}。`);
  return spec;
}

function platformRequireLinuxManager(paths: AppPaths): void {
  platformRequireAdministrator();
  if (!platformIsSystemPath(paths)) throw new Error("便携目录没有 systemd 管理定义。");
  if (!platformFs.existsSync(platformUnitFile)) throw new Error("尚未安装 systemd unit。");
  platformAssertUnitOwner(paths);
}

/** Disable automatic triggers; preserve the manager definition for future manual start/stop. */
export async function disableStartup(paths: AppPaths): Promise<void> {
  if (process.platform === "win32") {
    const spec = await platformOwnedWindowsTask(paths);
    await platformPowerShell(platformPowerShellPayload(spec) + platformGetTaskCode + platformAssertTaskOwnerCode + `
if (-not $t) { throw '计划任务已不存在。' }
$t.Triggers = @()
$t.Settings.Enabled = $true
Set-ScheduledTask -InputObject $t | Out-Null
`);
    if ((await getStartupStatus(paths)).enabled) throw new Error("计划任务自动触发器关闭验证失败。");
  } else if (process.platform === "linux") {
    platformRequireLinuxManager(paths);
    await platformSystemctl(["disable", platformUnitName]);
    if ((await platformLinuxStatus(paths)).enabled) throw new Error("systemd 自启关闭验证失败。");
  } else throw new Error("此系统不支持自启管理。");
}

export async function startManaged(paths: AppPaths): Promise<void> {
  if (process.platform === "win32") {
    const spec = await platformOwnedWindowsTask(paths);
    await platformPowerShell(platformPowerShellPayload(spec) + platformGetTaskCode + platformAssertTaskOwnerCode + `
if (-not $t) { throw '计划任务已不存在。' }
Enable-ScheduledTask -TaskName $p.name -TaskPath '\\' | Out-Null
Start-ScheduledTask -TaskName $p.name -TaskPath '\\'
`);
  } else if (process.platform === "linux") {
    platformRequireLinuxManager(paths);
    await platformAssertProtectedInstallation(paths);
    // Reject altered drop-ins before asking systemd to execute anything.
    await platformLinuxStatus(paths);
    await platformSystemctl(["start", platformUnitName]);
  } else throw new Error("此系统不支持托管启动。");
}

export async function stopManaged(paths: AppPaths): Promise<void> {
  if (process.platform === "win32") {
    const spec = await platformOwnedWindowsTask(paths);
    // Stop-ScheduledTask terminates immediately. Give our authenticated local IPC time to stop both cores.
    platformRequireSuccess(await platformCommand(paths.runtime, [paths.entry, "--stop-worker"], { cwd: paths.root, timeoutMs: 25000 }), "后台正常停止");
    const deadline = Date.now() + 15000;
    do {
      const task = await platformReadTask(spec);
      if (!task || !["Running", "Queued", "4", "2"].includes(task.state)) return;
      await platformDelay(250);
    } while (Date.now() < deadline);
    throw new Error("后台停止请求已发送，但计划任务仍未退出。已保留进程和日志，请查看状态；不会依据旧 PID 强制终止进程。");
  } else if (process.platform === "linux") {
    platformRequireLinuxManager(paths);
    await platformSystemctl(["stop", platformUnitName]);
  } else throw new Error("此系统不支持托管停止。");
}

export async function restartManaged(paths: AppPaths): Promise<void> { await stopManaged(paths); await startManaged(paths); }

/** Pure builders and validation helpers for tests; tests never register tasks/services or elevate. */
export const platformInternals = {
  quoteWindowsArg: platformQuoteWindowsArg, windowsArguments: platformWindowsArguments,
  encodePowerShell: platformEncodePowerShell, powerShellPayload: platformPowerShellPayload,
  taskSpec: platformTaskSpec, buildTaskScript: platformBuildTaskScript, assessTask: platformAssessTask,
  systemdUnit: platformSystemdUnit, quoteSystemd: platformQuoteSystemd,
  systemdWorkingDirectory: platformSystemdWorkingDirectory,
  copyRegularTree: platformCopyRegularTree, linuxProtected: platformLinuxProtected,
  makeInstallMarker: platformMakeInstallMarker, installMarkerActive: platformInstallMarkerActive,
};
