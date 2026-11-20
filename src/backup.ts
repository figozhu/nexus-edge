import * as backupFs from "node:fs";
import * as backupPath from "node:path";
import * as backupCrypto from "node:crypto";
import * as backupNet from "node:net";
import { APP_VERSION, type AppConfig, type AppPaths, validateConfig, ensureDataDir } from "./core.ts";

// Fixed parameters are part of format v1; untrusted files cannot choose KDF cost.
const backupFormat = "nexus-edge-backup";
const backupSuite = "scrypt-32768-8-1/aes-256-gcm";
const backupLimit = 16 * 1024 * 1024;
export const BACKUP_FILE_LIMIT = 24 * 1024 * 1024;
const backupAad = Buffer.from(`${backupFormat}:1:${backupSuite}`);

export interface ConfigBackup { appVersion: string; createdAt: string; config: AppConfig }
export interface ConfigImportPreview {
  config: AppConfig;
  appVersion: string;
  createdAt: string;
  /** Exact on-disk bytes fingerprint, including absent/corrupt configuration. */
  expected: string | null;
}

export function validateBackupPassword(password: string): string {
  if (password.length < 12 || Buffer.byteLength(password) > 1024) throw new Error("备份密码须至少 12 个字符，且不超过 1024 UTF-8 字节。请使用独立的长密码。");
  return password;
}

function backupKey(password: string, salt: Buffer): Buffer {
  validateBackupPassword(password);
  return backupCrypto.scryptSync(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

/** Reject unknown fields rather than silently dropping data from newer schemas. */
function backupShape(value: unknown, allowed: string[]): Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw new Error("备份包含未知字段或无效结构；请使用兼容版本。");
  return value as Record<string, any>;
}

function backupValidateConfig(value: unknown): AppConfig {
  const config = backupShape(value, ["schema", "coreIpv6", "nodes", "warp", "webhook", "firewall"]);
  backupShape(config.webhook, ["kind", "url"]);
  if (config.warp !== undefined) backupShape(config.warp, ["privateKey", "addresses", "peerPublicKey", "endpointHost", "endpointPort", "reserved"]);
  if (config.firewall !== undefined) backupShape(config.firewall, ["mode", "linuxBackend", "firewalldZone"]);
  if (!Array.isArray(config.nodes)) throw new Error("备份节点列表无效。");
  for (const node of config.nodes) {
    backupShape(node, ["id", "name", "enabled", "protocol", "listen", "port", "address", "publicPort", "direct", "egress", "uuid", "username", "password", "method", "transport", "tls", "flow", "vlessEncryption", "vlessDecryption", "vmessSecurity", "hy2", "tuic", "tunnel"]);
    backupShape(node.transport, ["type", "path", "host", "serviceName", "mode"]);
    backupShape(node.tls, ["mode", "serverName", "alpn", "certificatePem", "keyPem", "insecure", "reality"]);
    backupShape(node.tls.reality, ["privateKey", "publicKey", "shortId", "handshakeServer", "handshakePort"]);
    backupShape(node.hy2, ["obfsPassword", "upMbps", "downMbps"]);
    backupShape(node.tuic, ["congestionControl", "zeroRttHandshake"]);
    backupShape(node.tunnel, ["mode", "token", "domain", "connectAddress", "protocol"]);
  }
  try { return validateConfig(value, { allowExpiredCertificate: true }); }
  // Validation messages can contain values from the file. Never echo backup data.
  catch { throw new Error("备份配置校验失败；原配置未改变。请检查源版本、节点、证书及端口冲突。"); }
}

/** Encrypt only the portable config model; no runtime files, paths or executables. */
export function encodeConfigBackup(config: AppConfig, password: string): string {
  const payload = Buffer.from(JSON.stringify({ appVersion: APP_VERSION, createdAt: new Date().toISOString(), config: backupValidateConfig(config) }));
  if (payload.length > backupLimit) throw new Error("配置过大，无法导出备份。");
  const salt = backupCrypto.randomBytes(16), iv = backupCrypto.randomBytes(12);
  const key = backupKey(password, salt);
  try {
    const cipher = backupCrypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(backupAad);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
    return JSON.stringify({ format: backupFormat, version: 1, suite: backupSuite, salt: salt.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: encrypted.toString("base64") }) + "\n";
  } finally { key.fill(0); payload.fill(0); }
}

function backupBase64(value: unknown, length?: number): Buffer {
  if (typeof value !== "string" || !value.length) throw new Error("备份编码无效。");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (length !== undefined && bytes.length !== length)) throw new Error("备份编码无效。");
  return bytes;
}

/** Authenticate before JSON parsing; all metadata containing user data is encrypted. */
export function decodeConfigBackup(text: string, password: string): ConfigBackup {
  if (Buffer.byteLength(text) > BACKUP_FILE_LIMIT) throw new Error("备份文件超过 24 MiB 限制。");
  let envelope: Record<string, any>;
  try { envelope = backupShape(JSON.parse(text), ["format", "version", "suite", "salt", "iv", "tag", "data"]); }
  catch { throw new Error("备份文件损坏或格式无效。"); }
  if (envelope.format !== backupFormat || envelope.version !== 1 || envelope.suite !== backupSuite) throw new Error("不支持此备份版本或加密格式，请使用兼容的 NexusEdge 版本。");
  const salt = backupBase64(envelope.salt, 16), iv = backupBase64(envelope.iv, 12), tag = backupBase64(envelope.tag, 16), encrypted = backupBase64(envelope.data);
  if (encrypted.length > backupLimit) throw new Error("备份内容超过大小限制。");
  const key = backupKey(password, salt);
  let plain: Buffer;
  try {
    const decipher = backupCrypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(backupAad); decipher.setAuthTag(tag);
    plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch { throw new Error("密码错误或备份已损坏；原配置未改变。"); }
  finally { key.fill(0); }
  let payload: Record<string, any>;
  try { payload = backupShape(JSON.parse(plain.toString("utf8")), ["appVersion", "createdAt", "config"]); }
  catch { throw new Error("备份内容损坏或版本不兼容。"); }
  finally { plain.fill(0); }
  if (typeof payload.appVersion !== "string" || !/^3\.\d+\.\d+$/.test(payload.appVersion) || typeof payload.createdAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(payload.createdAt) || !Number.isFinite(Date.parse(payload.createdAt))) throw new Error("备份元数据无效或应用版本不兼容。");
  return { appVersion: payload.appVersion, createdAt: payload.createdAt, config: backupValidateConfig(payload.config) };
}

/** Bounded regular-file read, rejecting symlinks, devices and hardlinks. */
function backupReadFile(path: string, limit: number): Buffer {
  const before = backupFs.lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > limit) throw new Error("请选择大小受限的普通文件，不支持链接文件。");
  const fd = backupFs.openSync(path, backupFs.constants.O_RDONLY | (backupFs.constants.O_NOFOLLOW || 0));
  try {
    const opened = backupFs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > limit) throw new Error("文件已改变，请重新选择。");
    const bytes = Buffer.alloc(opened.size + 1);
    let length = 0;
    while (length < bytes.length) { const count = backupFs.readSync(fd, bytes, length, bytes.length - length, null); if (!count) break; length += count; }
    if (length !== opened.size) throw new Error("文件在读取时发生变化。");
    return bytes.subarray(0, length);
  } finally { backupFs.closeSync(fd); }
}

/** Exclusive creation never overwrites a destination; failed partial writes are removed. */
function backupCreateFile(path: string, bytes: string | Buffer): void {
  const fd = backupFs.openSync(path, "wx", 0o600);
  let complete = false;
  try { backupFs.writeFileSync(fd, bytes); backupFs.fsyncSync(fd); complete = true; }
  finally {
    backupFs.closeSync(fd);
    if (!complete) { try { backupFs.unlinkSync(path); } catch {} }
  }
}

export function exportConfigBackup(config: AppConfig, filename: string, password: string): void {
  if (backupPath.extname(filename).toLowerCase() !== ".nexus-backup") throw new Error("备份文件名必须以 .nexus-backup 结尾。");
  const encrypted = encodeConfigBackup(config, password);
  try { backupCreateFile(filename, encrypted); }
  catch { throw new Error("无法保存备份：请使用可写目录中的新文件名；不会覆盖已有文件。"); }
}

/** Read current bytes without initializing, migrating or repairing config. */
function backupCurrent(paths: AppPaths): Buffer | null {
  try { return backupReadFile(paths.config, backupLimit); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
}
function backupFingerprint(bytes: Buffer | null): string | null { return bytes === null ? null : backupCrypto.createHash("sha256").update(bytes).digest("hex"); }

/** New-host defaults: retain identity/credentials, require deliberate activation. */
export function prepareConfigImport(paths: AppPaths, filename: string, password: string): ConfigImportPreview {
  let encrypted: string;
  try { encrypted = backupReadFile(filename, BACKUP_FILE_LIMIT).toString("utf8"); }
  catch { throw new Error("无法读取备份：请选择不超过 24 MiB 的普通文件。"); }
  const backup = decodeConfigBackup(encrypted, password);
  const config = structuredClone(backup.config);
  config.firewall = { mode: "manual", linuxBackend: "auto", firewalldZone: "" };
  config.webhook = { kind: "none", url: "" };
  config.coreIpv6 = false;
  for (const node of config.nodes) {
    node.enabled = false;
    // Preserve wildcard/loopback semantics; remove bindings to old NIC addresses.
    if (!["0.0.0.0", "::", "127.0.0.1", "::1"].includes(node.listen)) node.listen = backupNet.isIP(node.listen) === 6 ? "::" : "0.0.0.0";
    if (backupNet.isIP(node.address)) node.address = "";
    node.tunnel.connectAddress = "";
  }
  return { ...backup, config: backupValidateConfig(config), expected: backupFingerprint(backupCurrent(paths)) };
}

/** Save only after preview/confirmation. No service, firewall, network or core calls. */
export function commitConfigImport(paths: AppPaths, preview: ConfigImportPreview): { recovery: string | null } {
  const candidate = JSON.stringify(backupValidateConfig(preview.config), null, 2) + "\n";
  ensureDataDir(paths);
  const lock = backupPath.join(paths.data, "config-import.lock");
  let lockFd: number;
  try { lockFd = backupFs.openSync(lock, "wx", 0o600); }
  catch { throw new Error("另一个导入正在进行，或上次导入被中断；确认没有导入进程后移除 config-import.lock 再重试。"); }
  const suffix = `${Date.now()}.${backupCrypto.randomBytes(8).toString("hex")}`;
  const staging = backupPath.join(paths.data, `config-import.${suffix}.tmp`);
  let recovery: string | null = null;
  try {
    const original = backupCurrent(paths);
    if (backupFingerprint(original) !== preview.expected) throw new Error("配置已在另一处修改，请重新预览后导入。");
    if (original !== null) {
      recovery = backupPath.join(paths.data, `config.json.pre-import.${suffix}.bak`);
      backupCreateFile(recovery, original);
    }
    backupCreateFile(staging, candidate);
    if (backupFingerprint(backupCurrent(paths)) !== preview.expected) throw new Error("配置已在另一处修改，请重新预览后导入。");
    // Rename is the commit point. All potentially failing writes precede it.
    backupFs.renameSync(staging, paths.config);
    return { recovery };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("配置已在另一处修改")) throw error;
    throw new Error("导入保存失败，原配置未改变；请检查目录权限、磁盘空间并重试。");
  } finally {
    try { backupFs.unlinkSync(staging); } catch {}
    try { backupFs.closeSync(lockFd); } catch {}
    try { backupFs.unlinkSync(lock); } catch {}
  }
}
