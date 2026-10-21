#!/usr/bin/env bun
/**
 * NexusEdge 2.2.1 — stable core defaults, simple multi-protocol setup, optional tunnels.
 * Run: bun nexus-edge.ts
 * Requires Bun >= 1.4.3; Windows x64 / Linux x64, arm64.
 * Generated from the typed source modules using scripts/build.ts.
 * No npm runtime dependencies. See README.md for operation and verification.
 */

// ==================== core.ts ====================
import * as coreFs from "node:fs";
import * as corePath from "node:path";
import * as coreCrypto from "node:crypto";
import * as coreNet from "node:net";
import * as coreUrl from "node:url";
import * as coreCp from "node:child_process";
import * as coreDecoder from "node:string_decoder";

export const APP_VERSION = "2.2.1";

export interface WarpProfile {
  privateKey: string;
  addresses: string[];
  peerPublicKey: string;
  endpointHost: string;
  endpointPort: number;
  reserved: number[];
}

export type NodeProtocol = "vless" | "vmess" | "shadowsocks" | "trojan" | "hysteria2" | "tuic" | "anytls" | "socks" | "naive";
export type CoreName = "xray" | "singBox";
export type NodeRoute = "direct" | "tunnel";
export interface NodeConfig {
  id: string;
  name: string;
  enabled: boolean;
  protocol: NodeProtocol;
  listen: string;
  port: number;
  /** Client-facing address and port may differ from the local listener (NAT/CDN). */
  address: string;
  publicPort: number;
  direct: boolean;
  egress: "direct" | "warp";
  uuid: string;
  username: string;
  password: string;
  method: string;
  transport: { type: "tcp" | "ws" | "grpc" | "xhttp"; path: string; host: string; serviceName: string; mode: "auto" | "packet-up" | "stream-up" | "stream-one" };
  tls: {
    mode: "none" | "tls" | "reality";
    serverName: string;
    alpn: string[];
    certificatePem: string;
    keyPem: string;
    insecure: boolean;
    reality: { privateKey: string; publicKey: string; shortId: string; handshakeServer: string; handshakePort: number };
  };
  flow: "" | "xtls-rprx-vision";
  vlessEncryption: string;
  vlessDecryption: string;
  vmessSecurity: "auto" | "aes-128-gcm" | "chacha20-poly1305" | "zero" | "none";
  /** Bandwidth from the server's point of view; client export reverses the directions. */
  hy2: { obfsPassword: string; upMbps: number; downMbps: number };
  tuic: { congestionControl: "cubic" | "new_reno" | "bbr"; zeroRttHandshake: boolean };
  tunnel: { mode: "none" | "quick" | "fixed"; token: string; domain: string; connectAddress: string; protocol: "auto" | "http2" | "quic" };
}

export interface NodeLink {
  nodeId: string;
  via: NodeRoute;
  label: string;
  uri: string | null;
  format: "uri" | "json";
  error?: string;
}

export interface AppConfig {
  schema: 2;
  nodes: NodeConfig[];
  warp?: WarpProfile;
  webhook: { kind: "none" | "generic" | "feishu" | "wecom" | "dingtalk" | "bark"; url: string };
}

export interface AppPaths {
  root: string;
  entry: string;
  runtime: string;
  data: string;
  bin: string;
  config: string;
  runtimeState: string;
  log: string;
  link: string;
  lockDb: string;
  tokenFile: string;
  singConfig: string;
  xrayConfig: string;
}

export interface RuntimeRecord {
  schema: 1;
  instanceId: string;
  pid: number;
  startedAt: string;
  controlPort: number;
  controlToken: string;
  configHash: string;
}

export type CoreProcessState = "starting" | "running" | "backoff" | "stopped";
export interface CoreRuntimeStatus { state: CoreProcessState; restarts: number; lastError: string | null }
export interface NodeRuntimeStatus {
  id: string;
  name: string;
  protocol: NodeProtocol;
  engine: CoreName;
  enabled: boolean;
  phase: "disabled" | "starting" | "ready" | "degraded" | "stopping";
  listenerReady: boolean;
  listenerCheck: "tcp" | "udp" | "tcp+udp";
  directReady: boolean;
  tunnelReady: boolean;
  tunnelMode: NodeConfig["tunnel"]["mode"];
  tunnelState: CoreProcessState | "disabled";
  tunnelRestarts: number;
  domain: string | null;
  links: NodeLink[];
  lastError: string | null;
  detail: string;
}
export interface DaemonStatus {
  instanceId: string;
  pid: number;
  startedAt: string;
  configHash: string;
  /** Optional so panels can still identify and stop workers from older releases. */
  runtimeConfigHash?: string;
  /** The selected releases are frozen when a worker starts, including retries. */
  coreReleaseHash?: string;
  phase: "starting" | "ready" | "degraded" | "stopping";
  cores: Partial<Record<CoreName, CoreRuntimeStatus>>;
  nodes: NodeRuntimeStatus[];
  links: NodeLink[];
  lastError: string | null;
}

export function assertSupportedPlatform(os = process.platform, cpu = process.arch): void {
  if (os !== "win32" && os !== "linux") throw new Error(`本版本支持 Windows / Linux；当前系统是 ${os}。`);
  if (cpu !== "x64" && !(os === "linux" && cpu === "arm64")) {
    throw new Error(`暂不支持 ${os}/${cpu}。Windows 请使用 x64 Bun；Windows ARM64 没有对应的官方 cloudflared 资产。`);
  }
}

export function createPaths(entry: string, runtime = process.execPath): AppPaths {
  const absolute = corePath.resolve(entry);
  const root = corePath.dirname(absolute);
  const data = corePath.join(root, ".nexus-edge");
  return {
    root, entry: absolute, runtime: corePath.resolve(runtime), data,
    bin: corePath.join(data, "bin"), config: corePath.join(data, "config.json"),
    runtimeState: corePath.join(data, "runtime.json"), log: corePath.join(data, "daemon.log"),
    link: corePath.join(data, "node-link.txt"), lockDb: corePath.join(data, "daemon-lock.sqlite"),
    tokenFile: corePath.join(data, "tunnel-token.txt"), singConfig: corePath.join(data, "sing-box.json"),
    xrayConfig: corePath.join(data, "xray.json"),
  };
}

const coreProtectedDirs = new Set<string>();

export function ensureDataDir(paths: AppPaths): void {
  for (const dir of [paths.data, paths.bin]) {
    if (coreFs.existsSync(dir) && coreFs.lstatSync(dir).isSymbolicLink()) throw new Error(`数据目录不能是符号链接：${dir}`);
    coreFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") coreFs.chmodSync(dir, 0o700);
  }
  if (process.platform === "win32" && !coreProtectedDirs.has(paths.data)) {
    // The system installer owns this DACL. Do not add an individual administrator
    // SID: their unelevated token would then gain write access to SYSTEM's cores.
    const markerPath = corePath.join(paths.root, "installation.json");
    if (coreFs.existsSync(markerPath)) {
      const marker = JSON.parse(coreFs.readFileSync(markerPath, "utf8")) as { app?: string; schema?: number; entry?: string; runtime?: string };
      if (marker.app === "NexusEdge" && marker.schema === 1 && typeof marker.entry === "string" && corePath.resolve(marker.entry).toLowerCase() === paths.entry.toLowerCase()) {
        const script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)";
        const query = coreCp.spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", windowsHide: true, timeout: 20000 });
        const programData = query.stdout?.trim().replace(/^\uFEFF/, "");
        if (query.status === 0 && programData && corePath.win32.resolve(paths.root).toLowerCase() === corePath.win32.join(programData, "NexusEdge").toLowerCase()) {
          coreProtectedDirs.add(paths.data);
          return;
        }
      }
    }
    const identity = coreCp.spawnSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
    const sid = identity.stdout?.match(/S-1-5-\d+(?:-\d+)+/)?.[0];
    if (identity.status !== 0 || !sid) throw new Error("无法确认当前 Windows 用户 SID，未写入含密钥的数据。");
    const rights = [...new Set([sid, "S-1-5-18", "S-1-5-32-544"])].map(id => `*${id}:(OI)(CI)F`);
    const acl = coreCp.spawnSync("icacls.exe", [paths.data, "/inheritance:r", "/grant:r", ...rights], { encoding: "utf8", windowsHide: true });
    if (acl.status !== 0) throw new Error(`无法保护数据目录权限：${acl.stderr || acl.stdout}`);
    coreProtectedDirs.add(paths.data);
  }
}

export function defaultConfig(): AppConfig {
  return { schema: 2, nodes: [], webhook: { kind: "none", url: "" } };
}

export const NODE_PROTOCOLS: readonly NodeProtocol[] = ["vless", "vmess", "shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"];
export const SHADOWSOCKS_METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] as const;
export function nodeEngine(node: NodeConfig): CoreName { return node.protocol === "vless" ? "xray" : "singBox"; }
export function nodeListenNetworks(node: NodeConfig): ("tcp" | "udp")[] {
  if (node.protocol === "hysteria2" || node.protocol === "tuic") return ["udp"];
  if (node.protocol === "shadowsocks") return ["tcp", "udp"];
  // sing-box SOCKS starts a TCP listener. Its UDP sockets are created through
  // UDP ASSOCIATE, not bound to node.port during startup.
  return ["tcp"];
}
export function nodeAllowsTunnel(node: NodeConfig): boolean {
  return (node.protocol === "vless" || node.protocol === "vmess") && node.transport.type === "ws" && node.tls.mode === "none";
}
export function generateShadowsocksPassword(method: string): string {
  if (!(SHADOWSOCKS_METHODS as readonly string[]).includes(method)) throw new Error("不支持此 Shadowsocks 加密方法。");
  return coreCrypto.randomBytes(method === "2022-blake3-aes-128-gcm" ? 16 : 32).toString("base64");
}
export function generateRealityKeyPair(): { privateKey: string; publicKey: string } {
  const pair = coreCrypto.generateKeyPairSync("x25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  if (!privateJwk.d || !publicJwk.x) throw new Error("当前运行时无法生成 X25519 密钥。");
  return { privateKey: privateJwk.d, publicKey: publicJwk.x };
}
export function deriveRealityPublicKey(privateKey: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(privateKey) || Buffer.from(privateKey, "base64url").length !== 32 || Buffer.from(privateKey, "base64url").toString("base64url") !== privateKey) throw new Error("REALITY 私钥须为 32 字节 Base64URL。");
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(privateKey, "base64url")]);
  const key = coreCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const result = coreCrypto.createPublicKey(key).export({ format: "jwk" }).x;
  if (!result) throw new Error("无法从 REALITY 私钥导出公钥。");
  return result;
}

/** A wizard draft. TLS protocols require certificate material before an enabled save. */
export function createDefaultNode(protocol: NodeProtocol, existingNodes: NodeConfig[] = []): NodeConfig {
  if (!NODE_PROTOCOLS.includes(protocol)) throw new Error("不支持此节点协议。");
  const tlsRequired = ["trojan", "hysteria2", "tuic", "anytls", "naive"].includes(protocol);
  const node: NodeConfig = {
    id: coreCrypto.randomUUID(), name: `${protocol.toUpperCase()}-${existingNodes.length + 1}`, enabled: true,
    protocol, listen: "0.0.0.0", port: protocol === "shadowsocks" ? 8388 : protocol === "vmess" ? 10086 : protocol === "socks" ? 1080 : 8443,
    address: "", publicPort: 8443, direct: true, egress: "direct", uuid: coreCrypto.randomUUID(), username: "nexus",
    password: coreCrypto.randomBytes(24).toString("base64url"), method: "2022-blake3-aes-128-gcm",
    transport: { type: "tcp", path: "/nexus-ws", host: "", serviceName: "nexus-grpc", mode: "auto" },
    tls: { mode: tlsRequired ? "tls" : "none", serverName: "", alpn: [], certificatePem: "", keyPem: "", insecure: false,
      reality: { privateKey: "", publicKey: "", shortId: "", handshakeServer: "", handshakePort: 443 } },
    flow: "", vlessEncryption: "none", vlessDecryption: "none", vmessSecurity: "auto",
    hy2: { obfsPassword: "", upMbps: 100, downMbps: 100 }, tuic: { congestionControl: "bbr", zeroRttHandshake: false },
    tunnel: { mode: "none", token: "", domain: "", connectAddress: "", protocol: "auto" },
  };
  if (protocol === "shadowsocks") node.password = generateShadowsocksPassword(node.method);
  while (existingNodes.some(other => other.enabled && other.port === node.port && nodeListenNetworks(other).some(network => nodeListenNetworks(node).includes(network)))) node.port++;
  if (node.port > 65535) throw new Error("没有可分配的默认监听端口，请手动调整已有节点。");
  node.publicPort = node.port;
  return node;
}

function coreObject(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} 必须是对象。`);
  return value as Record<string, unknown>;
}

function coreString(value: unknown, name: string, max = 1024): string {
  if (typeof value !== "string" || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${name} 不是有效文本。`);
  return value.trim();
}

function coreChoice<T extends string>(value: unknown, values: readonly T[], name: string): T {
  if (typeof value !== "string" || !values.includes(value as T)) throw new Error(`${name} 的取值无效。`);
  return value as T;
}

export function normalizeDomain(value: string): string {
  const input = coreString(value, "隧道域名", 253).replace(/\.$/, "");
  const domain = coreUrl.domainToASCII(input).toLowerCase();
  if (!domain || !domain.includes(".") || coreNet.isIP(domain) || /[:/\\?#@\s]/.test(input) || domain.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) {
    throw new Error("请输入完整域名，例如 node.example.com；不要包含 https://、路径或端口。");
  }
  return domain;
}

export function normalizeConnectAddress(value: string): string {
  const input = coreString(value, "连接地址", 253);
  if (!input) return "";
  if (input.includes("%")) throw new Error("连接地址不能包含 IPv6 scope ID 或百分号转义。");
  const unbracketed = input.startsWith("[") && input.endsWith("]") ? input.slice(1, -1) : input;
  const family = coreNet.isIP(unbracketed);
  if (family === 6) return new URL(`http://[${unbracketed}]`).hostname.slice(1, -1);
  if (family === 4) return unbracketed;
  return normalizeDomain(input);
}

export function validateWarpProfile(value: unknown): WarpProfile {
  const v = coreObject(value, "WARP 配置");
  const key = (input: unknown, name: string): string => {
    const text = coreString(input, name, 64);
    if (!/^[A-Za-z0-9+/]{43}=$/.test(text) || Buffer.from(text, "base64").length !== 32 || Buffer.from(text, "base64").toString("base64") !== text) throw new Error(`${name} 必须是 32 字节的 Base64 WireGuard 密钥。`);
    return text;
  };
  if (!Array.isArray(v.addresses) || v.addresses.length < 1 || v.addresses.length > 8) throw new Error("WARP 必须提供接口 IP/CIDR 地址。");
  const addresses = v.addresses.map((item: unknown) => {
    const addr = coreString(item, "WARP 地址", 128);
    const parts = addr.split("/");
    const family = coreNet.isIP(parts[0] || "");
    if (parts.length !== 2 || !family || !/^\d{1,3}$/.test(parts[1] || "") || Number(parts[1]) > (family === 4 ? 32 : 128)) throw new Error(`无效 WARP IP/CIDR：${addr}`);
    return addr;
  });
  const endpointHost = normalizeConnectAddress(coreString(v.endpointHost, "WARP endpoint"));
  if (!endpointHost) throw new Error("WARP endpoint 不能为空。");
  if (!Number.isInteger(v.endpointPort) || (v.endpointPort as number) < 1 || (v.endpointPort as number) > 65535) throw new Error("WARP endpoint 端口必须为 1–65535。");
  if (!Array.isArray(v.reserved) || v.reserved.length !== 3 || v.reserved.some((n: unknown) => !Number.isInteger(n) || (n as number) < 0 || (n as number) > 255)) throw new Error("WARP Reserved 必须是三个 0–255 整数。");
  return {
    privateKey: key(v.privateKey, "WARP privateKey"), addresses,
    peerPublicKey: key(v.peerPublicKey, "WARP peerPublicKey"), endpointHost,
    endpointPort: v.endpointPort as number, reserved: [...v.reserved] as number[],
  };
}

function coreBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${name} 必须是布尔值。`);
  return value;
}
function coreInteger(value: unknown, name: string, min: number, max: number): number {
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) throw new Error(`${name} 必须为 ${min}–${max} 的整数。`);
  return value as number;
}
function corePassword(value: unknown, name: string, max = 4096): string {
  if (typeof value !== "string" || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${name} 不是有效密码文本。`);
  return value;
}
function corePathValue(value: unknown): string {
  const path = coreString(value, "传输路径", 200);
  if (path && (!/^\/[A-Za-z0-9/._~-]*$/.test(path) || path.includes("//") || path.split("/").some(part => part === "." || part === ".."))) throw new Error("传输路径须以 / 开始，只能使用英文字母、数字、/、-、.、_、~，不能含 // 或 . / .. 路径段。");
  return path;
}
function coreHostHeader(value: unknown): string {
  const host = coreString(value, "传输 Host", 300);
  if (!host) return "";
  if (coreNet.isIP(host) === 6) return `[${normalizeConnectAddress(host)}]`;
  if (/[\s/\\?#@]/.test(host)) throw new Error("传输 Host 应为主机名或 IP，可附带端口；不要填写 URL 或路径。");
  let parsed: URL;
  try { parsed = new URL(`http://${host}`); } catch { throw new Error("传输 Host 格式无效。"); }
  const hostname = normalizeConnectAddress(parsed.hostname);
  if (!hostname || parsed.username || parsed.password || parsed.pathname !== "/") throw new Error("传输 Host 格式无效。");
  const explicitPort = host.match(/(?:\]|^[^:]+):(\d+)$/)?.[1];
  if (host.endsWith(":")) throw new Error("传输 Host 的端口不能为空。");
  const port = explicitPort === undefined ? undefined : coreInteger(Number(explicitPort), "传输 Host 端口", 1, 65535);
  return `${coreNet.isIP(hostname) === 6 ? `[${hostname}]` : hostname}${port === undefined ? "" : `:${port}`}`;
}
export function normalizeTransportHost(value: string): string { return coreHostHeader(value); }
function corePem(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length > 256 * 1024 || value.includes("\0")) throw new Error(`${name} 应为 PEM 文本，最大 256 KiB。`);
  const text = value.replace(/\r\n/g, "\n").trim();
  return text ? text + "\n" : "";
}
function coreValidateCertificate(certificatePem: string, keyPem: string, complete: boolean, allowExpired = false): void {
  if (complete && (!certificatePem || !keyPem)) throw new Error("TLS 节点需要完整证书与私钥；可以生成自签证书或导入自己的 PEM。");
  let certificate: coreCrypto.X509Certificate | undefined;
  let privateKey: coreCrypto.KeyObject | undefined;
  if (certificatePem) {
    try { certificate = new coreCrypto.X509Certificate(certificatePem); }
    catch { throw new Error("TLS 证书不是有效的 X.509 PEM 证书。"); }
    if (complete && !allowExpired && Date.parse(certificate.validTo) <= Date.now()) throw new Error("TLS 证书已经过期，请更换证书后启用节点。");
    if (complete && Date.parse(certificate.validFrom) > Date.now() + 60_000) throw new Error("TLS 证书尚未生效，请检查证书和系统时间。");
  }
  if (keyPem) {
    try { privateKey = coreCrypto.createPrivateKey(keyPem); }
    catch { throw new Error("TLS 私钥不是有效的未加密 PEM 私钥。"); }
  }
  if (certificate && privateKey) {
    const expected = certificate.publicKey.export({ format: "der", type: "spki" });
    const actual = coreCrypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
    if (!Buffer.from(expected).equals(Buffer.from(actual))) throw new Error("TLS 证书与私钥不匹配。");
  }
}

/** Validate drafts too, but require all operational credentials only when enabled. */
export function validateNode(value: unknown, options: { allowIncomplete?: boolean; allowExpiredCertificate?: boolean } = {}): NodeConfig {
  const v = coreObject(value, "节点");
  const id = coreString(v.id, "节点 ID", 64);
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error("节点 ID 只能包含字母、数字、下划线和连字符。");
  const name = coreString(v.name, "节点名称", 100);
  if (!name) throw new Error("节点名称不能为空。");
  const enabled = coreBoolean(v.enabled, "节点启用状态");
  const complete = enabled && !options.allowIncomplete;
  const protocol = coreChoice(v.protocol, NODE_PROTOCOLS, "节点协议");
  const listen = normalizeConnectAddress(coreString(v.listen, "监听地址", 100));
  if (!coreNet.isIP(listen)) throw new Error("监听地址必须是本机 IPv4 / IPv6，例如 0.0.0.0 或 127.0.0.1。");
  const port = coreInteger(v.port, "监听端口", 1, 65535);
  const publicPort = coreInteger(v.publicPort, "客户端连接端口", 1, 65535);
  const address = normalizeConnectAddress(coreString(v.address, "客户端连接地址", 253));
  if (["0.0.0.0", "::"].includes(address)) throw new Error("客户端连接地址不能是 0.0.0.0 / ::；请填写实际 IP / 域名，或暂时留空。");
  const direct = coreBoolean(v.direct, "直连入口开关");
  const egress = coreChoice(v.egress, ["direct", "warp"] as const, "出站模式");
  const uuid = coreString(v.uuid, "UUID", 36).toLowerCase();
  if (uuid && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) throw new Error("UUID 格式无效。");
  if (complete && ["vless", "vmess", "tuic"].includes(protocol) && !uuid) throw new Error(`${protocol} 节点需要 UUID。`);
  const username = corePassword(v.username, "用户名", 255);
  const password = corePassword(v.password, "密码");
  const method = coreString(v.method, "Shadowsocks 加密方法", 100);
  if (["socks", "naive"].includes(protocol) && (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255)) throw new Error(`${protocol} 用户名及密码不能超过 255 个 UTF-8 字节。`);
  if (complete && ["shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"].includes(protocol) && !password) throw new Error(`${protocol} 节点需要密码。`);
  if (complete && ["socks", "naive"].includes(protocol) && !username) throw new Error(`${protocol} 节点需要用户名；本版不创建无认证公网代理。`);
  if (protocol === "shadowsocks") {
    if (!(SHADOWSOCKS_METHODS as readonly string[]).includes(method)) throw new Error("不支持此 Shadowsocks 加密方法。");
    if (password && method.startsWith("2022-")) {
      const expectedBytes = method === "2022-blake3-aes-128-gcm" ? 16 : 32;
      const decoded = Buffer.from(password, "base64");
      if (decoded.length !== expectedBytes || decoded.toString("base64") !== password) throw new Error(`${method} 需要 ${expectedBytes} 字节的标准 Base64 密钥。`);
    }
  }
  const rawTransport = coreObject(v.transport, "传输配置");
  const transport: NodeConfig["transport"] = {
    type: coreChoice(rawTransport.type, ["tcp", "ws", "grpc", "xhttp"] as const, "传输类型"),
    path: corePathValue(rawTransport.path), host: coreHostHeader(rawTransport.host),
    serviceName: coreString(rawTransport.serviceName, "gRPC 服务名", 200),
    mode: coreChoice(rawTransport.mode, ["auto", "packet-up", "stream-up", "stream-one"] as const, "XHTTP 模式"),
  };
  if (transport.serviceName && !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(transport.serviceName)) throw new Error("gRPC 服务名只能使用英文字母、数字、.、_、-、/。");
  if (["ws", "xhttp"].includes(transport.type) && !transport.path) throw new Error("WebSocket / XHTTP 需要非空传输路径。");
  if (transport.type === "grpc" && !transport.serviceName) throw new Error("gRPC 需要非空服务名。");
  if (!["vless", "vmess", "trojan"].includes(protocol) && transport.type !== "tcp") throw new Error(`${protocol} 使用原生传输，不支持 V2Ray ${transport.type} 传输选项。`);
  if (transport.type === "xhttp" && protocol !== "vless") throw new Error("本版 XHTTP 使用 Xray VLESS，请选择 VLESS 协议。");
  const rawTls = coreObject(v.tls, "TLS 配置");
  const rawReality = coreObject(rawTls.reality, "REALITY 配置");
  if (!Array.isArray(rawTls.alpn) || rawTls.alpn.length > 8) throw new Error("ALPN 必须是最多 8 项的数组。");
  const tls: NodeConfig["tls"] = {
    mode: coreChoice(rawTls.mode, ["none", "tls", "reality"] as const, "TLS 模式"),
    serverName: normalizeConnectAddress(coreString(rawTls.serverName, "TLS Server Name", 253)),
    alpn: [...new Set(rawTls.alpn.map(value => {
      const token = coreString(value, "ALPN", 255);
      if (!token || !/^[\x21-\x7e]+$/.test(token)) throw new Error("ALPN 项必须是非空 ASCII 标识。");
      return token;
    }))],
    certificatePem: corePem(rawTls.certificatePem, "TLS 证书"), keyPem: corePem(rawTls.keyPem, "TLS 私钥"),
    insecure: coreBoolean(rawTls.insecure, "客户端跳过证书验证"),
    reality: {
      privateKey: coreString(rawReality.privateKey, "REALITY 私钥", 100), publicKey: coreString(rawReality.publicKey, "REALITY 公钥", 100),
      shortId: coreString(rawReality.shortId, "REALITY short ID", 16).toLowerCase(),
      handshakeServer: normalizeConnectAddress(coreString(rawReality.handshakeServer, "REALITY 握手目标", 253)),
      handshakePort: coreInteger(rawReality.handshakePort, "REALITY 握手端口", 1, 65535),
    },
  };
  if (tls.mode === "tls") coreValidateCertificate(tls.certificatePem, tls.keyPem, complete, options.allowExpiredCertificate);
  if (["shadowsocks", "socks"].includes(protocol) && tls.mode !== "none") throw new Error(`${protocol} 原生协议不使用这里的 TLS 包装；请使用协议本身支持的连接参数。`);
  if (["trojan", "hysteria2", "tuic", "naive"].includes(protocol) && tls.mode !== "tls") throw new Error(`${protocol} 需要 TLS 证书模式。`);
  if (protocol === "anytls" && tls.mode === "none") throw new Error("AnyTLS 需要 TLS 或 REALITY。");
  if (tls.mode === "reality") {
    if (!["vless", "anytls"].includes(protocol)) throw new Error("本版 REALITY 仅支持 VLESS 和 AnyTLS。");
    if (transport.type === "ws") throw new Error("REALITY 不支持 WebSocket 传输；可选 TCP / XHTTP，或改为普通 TLS。");
    const r = tls.reality;
    if (r.privateKey && deriveRealityPublicKey(r.privateKey) !== r.publicKey) throw new Error("REALITY 公钥与私钥不匹配。");
    if (r.publicKey && (!/^[A-Za-z0-9_-]{43}$/.test(r.publicKey) || Buffer.from(r.publicKey, "base64url").toString("base64url") !== r.publicKey)) throw new Error("REALITY 公钥必须为 32 字节 Base64URL。");
    if (!/^(?:[0-9a-f]{2}){0,8}$/.test(r.shortId)) throw new Error("REALITY short ID 必须是最多 16 位、偶数长度的十六进制文本。");
    if (complete && (!r.privateKey || !r.publicKey || !r.handshakeServer || !tls.serverName)) throw new Error("REALITY 需要密钥对、握手目标和 Server Name。");
    if (tls.serverName && coreNet.isIP(tls.serverName)) throw new Error("REALITY Server Name 应为握手目标支持的域名，不能是 IP。");
  }
  const flow = coreChoice(v.flow, ["", "xtls-rprx-vision"] as const, "VLESS flow");
  const vlessEncryption = coreString(v.vlessEncryption, "VLESS 客户端 encryption", 16384);
  const vlessDecryption = coreString(v.vlessDecryption, "VLESS 服务端 decryption", 16384);
  if (!vlessEncryption || !vlessDecryption || (vlessEncryption === "none") !== (vlessDecryption === "none")) throw new Error("VLESS ENC 必须同时提供客户端 encryption 与服务端 decryption；关闭时两项都填 none。");
  if (protocol !== "vless" && (flow || vlessEncryption !== "none" || vlessDecryption !== "none")) throw new Error("flow / VLESS ENC 仅适用于 VLESS 节点。");
  if (flow && vlessEncryption === "none" && (transport.type !== "tcp" || tls.mode === "none")) throw new Error("未开启 VLESS ENC 时，XTLS Vision 需要 TCP + TLS / REALITY；其他传输请启用 ENC，或选择普通 VLESS。");
  const rawHy2 = coreObject(v.hy2, "Hysteria2 配置");
  const hy2 = { obfsPassword: corePassword(rawHy2.obfsPassword, "Hysteria2 混淆密码"),
    upMbps: coreInteger(rawHy2.upMbps, "Hysteria2 上行 Mbps", 0, 1000000), downMbps: coreInteger(rawHy2.downMbps, "Hysteria2 下行 Mbps", 0, 1000000) };
  const rawTuic = coreObject(v.tuic, "TUIC 配置");
  const tuic: NodeConfig["tuic"] = {
    congestionControl: coreChoice(rawTuic.congestionControl, ["cubic", "new_reno", "bbr"] as const, "TUIC 拥塞控制"),
    zeroRttHandshake: coreBoolean(rawTuic.zeroRttHandshake, "TUIC 0-RTT"),
  };
  const rawTunnel = coreObject(v.tunnel, "隧道配置");
  const tunnel: NodeConfig["tunnel"] = {
    mode: coreChoice(rawTunnel.mode, ["none", "quick", "fixed"] as const, "隧道模式"),
    token: coreString(rawTunnel.token, "Tunnel Token", 16384),
    domain: coreString(rawTunnel.domain, "隧道域名", 253),
    connectAddress: normalizeConnectAddress(coreString(rawTunnel.connectAddress, "隧道连接地址", 253)),
    protocol: coreChoice(rawTunnel.protocol, ["auto", "http2", "quic"] as const, "隧道传输"),
  };
  if (tunnel.domain) tunnel.domain = normalizeDomain(tunnel.domain);
  if (tunnel.token && !/^[A-Za-z0-9_+/=-]{16,16384}$/.test(tunnel.token)) throw new Error("Tunnel Token 格式无效，请填写完整 Token。");
  if (tunnel.mode === "fixed" && complete && (!tunnel.token || !tunnel.domain)) throw new Error("固定隧道需要 Tunnel Token 和公共主机名。");
  const node: NodeConfig = { id, name, enabled, protocol, listen, port, address, publicPort, direct, egress,
    uuid, username, password, method, transport, tls, flow, vlessEncryption, vlessDecryption,
    vmessSecurity: coreChoice(v.vmessSecurity, ["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"] as const, "VMess 加密方式"), hy2, tuic, tunnel };
  if (!direct && tunnel.mode === "none") throw new Error("至少需要开启直连入口或一个隧道入口。");
  if (!direct && !["127.0.0.1", "::1"].includes(listen)) throw new Error("仅隧道节点应监听 127.0.0.1 或 ::1，避免额外暴露直连端口。");
  if (tunnel.mode !== "none" && !nodeAllowsTunnel(node)) throw new Error("Cloudflare HTTP 隧道仅适用于本机无 TLS 的 VLESS / VMess WebSocket 节点；原生 TCP / UDP 协议请选择不启用隧道。");
  return node;
}

function coreValidateWebhook(value: unknown): AppConfig["webhook"] {
  const w = coreObject(value, "Webhook");
  const kind = coreChoice(w.kind, ["none", "generic", "feishu", "wecom", "dingtalk", "bark"] as const, "Webhook 类型");
  const url = coreString(w.url, "Webhook URL", 4096);
  if (kind !== "none") {
    let parsed: URL;
    try { parsed = new URL(url); } catch { throw new Error("Webhook 需要完整的 HTTPS URL。"); }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash) throw new Error("Webhook 必须使用 HTTPS，且不能带用户名、密码或 #片段。");
  }
  return { kind, url: kind === "none" ? "" : url };
}

function coreListenersOverlap(a: NodeConfig, b: NodeConfig): boolean {
  if (a.port !== b.port || !nodeListenNetworks(a).some(network => nodeListenNetworks(b).includes(network))) return false;
  if (a.listen === b.listen || a.listen === "::" || b.listen === "::") return true;
  const aFamily = coreNet.isIP(a.listen), bFamily = coreNet.isIP(b.listen);
  return aFamily === bFamily && (a.listen === "0.0.0.0" || b.listen === "0.0.0.0");
}

export function validateConfig(value: unknown, options: { allowExpiredCertificate?: boolean } = {}): AppConfig {
  const v = coreObject(value, "配置");
  if (v.schema !== 2) throw new Error("不支持此配置版本；请通过 readConfig 升级旧配置，并保留原文件。");
  if (!Array.isArray(v.nodes) || v.nodes.length > 32) throw new Error("nodes 必须是最多 32 个节点的数组。");
  const nodes = v.nodes.map(node => validateNode(node, options));
  if (new Set(nodes.map(node => node.id)).size !== nodes.length) throw new Error("节点 ID 重复；复制节点时必须生成新的节点 ID。");
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i]!;
    if (!a.enabled) continue;
    for (const b of nodes.slice(i + 1)) if (b.enabled && coreListenersOverlap(a, b)) throw new Error(`节点“${a.name}”与“${b.name}”的监听地址 / 端口冲突（${a.port}）。`);
  }
  const warp = v.warp === undefined ? undefined : validateWarpProfile(v.warp);
  if (!warp && nodes.some(node => node.enabled && node.egress === "warp")) throw new Error("已启用的节点选择了 WARP 出站，但尚未配置有效的 WARP 凭据。");
  return { schema: 2, nodes, ...(warp ? { warp } : {}), webhook: coreValidateWebhook(v.webhook) };
}

/** Convert only the released v1 shape; never reinterpret damaged legacy data. */
export function migrateLegacyConfig(value: unknown, options: { allowExpiredCertificate?: boolean } = {}): AppConfig {
  const legacy = coreObject(value, "旧配置");
  if (legacy.schema !== 1) return validateConfig(value, options);
  const oldTunnel = coreObject(legacy.tunnel, "旧隧道配置");
  const oldMode = coreChoice(oldTunnel.mode, ["quick", "fixed"] as const, "旧隧道模式");
  const node = createDefaultNode("vless");
  node.uuid = coreString(legacy.uuid, "旧 UUID", 36).toLowerCase();
  node.id = `legacy-${node.uuid}`;
  node.name = "VLESS（从 1.0 迁移）";
  node.port = coreInteger(legacy.port, "旧监听端口", 1024, 65535);
  node.publicPort = node.port;
  node.listen = "127.0.0.1";
  node.direct = false;
  node.transport.type = "ws";
  node.transport.path = coreString(legacy.wsPath, "旧 WebSocket 路径", 200);
  node.egress = coreChoice(legacy.egress, ["direct", "warp"] as const, "旧出站模式");
  node.tunnel = { mode: oldMode, token: coreString(oldTunnel.token, "旧 Tunnel Token", 16384), domain: coreString(oldTunnel.domain, "旧隧道域名", 253),
    connectAddress: normalizeConnectAddress(coreString(legacy.connectAddress, "旧连接地址", 253)),
    protocol: coreChoice(oldTunnel.protocol, ["auto", "http2", "quic"] as const, "旧隧道传输") };
  return validateConfig({ schema: 2, nodes: [node], ...(legacy.warp === undefined ? {} : { warp: legacy.warp }), webhook: coreValidateWebhook(legacy.webhook) });
}

export function collectConfigSecrets(config: AppConfig): string[] {
  return [config.warp?.privateKey ?? "", config.webhook.url, ...config.nodes.flatMap(node => [
    node.uuid, node.password, node.tunnel.token, node.tls.keyPem, ...node.tls.keyPem.split(/\r?\n/), node.tls.reality.privateKey,
    node.vlessEncryption === "none" ? "" : node.vlessEncryption,
    node.vlessDecryption === "none" ? "" : node.vlessDecryption, node.hy2.obfsPassword,
  ])];
}

/** Write-and-rename: readers see either the old complete file or the new complete file. */
export function atomicWrite(path: string, data: string | Uint8Array, mode = 0o600): void {
  coreFs.mkdirSync(corePath.dirname(path), { recursive: true, mode: 0o700 });
  if (coreFs.existsSync(path) && coreFs.lstatSync(path).isSymbolicLink()) throw new Error(`拒绝覆盖符号链接：${path}`);
  const tmp = `${path}.${process.pid}.${coreCrypto.randomBytes(8).toString("hex")}.tmp`;
  let fd: number | undefined;
  try {
    fd = coreFs.openSync(tmp, "wx", mode);
    coreFs.writeFileSync(fd, data);
    coreFs.fsyncSync(fd);
    coreFs.closeSync(fd); fd = undefined;
    coreFs.renameSync(tmp, path);
    if (process.platform !== "win32") coreFs.chmodSync(path, mode);
  } finally {
    if (fd !== undefined) coreFs.closeSync(fd);
    try { coreFs.unlinkSync(tmp); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  }
}

export function readConfig(paths: AppPaths): AppConfig {
  ensureDataDir(paths);
  if (!coreFs.existsSync(paths.config)) {
    const config = defaultConfig();
    writeConfig(paths, config);
    return config;
  }
  try {
    const original = coreFs.readFileSync(paths.config, "utf8");
    const parsed: unknown = JSON.parse(original);
    if (parsed !== null && typeof parsed === "object" && (parsed as Record<string, unknown>).schema === 1) {
      const upgraded = migrateLegacyConfig(parsed);
      // Archive the exact released-v1 data before replacing it. A later manual
      // re-import of a different v1 file gets its own archive, not an overwrite.
      let archive = `${paths.config}.schema1.bak`;
      if (coreFs.existsSync(archive) && coreFs.readFileSync(archive, "utf8") !== original) archive = `${paths.config}.schema1.${Date.now()}.${coreCrypto.randomBytes(4).toString("hex")}.bak`;
      if (!coreFs.existsSync(archive)) atomicWrite(archive, original);
      writeConfig(paths, upgraded);
      return upgraded;
    }
    return validateConfig(parsed, { allowExpiredCertificate: true });
  }
  catch (e) { throw new Error(`无法读取配置 ${paths.config}：${errorMessage(e)}\n原文件已保留；不会自动重置 UUID。可检查 config.json.bak。`); }
}

export function writeConfig(paths: AppPaths, config: AppConfig): void {
  const normalized = validateConfig(config, { allowExpiredCertificate: true });
  ensureDataDir(paths);
  if (coreFs.existsSync(paths.config)) {
    const old = coreFs.readFileSync(paths.config, "utf8");
    // Do not replace the last known good backup with corrupt data.
    try { migrateLegacyConfig(JSON.parse(old), { allowExpiredCertificate: true }); atomicWrite(`${paths.config}.bak`, old); } catch { /* Preserve existing backup. */ }
  }
  atomicWrite(paths.config, JSON.stringify(normalized, null, 2) + "\n");
}

export function configFingerprint(config: AppConfig): string {
  return coreCrypto.createHash("sha256").update(JSON.stringify(validateConfig(config, { allowExpiredCertificate: true }))).digest("hex");
}

/** Direct client endpoint metadata may change without changing a running core.
 * Keep every other field, including node names and shared settings, conservative. */
export function runtimeConfigFingerprint(config: AppConfig): string {
  const normalized = validateConfig(config, { allowExpiredCertificate: true });
  const runtimeConfig = {
    ...normalized,
    nodes: normalized.nodes.map(({ address: _address, publicPort: _publicPort, ...node }) => node),
  };
  return coreCrypto.createHash("sha256").update(JSON.stringify(runtimeConfig)).digest("hex");
}

interface CoreClientEndpoint {
  address: string;
  port: number;
  security: NodeConfig["tls"]["mode"];
  serverName: string;
  host: string;
  alpn: string[];
  insecure: boolean;
  certificatePin?: string;
}

function coreClientEndpoint(node: NodeConfig, via: NodeRoute, assignedDomain?: string): CoreClientEndpoint {
  if (via === "direct") {
    if (!node.direct) throw new Error("此节点没有开启直连入口。");
    if (!node.address) throw new Error("请先填写此节点的客户端连接地址（公网 IP / 域名），再导出直连配置。");
    return { address: node.address, port: node.publicPort, security: node.tls.mode,
      serverName: node.tls.serverName || node.address, host: node.transport.host,
      alpn: node.tls.alpn, insecure: node.tls.insecure,
      ...(node.protocol === "vless" && node.tls.mode === "tls" && node.tls.insecure
        ? { certificatePin: coreCrypto.createHash("sha256").update(new coreCrypto.X509Certificate(node.tls.certificatePem).raw).digest("hex") } : {}) };
  }
  if (via !== "tunnel") throw new Error("导出入口应为 direct 或 tunnel。");
  if (node.tunnel.mode === "none") throw new Error("此节点没有开启隧道入口。");
  const value = node.tunnel.mode === "fixed" ? node.tunnel.domain : assignedDomain;
  if (!value) throw new Error("临时隧道尚未分配域名；启动节点并等待隧道就绪后再导出。");
  const domain = normalizeDomain(value);
  return { address: node.tunnel.connectAddress || domain, port: 443, security: "tls", serverName: domain,
    host: domain, alpn: [], insecure: false };
}

function coreAuthority(address: string, port: number): string {
  return `${coreNet.isIP(address) === 6 ? `[${address}]` : address}:${port}`;
}
function coreNodeLabel(node: NodeConfig, via: NodeRoute): string { return `${node.name} · ${via === "direct" ? "直连" : "隧道"}`; }
function coreTlsQuery(endpoint: CoreClientEndpoint): URLSearchParams {
  const params = new URLSearchParams({ security: endpoint.security });
  if (endpoint.security !== "none") {
    params.set("sni", endpoint.serverName);
    params.set("fp", "chrome");
    if (endpoint.alpn.length) params.set("alpn", endpoint.alpn.join(","));
    if (endpoint.certificatePin) params.set("pcs", endpoint.certificatePin);
    else if (endpoint.insecure && endpoint.security === "tls") params.set("allowInsecure", "1");
  }
  return params;
}
function coreTransportQuery(params: URLSearchParams, node: NodeConfig, endpoint: CoreClientEndpoint): void {
  params.set("type", node.transport.type);
  if (endpoint.host) params.set("host", endpoint.host);
  if (node.transport.type === "ws" || node.transport.type === "xhttp") params.set("path", node.transport.path);
  if (node.transport.type === "grpc") {
    params.set("serviceName", node.transport.serviceName);
    if (endpoint.host) params.set("authority", endpoint.host);
  }
  if (node.transport.type === "xhttp") params.set("mode", node.transport.mode);
}
function coreNodeUri(node: NodeConfig, via: NodeRoute, endpoint: CoreClientEndpoint): string | null {
  const authority = coreAuthority(endpoint.address, endpoint.port);
  const label = encodeURIComponent(coreNodeLabel(node, via));
  switch (node.protocol) {
    case "vless": {
      const query = coreTlsQuery(endpoint);
      query.set("encryption", node.vlessEncryption);
      coreTransportQuery(query, node, endpoint);
      if (node.flow) query.set("flow", node.flow);
      if (endpoint.security === "reality") {
        query.set("pbk", node.tls.reality.publicKey);
        query.set("sid", node.tls.reality.shortId);
      }
      return `vless://${node.uuid}@${authority}?${query.toString()}#${label}`;
    }
    case "vmess": {
      // v2rayN's v2 JSON share format, including the documented gRPC path field.
      const value = { v: "2", ps: coreNodeLabel(node, via), add: endpoint.address, port: String(endpoint.port),
        id: node.uuid, aid: "0", scy: node.vmessSecurity, net: node.transport.type, type: "none",
        host: endpoint.host, path: node.transport.type === "grpc" ? node.transport.serviceName : node.transport.type === "ws" ? node.transport.path : "",
        tls: endpoint.security === "tls" ? "tls" : "", sni: endpoint.security === "none" ? "" : endpoint.serverName,
        alpn: endpoint.alpn.join(","), fp: endpoint.security === "none" ? "" : "chrome", allowInsecure: endpoint.insecure ? "1" : "0" };
      return `vmess://${Buffer.from(JSON.stringify(value), "utf8").toString("base64")}`;
    }
    case "shadowsocks": {
      // SIP002 explicitly forbids Base64URL userinfo for AEAD-2022 methods.
      const userinfo = node.method.startsWith("2022-")
        ? `${encodeURIComponent(node.method)}:${encodeURIComponent(node.password)}`
        : Buffer.from(`${node.method}:${node.password}`, "utf8").toString("base64url");
      return `ss://${userinfo}@${authority}#${label}`;
    }
    case "trojan": {
      const query = coreTlsQuery(endpoint);
      coreTransportQuery(query, node, endpoint);
      return `trojan://${encodeURIComponent(node.password)}@${authority}?${query.toString()}#${label}`;
    }
    case "hysteria2": {
      // The official URI deliberately excludes bandwidth/client-listen settings.
      const query = new URLSearchParams({ sni: endpoint.serverName, insecure: endpoint.insecure ? "1" : "0" });
      if (node.hy2.obfsPassword) { query.set("obfs", "salamander"); query.set("obfs-password", node.hy2.obfsPassword); }
      return `hysteria2://${encodeURIComponent(node.password)}@${authority}/?${query.toString()}#${label}`;
    }
    case "tuic": {
      const query = new URLSearchParams({ sni: endpoint.serverName, congestion_control: node.tuic.congestionControl,
        udp_relay_mode: "native", allow_insecure: endpoint.insecure ? "1" : "0", zero_rtt_handshake: node.tuic.zeroRttHandshake ? "1" : "0" });
      if (endpoint.alpn.length) query.set("alpn", endpoint.alpn.join(","));
      return `tuic://${node.uuid}:${encodeURIComponent(node.password)}@${authority}?${query.toString()}#${label}`;
    }
    case "anytls": {
      // The published AnyTLS URI has no REALITY fields. JSON preserves that mode.
      if (endpoint.security === "reality") return null;
      const query = new URLSearchParams({ sni: endpoint.serverName, insecure: endpoint.insecure ? "1" : "0" });
      return `anytls://${encodeURIComponent(node.password)}@${authority}/?${query.toString()}#${label}`;
    }
    case "socks": return `socks5://${encodeURIComponent(node.username)}:${encodeURIComponent(node.password)}@${authority}#${label}`;
    case "naive": return null;
  }
}

/** A node may expose direct and tunnel routes simultaneously; readiness is the caller's concern. */
export function generateNodeLinks(value: NodeConfig, assignedDomain?: string): NodeLink[] {
  const routes: NodeRoute[] = [...(value.direct ? ["direct" as const] : []), ...(value.tunnel.mode !== "none" ? ["tunnel" as const] : [])];
  return routes.map(via => {
    const base = { nodeId: value.id, via, label: coreNodeLabel(value, via) };
    const format = value.protocol === "naive" || value.protocol === "anytls" && value.tls.mode === "reality" ? "json" as const : "uri" as const;
    try {
      // Disabled complete nodes may still be exported; disabled incomplete drafts may not.
      const node = validateNode({ ...value, enabled: true });
      const endpoint = coreClientEndpoint(node, via, assignedDomain);
      return { ...base, uri: coreNodeUri(node, via, endpoint), format };
    } catch (error) {
      return { ...base, uri: null, format, error: errorMessage(error) };
    }
  });
}

export interface ClientConfigExport { format: "xray" | "sing-box"; config: Record<string, unknown> }

/** Export a standalone local SOCKS/HTTP client without any server private keys. */
export function generateClientConfig(value: NodeConfig, via: NodeRoute = "direct", assignedDomain?: string): ClientConfigExport {
  const node = validateNode({ ...value, enabled: true });
  const endpoint = coreClientEndpoint(node, via, assignedDomain);
  if (node.protocol === "vless") {
    const stream: Record<string, unknown> = { network: node.transport.type, security: endpoint.security };
    if (node.transport.type === "ws") stream.wsSettings = { path: node.transport.path, ...(endpoint.host ? { headers: { Host: endpoint.host } } : {}) };
    if (node.transport.type === "grpc") stream.grpcSettings = { serviceName: node.transport.serviceName, ...(endpoint.host ? { authority: endpoint.host } : {}) };
    if (node.transport.type === "xhttp") stream.xhttpSettings = { path: node.transport.path, mode: node.transport.mode, ...(endpoint.host ? { host: endpoint.host } : {}) };
    if (endpoint.security === "tls") stream.tlsSettings = { serverName: endpoint.serverName, fingerprint: "chrome",
      ...(endpoint.certificatePin ? { pinnedPeerCertSha256: endpoint.certificatePin } : {}), ...(endpoint.alpn.length ? { alpn: endpoint.alpn } : {}) };
    if (endpoint.security === "reality") stream.realitySettings = { serverName: endpoint.serverName, fingerprint: "chrome", password: node.tls.reality.publicKey, shortId: node.tls.reality.shortId };
    return { format: "xray", config: {
      log: { loglevel: "warning" },
      inbounds: [{ tag: "local-socks", listen: "127.0.0.1", port: 1080, protocol: "socks", settings: { auth: "noauth", udp: true } }],
      outbounds: [{ tag: "proxy", protocol: "vless", settings: { vnext: [{ address: endpoint.address, port: endpoint.port,
        users: [{ id: node.uuid, encryption: node.vlessEncryption, ...(node.flow ? { flow: node.flow } : {}) }] }] }, streamSettings: stream }],
    } };
  }
  const outbound: Record<string, unknown> = { type: node.protocol, tag: "proxy", server: endpoint.address, server_port: endpoint.port };
  if (["vmess", "tuic"].includes(node.protocol)) outbound.uuid = node.uuid;
  if (node.protocol !== "vmess") outbound.password = node.password;
  if (node.protocol === "vmess") { outbound.security = node.vmessSecurity; outbound.alter_id = 0; }
  if (node.protocol === "shadowsocks") outbound.method = node.method;
  if (["socks", "naive"].includes(node.protocol)) outbound.username = node.username;
  if (node.protocol === "socks") outbound.version = "5";
  if (node.transport.type === "ws") outbound.transport = { type: "ws", path: node.transport.path, ...(endpoint.host ? { headers: { Host: endpoint.host } } : {}) };
  if (node.transport.type === "grpc") outbound.transport = { type: "grpc", service_name: node.transport.serviceName };
  if (node.protocol === "hysteria2") {
    if (node.hy2.downMbps) outbound.up_mbps = node.hy2.downMbps;
    if (node.hy2.upMbps) outbound.down_mbps = node.hy2.upMbps;
    if (node.hy2.obfsPassword) outbound.obfs = { type: "salamander", password: node.hy2.obfsPassword };
  }
  if (node.protocol === "tuic") {
    outbound.congestion_control = node.tuic.congestionControl;
    outbound.zero_rtt_handshake = node.tuic.zeroRttHandshake;
    outbound.udp_relay_mode = "native";
  }
  if (endpoint.security !== "none") {
    const tls: Record<string, unknown> = { enabled: true, server_name: endpoint.serverName };
    if (node.protocol === "naive") {
      // Naive's Chromium TLS adapter cannot skip verification. An explicit
      // public trust certificate keeps self-signed exports usable and portable.
      if (endpoint.insecure) tls.certificate = node.tls.certificatePem.trim().split(/\r?\n/);
    } else {
      if (endpoint.security === "tls") tls.insecure = endpoint.insecure;
      if (endpoint.alpn.length) tls.alpn = endpoint.alpn;
      if (endpoint.security === "reality") {
        tls.utls = { enabled: true, fingerprint: "chrome" };
        tls.reality = { enabled: true, public_key: node.tls.reality.publicKey, short_id: node.tls.reality.shortId };
      }
    }
    outbound.tls = tls;
  }
  return { format: "sing-box", config: {
    log: { level: "warn", timestamp: true },
    dns: { servers: [{ type: "local", tag: "dns-local" }], final: "dns-local" },
    inbounds: [{ type: "mixed", tag: "local-in", listen: "127.0.0.1", listen_port: 1080 }],
    outbounds: [outbound], route: { final: "proxy", default_domain_resolver: "dns-local" },
  } };
}

export function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }

export function redact(text: string, secrets: string[]): string {
  let result = text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
  const variants = new Set(secrets.flatMap(secret => secret.split(/\r?\n/).concat(secret)).filter(secret => secret.length >= 4)
    .flatMap(secret => [secret, encodeURIComponent(secret), new URLSearchParams({ s: secret }).toString().slice(2), JSON.stringify(secret).slice(1, -1)]));
  for (const secret of [...variants].sort((a, b) => b.length - a.length)) result = result.split(secret).join("[REDACTED]");
  return result.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]")
    .replace(/\b(vmess:\/\/)[A-Za-z0-9+/_=-]+/gi, "$1[REDACTED]")
    .replace(/\b((?:vless|ss|trojan|hysteria2|hy2|tuic|anytls|socks5?|naive\+https):\/\/)[^@\s]+@/gi, "$1[REDACTED]@")
    .replace(/\b(ss:\/\/)[A-Za-z0-9+/_=-]+(?=$|[\s#])/gi, "$1[REDACTED]");
}

export class LineBuffer {
  private decoder = new coreDecoder.StringDecoder("utf8");
  private pending = "";
  private discarding = false;
  private callback: (line: string) => void;
  constructor(callback: (line: string) => void) { this.callback = callback; }
  feed(chunk: Uint8Array | string): void {
    this.pending += typeof chunk === "string" ? chunk : this.decoder.write(Buffer.from(chunk));
    if (this.discarding) {
      const end = this.pending.indexOf("\n");
      if (end < 0) { this.pending = ""; return; }
      this.pending = this.pending.slice(end + 1); this.discarding = false;
    }
    let index: number;
    while ((index = this.pending.indexOf("\n")) >= 0) {
      this.callback(index > 16384 ? "[超长日志行已丢弃]" : this.pending.slice(0, index).replace(/\r$/, ""));
      this.pending = this.pending.slice(index + 1);
    }
    // Discard the entire oversized line: splitting it could split a secret and bypass redaction.
    if (this.pending.length > 16384) {
      this.callback("[超长日志行已丢弃]"); this.pending = ""; this.discarding = true;
    }
  }
  end(): void { this.pending += this.decoder.end(); if (this.pending && !this.discarding) this.callback(this.pending.replace(/\r$/, "")); this.pending = ""; this.discarding = false; }
}

export interface CommandResult { code: number; stdout: string; stderr: string }
export async function runCommand(executable: string, args: string[], options: { cwd?: string; timeoutMs?: number; inherit?: boolean } = {}): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = coreCp.spawn(executable, args, { cwd: options.cwd, shell: false, windowsHide: !options.inherit, stdio: options.inherit ? "inherit" : ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      child.kill("SIGKILL");
      finished = true;
      reject(new Error(`命令执行超时：${corePath.basename(executable)}`));
    }, options.timeoutMs ?? 30000);
    child.stdout?.on("data", chunk => { stdout = (stdout + chunk.toString()).slice(-1024 * 1024); });
    child.stderr?.on("data", chunk => { stderr = (stderr + chunk.toString()).slice(-1024 * 1024); });
    child.once("error", error => { clearTimeout(timer); if (!finished) { finished = true; reject(error); } });
    child.once("close", code => { clearTimeout(timer); if (!finished) { finished = true; resolve({ code: code ?? 1, stdout, stderr }); } });
  });
}

export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const finish = () => { clearTimeout(timer); signal?.removeEventListener("abort", finish); resolve(); };
    const timer = setTimeout(finish, ms);
    signal?.addEventListener("abort", finish, { once: true });
  });
}


// ==================== address.ts ====================
import * as addressHttps from "node:https";
import * as addressHttp from "node:http";
import * as addressNet from "node:net";
import * as addressOs from "node:os";

export type AddressFamily = 4 | 6;
export interface PublicAddressResult {
  ipv4: string | null;
  ipv6: string | null;
  preferredAddress: string | null;
  source: { ipv4: string | null; ipv6: string | null };
  warnings: string[];
  cancelled: boolean;
  checkedAt: string;
}
export interface LocalAddressCandidate {
  address: string;
  family: AddressFamily;
  interfaceName: string;
  scope: "public" | "private" | "shared" | "link-local";
}
export interface AddressDetectionOptions { signal?: AbortSignal; timeoutMs?: number; requestTimeoutMs?: number }
export interface AddressTransportRequest {
  url: string;
  family: AddressFamily;
  signal: AbortSignal;
  timeoutMs: number;
  maxBodyBytes: number;
}
/** A transport returns only a bounded, complete HTTP 200 response body. */
export type AddressTransport = (request: AddressTransportRequest) => Promise<string>;
export type AddressHttpsRequest = (url: URL, options: addressHttps.RequestOptions, onResponse: (response: addressHttp.IncomingMessage) => void) => addressHttp.ClientRequest;

// Public, credential-free services with documented response formats:
// https://www.ipify.org/ (separate IPv4 / IPv6 APIs)
// https://docs.aws.amazon.com/batch/latest/userguide/create-a-base-security-group.html
// https://developers.cloudflare.com/privacy-proxy/get-started/ (trace's ip field)
const addressEndpoints = [
  { url: "https://api.ipify.org/?format=json", family: 4, format: "json" },
  { url: "https://checkip.amazonaws.com/", family: 4, format: "text" },
  { url: "https://api6.ipify.org/?format=json", family: 6, format: "json" },
  { url: "https://www.cloudflare.com/cdn-cgi/trace", family: 6, format: "trace" },
] as const;

const addressBodyLimit = 4096;
const addressReachabilityNotice = "检测到的是本机访问检测服务时的出口公网 IP，不代表该 IP 的端口已能从外部访问；NAT 仍需端口映射并放行防火墙，系统 VPN / TUN 也可能改变出口。";

function addressIpv4Number(value: string): number { return value.split(".").reduce((n, octet) => n * 256 + Number(octet), 0); }
function addressIpv4In(value: number, prefix: string, bits: number): boolean {
  const size = 2 ** (32 - bits);
  return Math.floor(value / size) === Math.floor(addressIpv4Number(prefix) / size);
}
function addressIpv6Number(value: string): bigint {
  // WHATWG canonicalization also converts an IPv4 tail to hexadecimal groups.
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const [left = "", right] = canonical.split("::");
  const before = left ? left.split(":") : [], after = right ? right.split(":") : [];
  const groups = right === undefined ? before : [...before, ...Array(8 - before.length - after.length).fill("0"), ...after];
  return groups.reduce((n, part) => (n << 16n) | BigInt(`0x${part}`), 0n);
}
function addressIpv6In(value: bigint, prefix: string, bits: number): boolean { return value >> BigInt(128 - bits) === addressIpv6Number(prefix) >> BigInt(128 - bits); }
function addressCanonical(value: string, family: AddressFamily): string { return family === 4 ? value : new URL(`http://[${value}]/`).hostname.slice(1, -1); }

/**
 * Accept ordinary global unicast addresses, excluding special-use ranges.
 * This is syntax/address-space validation, never proof of inbound reachability.
 * Registries checked for this release:
 * https://www.iana.org/assignments/iana-ipv4-special-registry/
 * https://www.iana.org/assignments/iana-ipv6-special-registry/
 */
export function isPublicIp(value: string): boolean {
  if (typeof value !== "string" || value.length > 45 || value !== value.trim() || value.includes("%")) return false;
  const family = addressNet.isIP(value);
  if (family === 4) {
    const n = addressIpv4Number(value);
    // These two specific anycast assignments are globally reachable exceptions.
    if (value === "192.0.0.9" || value === "192.0.0.10") return true;
    const excluded: [string, number][] = [
      ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
      ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
      ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
      ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
    ];
    return !excluded.some(([prefix, bits]) => addressIpv4In(n, prefix, bits));
  }
  if (family !== 6) return false;
  const n = addressIpv6Number(value);
  // Ordinary global unicast only: exclude mapped/translation addresses, ULA,
  // multicast, scoped addresses and non-global protocol reservations.
  if (!addressIpv6In(n, "2000::", 3)) return false;
  if (addressIpv6In(n, "2001:db8::", 32) || addressIpv6In(n, "3fff::", 20) || addressIpv6In(n, "2002::", 16)) return false;
  if (addressIpv6In(n, "2001::", 23)) {
    // Preserve global service assignments, while excluding Teredo, benchmark,
    // ORCHID and drone identifier space as server-address candidates.
    return ["2001:1::1", "2001:1::2", "2001:1::3"].some(ip => n === addressIpv6Number(ip))
      || addressIpv6In(n, "2001:3::", 32) || addressIpv6In(n, "2001:4:112::", 48);
  }
  return true;
}

function addressLocalScope(value: string, family: AddressFamily): LocalAddressCandidate["scope"] | null {
  if (isPublicIp(value)) return "public";
  if (family === 4) {
    const n = addressIpv4Number(value);
    if (addressIpv4In(n, "10.0.0.0", 8) || addressIpv4In(n, "172.16.0.0", 12) || addressIpv4In(n, "192.168.0.0", 16)) return "private";
    if (addressIpv4In(n, "100.64.0.0", 10)) return "shared";
    if (addressIpv4In(n, "169.254.0.0", 16)) return "link-local";
  } else {
    const n = addressIpv6Number(value);
    if (addressIpv6In(n, "fc00::", 7)) return "private";
    if (addressIpv6In(n, "fe80::", 10)) return "link-local";
  }
  return null;
}

/** Manual fallback candidates only; this never treats a LAN IP as a public IP. */
export function listLocalAddresses(interfaces: ReturnType<typeof addressOs.networkInterfaces> = addressOs.networkInterfaces()): LocalAddressCandidate[] {
  const candidates: LocalAddressCandidate[] = [], seen = new Set<string>();
  for (const [interfaceName, addresses] of Object.entries(interfaces).sort(([a], [b]) => a.localeCompare(b))) {
    for (const entry of addresses ?? []) {
      if (entry.internal || entry.address.includes("%")) continue;
      const family = addressNet.isIP(entry.address);
      if (family !== 4 && family !== 6) continue;
      const address = addressCanonical(entry.address, family), scope = addressLocalScope(address, family);
      if (!scope || seen.has(address)) continue;
      seen.add(address); candidates.push({ address, family, interfaceName, scope });
    }
  }
  const rank = { public: 0, private: 1, shared: 2, "link-local": 3 };
  return candidates.sort((a, b) => rank[a.scope] - rank[b.scope] || a.family - b.family || a.interfaceName.localeCompare(b.interfaceName) || a.address.localeCompare(b.address));
}

function addressMilliseconds(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 10_000) throw new Error(`${label} 必须是 1–10000 毫秒的整数。`);
  return value;
}

/**
 * Private HTTPS agents avoid global agents and HTTP(S)_PROXY/NODE_USE_ENV_PROXY.
 * No cookies, authorization, credentials, application config or request body are
 * sent. OS routing (including a VPN) still determines the actual egress path.
 * The optional request function is a mock boundary for offline transport tests.
 */
export function createHttpsAddressTransport(request: AddressHttpsRequest = addressHttps.request): AddressTransport {
  return async options => {
    if (!addressEndpoints.some(endpoint => endpoint.url === options.url && endpoint.family === options.family)) throw new Error("不在允许的公网 IP 检测服务列表中。");
    addressMilliseconds(options.timeoutMs, "单次探测超时");
    if (!Number.isInteger(options.maxBodyBytes) || options.maxBodyBytes < 1 || options.maxBodyBytes > addressBodyLimit) throw new Error("IP 检测响应体限制无效。");
    const agent = new addressHttps.Agent({ keepAlive: false, maxSockets: 1, proxyEnv: {} });
    return new Promise<string>((resolve, reject) => {
      let req: addressHttp.ClientRequest | undefined, response: addressHttp.IncomingMessage | undefined;
      let finished = false, length = 0;
      const chunks: Buffer[] = [];
      const finish = (error?: Error) => {
        if (finished) return;
        finished = true; clearTimeout(timer); options.signal.removeEventListener("abort", onAbort);
        response?.destroy(); req?.destroy(); agent.destroy();
        if (error) reject(error); else resolve(Buffer.concat(chunks, length).toString("utf8"));
      };
      const onAbort = () => finish(new Error("公网 IP 探测已取消。"));
      // Unlike a socket idle timeout, this also bounds DNS, TLS and slow bodies.
      const timer = setTimeout(() => finish(new Error("公网 IP 检测服务响应超时。")), options.timeoutMs);
      options.signal.addEventListener("abort", onAbort, { once: true });
      if (options.signal.aborted) { onAbort(); return; }
      try {
        req = request(new URL(options.url), {
          method: "GET", family: options.family, agent, rejectUnauthorized: true, maxHeaderSize: 8192,
          headers: { Accept: "text/plain, application/json", "Accept-Encoding": "identity", "User-Agent": "NexusEdge-IP-Check" },
        }, incoming => {
          response = incoming;
          incoming.on("error", () => finish(new Error("公网 IP 检测响应读取失败。")));
          incoming.once("aborted", () => finish(new Error("公网 IP 检测响应不完整。")));
          incoming.once("close", () => { if (!incoming.complete) finish(new Error("公网 IP 检测响应提前关闭。")); });
          if (finished) { incoming.destroy(); return; }
          // Deliberately do not follow redirects to another URL or a local host.
          if (incoming.statusCode !== 200) { finish(new Error(`公网 IP 检测服务返回 HTTP ${incoming.statusCode ?? 0}。`)); return; }
          const encoding = incoming.headers["content-encoding"], declared = incoming.headers["content-length"];
          if (encoding && encoding !== "identity") { finish(new Error("公网 IP 检测服务返回了不支持的压缩响应。")); return; }
          if (declared !== undefined && (typeof declared !== "string" || !/^\d+$/.test(declared) || Number(declared) > options.maxBodyBytes)) { finish(new Error("公网 IP 检测响应体过大或长度无效。")); return; }
          incoming.on("data", (chunk: Buffer | string) => {
            if (finished) return;
            const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
            length += bytes.length;
            if (length > options.maxBodyBytes) { finish(new Error("公网 IP 检测响应体过大。")); return; }
            chunks.push(bytes);
          });
          incoming.once("end", () => {
            if (declared !== undefined && Number(declared) !== length) { finish(new Error("公网 IP 检测响应长度不匹配。")); return; }
            finish();
          });
        });
        req.on("error", () => finish(new Error("无法连接公网 IP 检测服务。")));
        if (finished) { req.destroy(); return; }
        req.end();
      } catch { finish(new Error("无法发起公网 IP 检测请求。")); }
    });
  };
}

interface AddressObservation { address: string; source: string; systemWarp: boolean }
function addressParseResponse(endpoint: typeof addressEndpoints[number], body: string): AddressObservation | null {
  if (typeof body !== "string" || Buffer.byteLength(body, "utf8") > addressBodyLimit) return null;
  let value: unknown, systemWarp = false;
  if (endpoint.format === "json") {
    try { const decoded = JSON.parse(body); value = decoded && !Array.isArray(decoded) && typeof decoded === "object" ? decoded.ip : null; } catch { return null; }
  } else if (endpoint.format === "trace") {
    const lines = body.split(/\r?\n/), ips = lines.filter(line => line.startsWith("ip="));
    if (ips.length !== 1) return null;
    value = ips[0]!.slice(3); systemWarp = lines.includes("warp=on") || lines.includes("warp=plus");
  } else value = body.trim();
  if (typeof value !== "string" || !isPublicIp(value) || addressNet.isIP(value) !== endpoint.family) return null;
  return { address: addressCanonical(value, endpoint.family), source: endpoint.url, systemWarp };
}

function addressProbeFamily(family: AddressFamily, signal: AbortSignal, timeoutMs: number, transport: AddressTransport): Promise<AddressObservation | null> {
  const endpoints = addressEndpoints.filter(endpoint => endpoint.family === family);
  const controller = new AbortController();
  return new Promise(resolve => {
    let finished = false, remaining = endpoints.length;
    const finish = (result: AddressObservation | null) => {
      if (finished) return;
      finished = true; signal.removeEventListener("abort", onAbort);
      controller.abort(); resolve(result);
    };
    const onAbort = () => finish(null);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) { onAbort(); return; }
    for (const endpoint of endpoints) void (async () => {
      try {
        const body = await transport({ url: endpoint.url, family, signal: controller.signal, timeoutMs, maxBodyBytes: addressBodyLimit });
        if (!finished) { const observation = addressParseResponse(endpoint, body); if (observation) finish(observation); }
      } catch { /* Other providers and the other address family remain usable. */ }
      finally { if (--remaining === 0) finish(null); }
    })();
  });
}

/**
 * Probe both families concurrently, select IPv4 when available, otherwise IPv6.
 * An IPv4 success cancels all remaining probes immediately: ipv6=null can mean
 * "not needed / cancelled", and must not be displayed as "no IPv6 support".
 * Network failures return an empty result with guidance, not a guessed address.
 */
export async function detectPublicAddresses(options: AddressDetectionOptions = {}, transport: AddressTransport = createHttpsAddressTransport()): Promise<PublicAddressResult> {
  const timeoutMs = addressMilliseconds(options.timeoutMs ?? 3000, "探测总超时");
  const requestTimeoutMs = Math.min(timeoutMs, addressMilliseconds(options.requestTimeoutMs ?? 2000, "单次探测超时"));
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let v4: AddressObservation | null = null, v6: AddressObservation | null = null;
  try {
    const fourth = addressProbeFamily(4, controller.signal, requestTimeoutMs, transport);
    const sixth = addressProbeFamily(6, controller.signal, requestTimeoutMs, transport).then(result => { v6 = result; return result; });
    v4 = await fourth;
    if (v4) controller.abort();
    await sixth;
  } finally {
    clearTimeout(timer); options.signal?.removeEventListener("abort", onAbort); controller.abort();
  }
  const observed6 = v6 as AddressObservation | null;
  const cancelled = options.signal?.aborted === true;
  const preferredAddress = cancelled ? null : v4?.address ?? observed6?.address ?? null;
  const warnings: string[] = [];
  if (cancelled) warnings.push("已取消公网 IP 探测。");
  else if (!preferredAddress) warnings.push("未探测到可用公网 IP。请在 VPS 控制台确认公网 IP 后手动输入，或选择明确标注的本机网卡地址用于局域网连接。");
  else {
    warnings.push(addressReachabilityNotice);
    if (!v4 && observed6) warnings.push("本次仅识别到 IPv6；连接此节点的客户端网络也需要支持 IPv6。");
    if ((v4 ?? observed6)?.systemWarp) warnings.push("检测服务报告系统 WARP 正在生效；该地址可能是 WARP 出口，请在 VPS 控制台核对用于入站连接的公网 IP。");
  }
  return { ipv4: v4?.address ?? null, ipv6: observed6?.address ?? null, preferredAddress,
    source: { ipv4: v4?.source ?? null, ipv6: observed6?.source ?? null }, warnings, cancelled, checkedAt: new Date().toISOString() };
}


// ==================== presets.ts ====================
import { randomBytes as presetRandomBytes } from "node:crypto";
import { isIP as presetIsIP } from "node:net";

/** User-facing protocol choices; detailed transport options remain in advanced settings. */
export const SIMPLE_PROTOCOL_LABELS: Record<NodeProtocol, string> = {
  vless: "VLESS · TCP + REALITY + Vision",
  vmess: "VMess · WebSocket",
  shadowsocks: "Shadowsocks · SS2022",
  trojan: "Trojan · TLS",
  hysteria2: "Hysteria2 · UDP + TLS",
  tuic: "TUIC · UDP + TLS",
  anytls: "AnyTLS · TLS",
  socks: "SOCKS5 · 用户名 / 密码",
  naive: "Naive · HTTP/2 + TLS",
};

const SIMPLE_REALITY_SERVER = "apple.com";

function presetReality(node: NodeConfig): void {
  const reality = node.tls.reality;
  const hadPrivateKey = Boolean(reality.privateKey);
  // The TLS name from an earlier ordinary TLS configuration is not necessarily
  // a usable REALITY target. Retain a previous REALITY target/name as a pair.
  if (!reality.handshakeServer) {
    reality.handshakeServer = SIMPLE_REALITY_SERVER;
    reality.handshakePort = 443;
    node.tls.serverName = SIMPLE_REALITY_SERVER;
  } else if (!node.tls.serverName) {
    node.tls.serverName = presetIsIP(reality.handshakeServer) ? SIMPLE_REALITY_SERVER : reality.handshakeServer;
  }
  if (reality.privateKey) {
    if (!reality.publicKey) reality.publicKey = deriveRealityPublicKey(reality.privateKey);
  } else {
    Object.assign(reality, generateRealityKeyPair());
  }
  // An empty short ID is a valid existing REALITY credential. Only give new
  // key material an automatic short ID; a route change must not rotate it.
  if (!reality.shortId && !hadPrivateKey) reality.shortId = presetRandomBytes(8).toString("hex");
  node.transport.type = "tcp";
  node.tls.mode = "reality";
  node.flow = "xtls-rprx-vision";
}

/**
 * Create a draft without downloading cores, generating certificates, or probing
 * the network. The panel supplies an address and any certificate before saving.
 */
export function createSimpleNode(protocol: NodeProtocol, existingNodes: NodeConfig[] = []): NodeConfig {
  const node = createDefaultNode(protocol, existingNodes);
  if (protocol === "vless") presetReality(node);
  if (protocol === "vmess") node.transport.type = "ws";
  if (node.tls.mode === "tls") {
    node.tls.serverName = "nexus.local";
    node.tls.insecure = true;
    node.tls.alpn = protocol === "hysteria2" || protocol === "tuic" ? ["h3"]
      : protocol === "naive" ? ["h2"] : ["h2", "http/1.1"];
  }
  return node;
}

/**
 * Apply an explicit simple-mode route change to a detached draft. Adding a
 * tunnel or switching quick ↔ fixed retains a previously chosen direct route.
 * Existing tunnel credentials and dormant transport/security fields are kept.
 */
export function applySimpleTunnel(node: NodeConfig, mode: NodeConfig["tunnel"]["mode"]): NodeConfig {
  const next = structuredClone(node);
  const previousMode = next.tunnel.mode;
  if (mode === previousMode) return next;
  if (mode !== "none" && next.protocol !== "vless" && next.protocol !== "vmess") {
    throw new Error("Cloudflare 隧道仅适用于 VLESS / VMess WebSocket 节点。");
  }
  next.tunnel.mode = mode;
  if (mode === "none") {
    next.direct = true;
    if (next.listen === "::1") next.listen = "::";
    else if (next.listen === "127.0.0.1") next.listen = "0.0.0.0";
    if (next.protocol === "vless") presetReality(next);
  } else if (previousMode === "none") {
    if (!next.direct) next.listen = presetIsIP(next.listen) === 6 ? "::1" : "127.0.0.1";
    next.transport.type = "ws";
    if (!next.transport.path) next.transport.path = "/nexus-ws";
    next.tls.mode = "none";
    next.flow = "";
  }
  return next;
}


// ==================== network.ts ====================
import * as networkFs from "node:fs";
import * as networkPath from "node:path";
import * as networkCrypto from "node:crypto";
import * as networkNet from "node:net";
import * as networkZlib from "node:zlib";
import * as networkSqlite from "bun:sqlite";

export interface NetworkAsset {
  asset: string;
  archive: "tar.gz" | "zip" | "binary";
  sha256: string;
  directory?: string;
  executable: string;
  files: Record<string, string>;
}

// Official release archive hashes were checked against GitHub's release asset digest.
// File hashes below were computed ONLY after verifying those fixed archive hashes.
// Keeping the extracted hashes here also authenticates the installed cache without
// trusting a mutable receipt next to the executable. Preserve upstream LICENSEs.
export const NETWORK_RELEASES = {
  singBox: {
    version: "1.14.3",
    prerelease: false,
    release: "https://github.com/SagerNet/sing-box/releases/tag/v1.14.3",
    base: "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/",
    assets: {
      "linux-x64": {
        asset: "sing-box-1.14.3-linux-amd64.tar.gz", archive: "tar.gz",
        sha256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
        directory: "sing-box-1.14.3-linux-amd64", executable: "sing-box",
        files: {
          "sing-box": "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93",
          "libcronet.so": "23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294",
          LICENSE: "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
        },
      },
      "linux-arm64": {
        asset: "sing-box-1.14.3-linux-arm64.tar.gz", archive: "tar.gz",
        sha256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
        directory: "sing-box-1.14.3-linux-arm64", executable: "sing-box",
        files: {
          "sing-box": "299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689",
          "libcronet.so": "3c1fcfcb56261a4b318ffb6d2227b9726782edb5a894e74db2b534406db62498",
          LICENSE: "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
        },
      },
      "win32-x64": {
        asset: "sing-box-1.14.3-windows-amd64.zip", archive: "zip",
        sha256: "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
        directory: "sing-box-1.14.3-windows-amd64", executable: "sing-box.exe",
        files: {
          "sing-box.exe": "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf",
          "libcronet.dll": "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928",
          LICENSE: "bb3805862b583aee73ad6f7805ec634747a37257a637a3069857843f05ea589c",
        },
      },
    } as Record<string, NetworkAsset>,
  },
  xray: {
    "version": "26.3.27",
    "prerelease": false,
    "release": "https://github.com/XTLS/Xray-core/releases/tag/v26.3.27",
    "base": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/",
    "assets": {
      "linux-x64": {
        "asset": "Xray-linux-64.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray",
        "sha256": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        "files": {
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "xray": "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      },
      "linux-arm64": {
        "asset": "Xray-linux-arm64-v8a.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray",
        "sha256": "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
        "files": {
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "xray": "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      },
      "win32-x64": {
        "asset": "Xray-windows-64.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray.exe",
        "sha256": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
        "files": {
          "xray_no_window.ps1": "82f62d3edaea84dc1abc395f71815781a4b9b934b2ecefd9f9f7ec7f770651eb",
          "xray.exe": "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1",
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "wintun.dll": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
          "xray_no_window.vbs": "141814ac8083e9dc53c1cc3c3b13160476f2fb9585dfa63c4010ed8c2926bd95",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "LICENSE-wintun.txt": "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      }
    } as Record<string, NetworkAsset>
  },
  cloudflared: {
    version: "2026.10.2",
    prerelease: false,
    release: "https://github.com/cloudflare/cloudflared/releases/tag/2026.10.2",
    base: "https://github.com/cloudflare/cloudflared/releases/download/2026.10.2/",
    assets: {
      "linux-x64": {
        asset: "cloudflared-linux-amd64", archive: "binary", executable: "cloudflared",
        sha256: "35fbdd2beb378436c7da377d7358cea8e33f9c94a6705d1d8036bf9b0d6d8005",
        files: { cloudflared: "35fbdd2beb378436c7da377d7358cea8e33f9c94a6705d1d8036bf9b0d6d8005" },
      },
      "linux-arm64": {
        asset: "cloudflared-linux-arm64", archive: "binary", executable: "cloudflared",
        sha256: "b7e55b4d9702c2ab5f8348f780bb1db044527fc555367714c78e0595750a4665",
        files: { cloudflared: "b7e55b4d9702c2ab5f8348f780bb1db044527fc555367714c78e0595750a4665" },
      },
      "win32-x64": {
        asset: "cloudflared-windows-amd64.exe", archive: "binary", executable: "cloudflared.exe",
        sha256: "12c7c887f8aaab779aef1dfa9b60673530a5adb88ecc55dd6df8f56e0b70f199",
        files: { "cloudflared.exe": "12c7c887f8aaab779aef1dfa9b60673530a5adb88ecc55dd6df8f56e0b70f199" },
      },
    } as Record<string, NetworkAsset>,
  },
} as const;

export type BinaryKind = "singBox" | "xray" | "cloudflared";
export type Binaries = Partial<Record<BinaryKind, string>>;
export type CoreUpdateChannel = "stable" | "preview";
export interface CoreRelease {
  tool: BinaryKind;
  version: string;
  tag: string;
  platform: string;
  prerelease: boolean;
  source: "bundled" | "github";
  downloadUrl: string;
  releaseUrl: string;
  asset: NetworkAsset;
}
export type CoreReleaseCandidate = Omit<CoreRelease, "asset"> & {
  asset: Omit<NetworkAsset, "files"> & { files?: Record<string, string> };
};
export type CoreReleaseMap = Record<BinaryKind, CoreRelease>;
export interface CoreSelectionState {
  schema: 1;
  active: CoreReleaseMap;
  previous?: CoreReleaseMap;
  updatedAt?: string;
}
export interface CoreUpdateCheck {
  tool: BinaryKind;
  current: CoreRelease;
  latest?: CoreReleaseCandidate;
  updateAvailable: boolean;
  error?: string;
}

const networkCoreKinds: readonly BinaryKind[] = ["singBox", "xray", "cloudflared"];
const networkCoreRepositories: Record<BinaryKind, string> = {
  singBox: "SagerNet/sing-box", xray: "XTLS/Xray-core", cloudflared: "cloudflare/cloudflared",
};
const networkCorePlatforms = ["linux-x64", "linux-arm64", "win32-x64"];
const networkVersionPattern = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const networkSha256Pattern = /^[a-f0-9]{64}$/;

export function coreReleaseLabel(tool: BinaryKind): string {
  return tool === "singBox" ? "sing-box" : tool === "xray" ? "Xray" : "cloudflared";
}

function networkVersion(value: unknown): string {
  if (typeof value !== "string" || value.length > 80 || !networkVersionPattern.test(value)) throw new Error("内核版本号格式无效。");
  return value;
}

/** Numeric release ordering, including SemVer prerelease identifiers. Never lexically sort dates. */
export function compareCoreVersions(left: string, right: string): number {
  const parse = (value: string): { core: number[]; suffix: string[] } => {
    const checked = networkVersion(value), dash = checked.indexOf("-");
    return { core: (dash < 0 ? checked : checked.slice(0, dash)).split(".").map(Number), suffix: dash < 0 ? [] : checked.slice(dash + 1).split(".") };
  };
  const a = parse(left), b = parse(right);
  for (let i = 0; i < 3; i++) if (a.core[i] !== b.core[i]) return a.core[i]! > b.core[i]! ? 1 : -1;
  if (!a.suffix.length || !b.suffix.length) return a.suffix.length ? -1 : b.suffix.length ? 1 : 0;
  for (let i = 0; i < Math.max(a.suffix.length, b.suffix.length); i++) {
    const aa = a.suffix[i], bb = b.suffix[i];
    if (aa === undefined || bb === undefined) return aa === undefined ? -1 : 1;
    if (aa === bb) continue;
    const an = /^\d+$/.test(aa), bn = /^\d+$/.test(bb);
    if (an && bn) { const ai = BigInt(aa), bi = BigInt(bb); if (ai !== bi) return ai > bi ? 1 : -1; }
    else if (an !== bn) return an ? -1 : 1;
    else return aa > bb ? 1 : -1;
  }
  return 0;
}

function networkCoreTag(tool: BinaryKind, version: string): string { return tool === "cloudflared" ? version : `v${version}`; }

function networkCoreLayout(tool: BinaryKind, version: string, platform: string): Omit<NetworkAsset, "sha256" | "files"> {
  if (!networkCorePlatforms.includes(platform)) throw new Error(`没有适配 ${platform} 的官方内核发行包。`);
  const windows = platform === "win32-x64", arch = platform === "linux-arm64" ? "arm64" : "amd64";
  if (tool === "singBox") {
    const directory = `sing-box-${version}-${windows ? "windows" : "linux"}-${arch}`;
    return { asset: `${directory}.${windows ? "zip" : "tar.gz"}`, archive: windows ? "zip" : "tar.gz", directory, executable: windows ? "sing-box.exe" : "sing-box" };
  }
  if (tool === "xray") return { asset: windows ? "Xray-windows-64.zip" : platform === "linux-arm64" ? "Xray-linux-arm64-v8a.zip" : "Xray-linux-64.zip", archive: "zip", directory: "", executable: windows ? "xray.exe" : "xray" };
  return { asset: `cloudflared-${windows ? "windows" : "linux"}-${arch}${windows ? ".exe" : ""}`, archive: "binary", executable: windows ? "cloudflared.exe" : "cloudflared" };
}

function networkSafeReleaseFile(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name) && !name.endsWith(".") && !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(name);
}

function networkValidateFiles(value: unknown, executable: string, archive: NetworkAsset["archive"]): Record<string, string> {
  const object = networkObject(value, "内核文件校验清单"), entries = Object.entries(object);
  if (!entries.length || entries.length > 128) throw new Error("内核文件校验清单为空或过大。");
  const seen = new Set<string>();
  const files: Record<string, string> = {};
  for (const [name, hash] of entries) {
    if (!networkSafeReleaseFile(name) || seen.has(name.toLowerCase()) || typeof hash !== "string" || !networkSha256Pattern.test(hash)) throw new Error("内核文件名或 SHA-256 校验值无效。");
    seen.add(name.toLowerCase()); files[name] = hash;
  }
  if (!Object.hasOwn(files, executable) || (archive !== "binary" && !Object.hasOwn(files, "LICENSE"))) throw new Error("内核文件清单缺少可执行文件或许可证。");
  if (archive === "binary" && entries.length !== 1) throw new Error("单文件发行包的校验清单无效。");
  return files;
}

function networkValidateCandidate(value: unknown, requireFiles = false): CoreReleaseCandidate {
  const object = networkObject(value, "内核版本"), tool = object.tool as BinaryKind;
  if (!networkCoreKinds.includes(tool)) throw new Error("内核名称无效。");
  const version = networkVersion(object.version), tag = networkCoreTag(tool, version);
  const platform = object.platform;
  if (typeof platform !== "string" || !networkCorePlatforms.includes(platform)) throw new Error("内核平台无效。");
  if (object.source !== "bundled" && object.source !== "github") throw new Error("内核版本来源无效。");
  if (object.tag !== tag || typeof object.prerelease !== "boolean") throw new Error("内核发行标签无效。");
  const releaseUrl = `https://github.com/${networkCoreRepositories[tool]}/releases/tag/${tag}`;
  let layout = networkCoreLayout(tool, version, platform);
  // The bundled manifest is also a public fixture seam used to validate Windows ZIPs on Linux.
  // Actual user-selected GitHub releases always use the canonical platform layout above.
  const bundled = NETWORK_RELEASES[tool];
  if (object.source === "bundled" && version === bundled.version && bundled.assets[platform]) {
    const { sha256: _hash, files: _files, ...bundledLayout } = bundled.assets[platform]!;
    layout = bundledLayout;
  }
  const assetObject = networkObject(object.asset, "内核发行文件");
  for (const key of ["asset", "archive", "directory", "executable"] as const) if (assetObject[key] !== layout[key]) throw new Error("内核发行文件不符合官方平台目录布局。");
  const downloadUrl = `https://github.com/${networkCoreRepositories[tool]}/releases/download/${tag}/${layout.asset}`;
  if (object.downloadUrl !== downloadUrl || object.releaseUrl !== releaseUrl) throw new Error("内核下载地址必须是对应官方仓库的固定发行文件。");
  if (typeof assetObject.sha256 !== "string" || !networkSha256Pattern.test(assetObject.sha256)) throw new Error("内核发行包缺少有效 SHA-256 校验值。");
  const files = assetObject.files === undefined && !requireFiles ? undefined : networkValidateFiles(assetObject.files, layout.executable, layout.archive);
  if (object.source === "bundled" && version === bundled.version) {
    const pinned = bundled.assets[platform]!;
    if (assetObject.sha256 !== pinned.sha256 || (files && (Object.keys(files).length !== Object.keys(pinned.files).length || Object.entries(pinned.files).some(([name, hash]) => files[name] !== hash)))) throw new Error("内置版本的 SHA-256 必须与脚本中已验证的官方清单一致。");
  }
  return { tool, version, tag, platform, prerelease: object.prerelease, source: object.source, downloadUrl, releaseUrl, asset: { ...layout, sha256: assetObject.sha256, ...(files ? { files } : {}) } };
}

function networkBundledCoreMap(): CoreReleaseMap {
  const platform = `${process.platform}-${process.arch}`;
  return Object.fromEntries(networkCoreKinds.map(tool => {
    const release = NETWORK_RELEASES[tool], asset = release.assets[platform];
    if (!asset) throw new Error(`没有适配 ${platform} 的固定官方 ${tool} 发行包。`);
    return [tool, { tool, version: release.version, tag: networkCoreTag(tool, release.version), platform,
      prerelease: release.prerelease, source: "bundled", downloadUrl: release.base + asset.asset, releaseUrl: release.release,
      asset: { ...asset, files: { ...asset.files } } } satisfies CoreRelease];
  })) as CoreReleaseMap;
}

function networkValidateCoreMap(value: unknown): CoreReleaseMap {
  const object = networkObject(value, "内核版本集合");
  if (Object.keys(object).length !== networkCoreKinds.length) throw new Error("内核版本集合必须包含三种内核。");
  const platform = `${process.platform}-${process.arch}`;
  return Object.fromEntries(networkCoreKinds.map(tool => {
    const release = networkValidateCandidate(object[tool], true) as CoreRelease;
    if (release.tool !== tool || release.platform !== platform) throw new Error("内核版本集合与本机平台或内核名称不一致。");
    return [tool, release];
  })) as CoreReleaseMap;
}

function networkValidateSelection(value: unknown): CoreSelectionState {
  const object = networkObject(value, "内核版本记录");
  if (object.schema !== 1) throw new Error("不支持此内核版本记录格式。");
  if (object.updatedAt !== undefined && (typeof object.updatedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(object.updatedAt) || !Number.isFinite(Date.parse(object.updatedAt)))) throw new Error("内核更新时间无效。");
  return { schema: 1, active: networkValidateCoreMap(object.active), ...(object.previous === undefined ? {} : { previous: networkValidateCoreMap(object.previous) }), ...(object.updatedAt === undefined ? {} : { updatedAt: object.updatedAt as string }) };
}

export function coreSelectionPath(paths: AppPaths): string { return networkPath.join(paths.bin, "core-versions.json"); }

/** Local selection is protected like node configuration. Archive hashes come from the official API;
 * extracted file hashes are recorded only after those archive hashes have been verified. */
export function readCoreSelection(paths: AppPaths): CoreSelectionState {
  const file = coreSelectionPath(paths);
  let stat: networkFs.Stats;
  try { stat = networkFs.lstatSync(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { schema: 1, active: networkBundledCoreMap() }; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 256 * 1024) throw new Error("内核版本记录不是普通文件或大小异常，已停止读取。");
  try { return networkValidateSelection(JSON.parse(networkFs.readFileSync(file, "utf8"))); }
  catch (error) { throw new Error(`内核版本记录无效，请从备份恢复 ${file}：${error instanceof Error ? error.message : String(error)}`); }
}

export function writeCoreSelection(paths: AppPaths, state: CoreSelectionState): void {
  const checked = networkValidateSelection(state);
  ensureDataDir(paths);
  const file = coreSelectionPath(paths);
  try { const stat = networkFs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("拒绝覆盖异常内核版本记录。"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  atomicWrite(file, JSON.stringify(checked, null, 2) + "\n");
}

/** Shared by initial pin snapshots and explicit upgrade/rollback transactions. */
export function acquireCoreSelectionLock(paths: AppPaths): () => void {
  ensureDataDir(paths);
  const file = networkPath.join(paths.data, "core-update-lock.sqlite");
  for (const name of [file, `${file}-journal`, `${file}-wal`, `${file}-shm`]) {
    try {
      const stat = networkFs.lstatSync(name);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("内核更新锁不能是链接或特殊文件。");
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  const db = new networkSqlite.Database(file, { create: true });
  try {
    db.exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;");
    if (process.platform !== "win32") networkFs.chmodSync(file, 0o600);
  } catch (error) {
    db.close();
    if (/busy|locked/i.test(error instanceof Error ? error.message : String(error))) throw new Error("同一数据目录已有内核更新或回退正在进行，请等待其结束。");
    throw error;
  }
  let released = false;
  return () => { if (released) return; released = true; try { db.exec("ROLLBACK;"); } finally { db.close(); } };
}

/** Freeze first-use defaults so a later script update cannot silently switch core versions.
 * Read-only menus and explicit candidate preparation do not call this initializer. */
export function initializeCoreSelection(paths: AppPaths): CoreSelectionState {
  const file = coreSelectionPath(paths);
  const exists = (): boolean => { try { networkFs.lstatSync(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; } };
  if (exists()) return readCoreSelection(paths);
  const release = acquireCoreSelectionLock(paths);
  try {
    if (exists()) return readCoreSelection(paths);
    const initial = readCoreSelection(paths); writeCoreSelection(paths, initial); return initial;
  } finally { release(); }
}

export function coreReleaseFingerprint(releases: CoreReleaseMap): string {
  const values = networkCoreKinds.map(tool => {
    const release = releases[tool];
    return [tool, release.version, release.tag, release.platform, release.source, release.prerelease, release.downloadUrl, release.releaseUrl,
      release.asset.asset, release.asset.archive, release.asset.directory ?? null, release.asset.executable, release.asset.sha256,
      Object.entries(release.asset.files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)];
  });
  return networkCrypto.createHash("sha256").update(JSON.stringify(values)).digest("hex");
}

export function coreBinaryPath(paths: AppPaths, release: CoreRelease): string {
  const checked = networkValidateCandidate(release, true) as CoreRelease;
  const suffix = checked.source === "github" ? `-${checked.asset.sha256.slice(0, 16)}` : "";
  return networkPath.join(paths.bin, `${checked.tool}-${checked.version}-${checked.platform}${suffix}`, checked.asset.executable);
}

async function networkGitHubJson(apiPath: string): Promise<unknown> {
  const response = await fetch(`https://api.github.com/${apiPath}`, {
    headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "NexusEdge-core-updater" },
    signal: AbortSignal.timeout(25_000), redirect: "error",
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel().catch(() => {});
    if (response.status === 403 || response.status === 429) throw new Error("GitHub 暂时限制更新查询，请稍后重试；现有版本不受影响。");
    throw new Error(`官方版本查询失败：HTTP ${response.status}。`);
  }
  const limit = 16 * 1024 * 1024;
  if (Number(response.headers.get("content-length")) > limit) { await response.body.cancel(); throw new Error("官方版本列表超过大小限制。"); }
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > limit) throw new Error("官方版本列表超过大小限制。");
      chunks.push(value);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new Error("官方版本查询没有返回有效 JSON。"); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

function networkReleaseVersion(metadata: unknown): string | null {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
  const object = metadata as Record<string, unknown>;
  if (object.draft !== false || typeof object.prerelease !== "boolean" || typeof object.tag_name !== "string") return null;
  const version = object.tag_name.replace(/^v/, "");
  return version.length <= 80 && networkVersionPattern.test(version) ? version : null;
}

function networkCandidateFromMetadata(tool: BinaryKind, metadata: unknown): CoreReleaseCandidate {
  const object = networkObject(metadata, "官方发行信息"), version = networkReleaseVersion(object);
  if (!version) throw new Error("官方发行尚未公开或版本标签不受支持。");
  const platform = `${process.platform}-${process.arch}`, tag = networkCoreTag(tool, version), layout = networkCoreLayout(tool, version, platform);
  if (object.tag_name !== tag || !Array.isArray(object.assets)) throw new Error("官方发行标签或资产列表无效。");
  const matches = object.assets.filter(asset => asset && typeof asset === "object" && (asset as Record<string, unknown>).name === layout.asset) as Record<string, unknown>[];
  if (matches.length !== 1) throw new Error(`官方 ${version} 没有唯一的 ${platform} 发行包（${layout.asset}）。`);
  const asset = matches[0]!, digest = asset.digest;
  if (typeof digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("官方发行包未提供可验证的 SHA-256 digest，已拒绝无校验更新。");
  if (typeof asset.size === "number" && (asset.size <= 0 || asset.size > 160 * 1024 * 1024)) throw new Error("官方发行包大小异常或超过限制。");
  return networkValidateCandidate({ tool, version, tag, platform, prerelease: object.prerelease === true || version.includes("-"), source: "github",
    downloadUrl: asset.browser_download_url, releaseUrl: object.html_url,
    asset: { ...layout, sha256: digest.slice(7) } });
}

/** Advanced explicit version selection; only canonical tags in the three official repositories. */
export async function fetchCoreRelease(tool: BinaryKind, versionOrTag: string): Promise<CoreReleaseCandidate> {
  if (!networkCoreKinds.includes(tool)) throw new Error("内核名称无效。");
  const version = networkVersion(versionOrTag.trim().replace(/^v/, "")), tag = networkCoreTag(tool, version);
  const candidate = networkCandidateFromMetadata(tool, await networkGitHubJson(`repos/${networkCoreRepositories[tool]}/releases/tags/${tag}`));
  if (candidate.tag !== tag) throw new Error("官方返回的发行版本与所选版本不一致。");
  return candidate;
}

/** Version checks are opt-in. Failed or older channels never replace the selected version. */
export async function checkCoreUpdates(paths: AppPaths, channel: CoreUpdateChannel = "stable"): Promise<CoreUpdateCheck[]> {
  if (channel !== "stable" && channel !== "preview") throw new Error("更新通道无效。");
  const selected = readCoreSelection(paths).active;
  return await Promise.all(networkCoreKinds.map(async tool => {
    const current = selected[tool];
    try {
      const metadata = await networkGitHubJson(`repos/${networkCoreRepositories[tool]}/releases${channel === "stable" ? "/latest" : "?per_page=30"}`);
      let chosen: unknown = metadata;
      if (channel === "preview") {
        if (!Array.isArray(metadata)) throw new Error("官方预览版本列表格式无效。");
        const candidates = metadata.map(value => ({ value, version: networkReleaseVersion(value) })).filter(item => item.version !== null);
        candidates.sort((a, b) => compareCoreVersions(b.version!, a.version!));
        if (!candidates.length) throw new Error("官方仓库暂未提供可用发行版本。");
        chosen = candidates[0]!.value;
      }
      const latest = networkCandidateFromMetadata(tool, chosen);
      if (channel === "stable" && latest.prerelease) throw new Error("官方稳定通道返回预览版本，已停止自动选择。");
      return { tool, current, latest, updateAvailable: compareCoreVersions(latest.version, current.version) > 0 };
    } catch (error) { return { tool, current, updateAvailable: false, error: error instanceof Error ? error.message : String(error) }; }
  }));
}

async function networkFileHash(path: string): Promise<string> {
  const digest = networkCrypto.createHash("sha256");
  for await (const chunk of networkFs.createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

async function networkCacheMatches(directory: string, asset: NetworkAsset): Promise<boolean> {
  try {
    const dir = networkFs.lstatSync(directory);
    if (!dir.isDirectory() || dir.isSymbolicLink()) return false;
    const actualNames = networkFs.readdirSync(directory).sort();
    const expectedNames = Object.keys(asset.files).sort();
    if (actualNames.length !== expectedNames.length || actualNames.some((name, index) => name !== expectedNames[index])) return false;
    for (const [name, expected] of Object.entries(asset.files)) {
      const path = networkPath.join(directory, name);
      const file = networkFs.lstatSync(path);
      if (!file.isFile() || file.isSymbolicLink() || await networkFileHash(path) !== expected) return false;
    }
    return true;
  } catch { return false; }
}

async function networkDownload(url: string, path: string, expectedHash: string): Promise<void> {
  const response = await fetch(url, { signal: AbortSignal.timeout(120_000), redirect: "follow" });
  if (!response.ok || !response.body) throw new Error(`官方下载失败：HTTP ${response.status}`);
  const maxBytes = 160 * 1024 * 1024;
  if (Number(response.headers.get("content-length")) > maxBytes) {
    await response.body.cancel();
    throw new Error("下载文件超过本版本的大小限制。");
  }
  const fd = networkFs.openSync(path, "wx", 0o600);
  const reader = response.body.getReader();
  const digest = networkCrypto.createHash("sha256");
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error("下载文件超过本版本的大小限制。");
      digest.update(value);
      let offset = 0;
      while (offset < value.byteLength) offset += networkFs.writeSync(fd, value, offset, value.byteLength - offset);
    }
    networkFs.fsyncSync(fd);
    if (digest.digest("hex") !== expectedHash) throw new Error("下载文件 SHA-256 与官方发行包不符，已拒绝安装。");
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
    networkFs.closeSync(fd);
  }
}

/** Official archives are flat under a known root. Reject new/ambiguous layouts instead of
 * extracting paths, links, devices, or undeclared executable dependencies outside that root. */
function networkArchiveTarget(sourceName: string, directory: string | undefined, isDirectory: boolean): string | null {
  const source = sourceName.startsWith("./") ? sourceName.slice(2) : sourceName;
  if (source.includes("\\") || source.includes("\0") || source.startsWith("/")) throw new Error("发行包包含不安全的路径。");
  if (isDirectory) {
    const root = source.replace(/\/$/, "");
    if (!root || root === "." || root === (directory ?? "")) return null;
    throw new Error("发行包目录布局已变化，暂不支持此版本。");
  }
  const prefix = directory ? `${directory}/` : "";
  if (!source.startsWith(prefix)) throw new Error("发行包文件位于预期目录之外。");
  const target = source.slice(prefix.length);
  if (!networkSafeReleaseFile(target)) throw new Error("发行包包含不安全或不支持的文件路径。");
  return target;
}

interface NetworkArchiveCollector {
  files: Record<string, string>;
  write(target: string, content: Uint8Array): void;
  finish(): Record<string, string>;
}

function networkArchiveCollector(destination: string, asset: CoreReleaseCandidate["asset"]): NetworkArchiveCollector {
  const files: Record<string, string> = {}, seen = new Set<string>();
  let total = 0;
  return {
    files,
    write(target, content) {
      if (seen.has(target.toLowerCase())) throw new Error("发行包包含重复文件名。");
      seen.add(target.toLowerCase());
      if (seen.size > 128 || content.byteLength > 256 * 1024 * 1024 || (total += content.byteLength) > 512 * 1024 * 1024) throw new Error("解压文件数量或大小超过限制。");
      // Bundled/previous selections authenticate an exact manifest. Unselected
      // files in a known pinned archive are ignored, never placed beside the core.
      if (asset.files && !Object.hasOwn(asset.files, target)) return;
      const hash = networkCrypto.createHash("sha256").update(content).digest("hex");
      if (asset.files && hash !== asset.files[target]) throw new Error("解压文件 SHA-256 不匹配。");
      atomicWrite(networkPath.join(destination, target), content);
      files[target] = hash;
    },
    finish() {
      if (asset.files && Object.keys(files).length !== Object.keys(asset.files).length) throw new Error("发行包未包含完整的官方文件清单。");
      return networkValidateFiles(files, asset.executable, asset.archive);
    },
  };
}

/** No unzip command dependency on Windows. Only flat, regular, bounded files are written. */
function networkExtractZip(archive: string, destination: string, asset: CoreReleaseCandidate["asset"]): Record<string, string> {
  const data = networkFs.readFileSync(archive), collector = networkArchiveCollector(destination, asset);
  let end = -1;
  for (let at = data.length - 22; at >= Math.max(0, data.length - 65557); at--) {
    if (data.readUInt32LE(at) === 0x06054b50 && at + 22 + data.readUInt16LE(at + 20) === data.length) { end = at; break; }
  }
  if (end < 0 || data.readUInt16LE(end + 4) || data.readUInt16LE(end + 6)) throw new Error("不支持此 ZIP 分卷或目录格式。");
  const count = data.readUInt16LE(end + 10);
  if (count === 65535 || count !== data.readUInt16LE(end + 8)) throw new Error("不支持 ZIP64 / 分卷发行包。");
  const centralSize = data.readUInt32LE(end + 12);
  let at = data.readUInt32LE(end + 16);
  const centralEnd = at + centralSize;
  if (centralEnd > end || count > 256) throw new Error("ZIP 中央目录范围或文件数量无效。");
  for (let index = 0; index < count; index++) {
    if (at + 46 > centralEnd || data.readUInt32LE(at) !== 0x02014b50) throw new Error("ZIP 中央目录条目无效。");
    const flags = data.readUInt16LE(at + 8), method = data.readUInt16LE(at + 10);
    const compressed = data.readUInt32LE(at + 20), uncompressed = data.readUInt32LE(at + 24);
    const nameLength = data.readUInt16LE(at + 28), extraLength = data.readUInt16LE(at + 30), commentLength = data.readUInt16LE(at + 32);
    const next = at + 46 + nameLength + extraLength + commentLength;
    if (next > centralEnd) throw new Error("ZIP 文件名范围无效。");
    const sourceName = data.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    const unixType = (data.readUInt32LE(at + 38) >>> 16) & 0o170000;
    const isDirectory = sourceName.endsWith("/");
    if (unixType !== 0 && unixType !== (isDirectory ? 0o040000 : 0o100000)) throw new Error("ZIP 发行包包含链接或特殊文件。");
    const target = networkArchiveTarget(sourceName, asset.directory, isDirectory);
    if (target !== null) {
      if ((flags & 1) || ![0, 8].includes(method) || uncompressed > 256 * 1024 * 1024) throw new Error("ZIP 发行文件加密、压缩方式不受支持或过大。");
      const local = data.readUInt32LE(at + 42);
      if (local + 30 > at || data.readUInt32LE(local) !== 0x04034b50 || data.readUInt16LE(local + 8) !== method || data.readUInt16LE(local + 6) !== flags) throw new Error("ZIP 文件头无效。");
      const nameBytes = data.readUInt16LE(local + 26), extraBytes = data.readUInt16LE(local + 28);
      const begin = local + 30 + nameBytes + extraBytes;
      if (begin + compressed > at || data.subarray(local + 30, local + 30 + nameBytes).toString("utf8") !== sourceName) throw new Error("ZIP 文件数据范围无效。");
      const bytes = data.subarray(begin, begin + compressed);
      const content = method === 8 ? networkZlib.inflateRawSync(bytes, { maxOutputLength: Math.max(1, uncompressed) }) : bytes;
      if (content.length !== uncompressed) throw new Error("ZIP 解压后的文件大小不一致。");
      collector.write(target, content);
    }
    at = next;
  }
  if (at !== centralEnd) throw new Error("ZIP 中央目录大小无效。");
  return collector.finish();
}

/** The current official Linux sing-box archive uses ordinary ustar headers. */
function networkExtractTar(archive: string, destination: string, asset: CoreReleaseCandidate["asset"]): Record<string, string> {
  const data = networkZlib.gunzipSync(networkFs.readFileSync(archive), { maxOutputLength: 512 * 1024 * 1024 });
  const collector = networkArchiveCollector(destination, asset);
  const field = (header: Buffer, offset: number, length: number): string => header.subarray(offset, offset + length).toString("utf8").split("\0")[0]!;
  const octal = (text: string): number => {
    const value = text.trim(); if (!/^[0-7]+$/.test(value)) throw new Error("TAR 数字字段不受支持。");
    const number = Number.parseInt(value, 8); if (!Number.isSafeInteger(number)) throw new Error("TAR 数字超出范围。"); return number;
  };
  let at = 0, count = 0, ended = false;
  for (; at + 512 <= data.length;) {
    const header = data.subarray(at, at + 512);
    if (header.every(byte => byte === 0)) { ended = true; break; }
    if (++count > 256) throw new Error("TAR 文件数量超过限制。");
    let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i]!;
    if (octal(field(header, 148, 8)) !== sum) throw new Error("TAR 文件头校验失败。");
    const size = octal(field(header, 124, 12)), type = header[156];
    if (size > 256 * 1024 * 1024 || at + 512 + size > data.length) throw new Error("TAR 文件范围或大小无效。");
    if (type !== 0 && type !== 48 && type !== 53) throw new Error("TAR 发行包包含链接、特殊文件或不支持的扩展格式。");
    const prefix = field(header, 345, 155), name = field(header, 0, 100);
    const target = networkArchiveTarget(prefix ? `${prefix}/${name}` : name, asset.directory, type === 53);
    if (target !== null) collector.write(target, data.subarray(at + 512, at + 512 + size));
    else if (size !== 0) throw new Error("TAR 目录不应包含文件数据。");
    at += 512 + Math.ceil(size / 512) * 512;
  }
  if (!ended || !data.subarray(at).every(byte => byte === 0)) throw new Error("TAR 结束标记或尾部数据无效。");
  return collector.finish();
}

async function networkProbeCoreVersion(executable: string, release: CoreRelease): Promise<void> {
  const result = await runCommand(executable, release.tool === "cloudflared" ? ["--version"] : ["version"], { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`${coreReleaseLabel(release.tool)} ${release.version} 无法在本机运行（版本检查退出码 ${result.code}）。`);
  const output = result.stdout + "\n" + result.stderr;
  const pattern = release.tool === "singBox" ? /^sing-box version\s+(\S+)/im : release.tool === "xray" ? /^Xray\s+(\S+)/im : /^cloudflared version\s+(\S+)/im;
  const actual = output.match(pattern)?.[1]?.replace(/^v/, "");
  if (actual !== release.version) throw new Error(`${coreReleaseLabel(release.tool)} 返回的实际版本与所选 ${release.version} 不符，已拒绝切换。`);
}

async function networkInstallRelease(paths: AppPaths, selected: CoreReleaseCandidate, report: (message: string) => void, discoverFiles: boolean): Promise<CoreRelease> {
  assertSupportedPlatform(); ensureDataDir(paths);
  const candidate = networkValidateCandidate(selected, !discoverFiles);
  if (candidate.platform !== `${process.platform}-${process.arch}`) throw new Error("不能安装其他平台的内核版本。");
  const asset = discoverFiles ? { ...candidate.asset, files: undefined } : candidate.asset;
  if (!discoverFiles) {
    const complete = candidate as CoreRelease, executable = coreBinaryPath(paths, complete);
    if (await networkCacheMatches(networkPath.dirname(executable), complete.asset)) {
      if (process.platform !== "win32") networkFs.chmodSync(executable, 0o755);
      return complete;
    }
  }
  report(`下载并校验 ${coreReleaseLabel(candidate.tool)} ${candidate.version}…`);
  const staging = networkFs.mkdtempSync(networkPath.join(paths.bin, `.install-${candidate.tool}-`));
  networkFs.chmodSync(staging, 0o700);
  let backup: string | undefined, destination: string | undefined;
  try {
    const downloadPath = networkPath.join(staging, asset.asset);
    await networkDownload(candidate.downloadUrl, downloadPath, asset.sha256);
    const ready = networkPath.join(staging, "ready"); networkFs.mkdirSync(ready, { mode: 0o700 });
    let files: Record<string, string>;
    if (asset.archive === "binary") {
      files = { [asset.executable]: asset.sha256 };
      if (asset.files && (Object.keys(asset.files).length !== 1 || asset.files[asset.executable] !== asset.sha256)) throw new Error("单文件发行包校验清单与归档不一致。");
      networkFs.renameSync(downloadPath, networkPath.join(ready, asset.executable));
    } else if (asset.archive === "zip") files = networkExtractZip(downloadPath, ready, asset);
    else files = networkExtractTar(downloadPath, ready, asset);
    const complete: CoreRelease = { ...candidate, asset: { ...asset, files } };
    if (!await networkCacheMatches(ready, complete.asset)) throw new Error("解压后的内核文件校验失败，已拒绝安装。");
    const readyExecutable = networkPath.join(ready, asset.executable);
    if (process.platform !== "win32") networkFs.chmodSync(readyExecutable, 0o755);
    // Older bundled snapshots remain valid when a future script changes its
    // default pins. Their saved hashes have configuration-file trust, and a
    // reinstalled historical binary must still report the selected version.
    if (discoverFiles || candidate.source === "github" || candidate.version !== NETWORK_RELEASES[candidate.tool].version) await networkProbeCoreVersion(readyExecutable, complete);
    destination = networkPath.dirname(coreBinaryPath(paths, complete));
    if (await networkCacheMatches(destination, complete.asset)) return complete;
    try {
      const stat = networkFs.lstatSync(destination);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("拒绝替换异常内核目录。");
      backup = `${destination}.old-${networkCrypto.randomUUID()}`;
      networkFs.renameSync(destination, backup);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    try { networkFs.renameSync(ready, destination); }
    catch (error) { if (backup && !networkFs.existsSync(destination)) networkFs.renameSync(backup, destination); throw error; }
    report(`${coreReleaseLabel(candidate.tool)} ${candidate.version} 已校验并安装。`);
    return complete;
  } finally {
    networkFs.rmSync(staging, { recursive: true, force: true });
    if (backup && destination && networkFs.existsSync(destination)) {
      try { networkFs.rmSync(backup, { recursive: true, force: true }); } catch { /* A Windows antivirus may hold a replaced cache file. */ }
    }
  }
}

/** Prepare a separately versioned, verified cache. Does not select it or stop any running core. */
export async function prepareCoreRelease(paths: AppPaths, candidate: CoreReleaseCandidate, report: (message: string) => void = () => {}): Promise<CoreRelease> {
  if (candidate.source !== "github") throw new Error("更新候选必须来自官方 GitHub 发行信息。");
  return await networkInstallRelease(paths, candidate, report, true);
}

/** Validate the selected cache and restore it from the same official archive when necessary. */
export async function ensureSingleCore(paths: AppPaths, release: CoreRelease, report: (message: string) => void = () => {}): Promise<string> {
  return coreBinaryPath(paths, await networkInstallRelease(paths, release, report, false));
}

async function networkInstallAsset(paths: AppPaths, tool: BinaryKind, report: (message: string) => void): Promise<string> {
  return await ensureSingleCore(paths, initializeCoreSelection(paths).active[tool], report);
}

export function requiredBinaries(config: AppConfig): BinaryKind[] {
  const nodes = validateConfig(config).nodes.filter(node => node.enabled);
  const required = new Set<BinaryKind>(nodes.map(nodeEngine));
  if (nodes.some(node => node.tunnel.mode !== "none")) required.add("cloudflared");
  return (["singBox", "xray", "cloudflared"] as BinaryKind[]).filter(tool => required.has(tool));
}

/** An empty collection is a valid saved draft; it does not trigger any downloads. */
export async function ensureBinaries(paths: AppPaths, config: AppConfig, report: (message: string) => void = () => {}, releases?: CoreReleaseMap): Promise<Binaries> {
  const required = requiredBinaries(config);
  assertSupportedPlatform();
  ensureDataDir(paths);
  const selected = releases ? networkValidateCoreMap(releases) : (required.length ? initializeCoreSelection(paths) : readCoreSelection(paths)).active;
  const result = await Promise.allSettled(required.map(tool => ensureSingleCore(paths, selected[tool], report)));
  const failed = result.filter((r): r is PromiseRejectedResult => r.status === "rejected");
  if (failed.length) throw new Error(failed.map(r => r.reason instanceof Error ? r.reason.message : String(r.reason)).join("\n"));
  return Object.fromEntries(required.map((tool, index) => [tool, (result[index] as PromiseFulfilledResult<string>).value])) as Binaries;
}

function networkNodeTag(node: NodeConfig): string { return `node:${node.id}`; }
function networkPemLines(value: string): string[] { return value.trim().split(/\r?\n/); }
function networkHostPort(host: string, port: number): string { return `${networkNet.isIP(host) === 6 ? `[${host}]` : host}:${port}`; }

function networkSingTls(node: NodeConfig): Record<string, unknown> | undefined {
  if (node.tls.mode === "none") return undefined;
  const tls: Record<string, unknown> = { enabled: true };
  if (node.tls.serverName) tls.server_name = node.tls.serverName;
  if (node.tls.alpn.length) tls.alpn = node.tls.alpn;
  if (node.tls.mode === "reality") {
    const r = node.tls.reality;
    tls.reality = { enabled: true, handshake: { server: r.handshakeServer, server_port: r.handshakePort }, private_key: r.privateKey, short_id: [r.shortId] };
  } else {
    tls.certificate = networkPemLines(node.tls.certificatePem);
    tls.key = networkPemLines(node.tls.keyPem);
  }
  return tls;
}

function networkSingTransport(node: NodeConfig): Record<string, unknown> | undefined {
  if (node.transport.type === "ws") return { type: "ws", path: node.transport.path };
  if (node.transport.type === "grpc") return { type: "grpc", service_name: node.transport.serviceName };
  return undefined;
}

function networkSingInbound(node: NodeConfig): Record<string, unknown> {
  const inbound: Record<string, unknown> = { type: node.protocol, tag: networkNodeTag(node), listen: node.listen, listen_port: node.port };
  switch (node.protocol) {
    case "vmess": inbound.users = [{ uuid: node.uuid, alterId: 0 }]; break;
    case "shadowsocks": inbound.method = node.method; inbound.password = node.password; break;
    case "trojan": case "anytls": inbound.users = [{ password: node.password }]; break;
    case "hysteria2":
      inbound.users = [{ password: node.password }];
      if (node.hy2.upMbps) inbound.up_mbps = node.hy2.upMbps;
      if (node.hy2.downMbps) inbound.down_mbps = node.hy2.downMbps;
      if (node.hy2.obfsPassword) inbound.obfs = { type: "salamander", password: node.hy2.obfsPassword };
      break;
    case "tuic":
      inbound.users = [{ uuid: node.uuid, password: node.password }];
      inbound.congestion_control = node.tuic.congestionControl;
      inbound.zero_rtt_handshake = node.tuic.zeroRttHandshake;
      break;
    case "socks": case "naive":
      inbound.users = [{ username: node.username, password: node.password }];
      // Naive HTTP/2 uses TCP. HTTP/3 would require an additional UDP listener.
      if (node.protocol === "naive") inbound.network = "tcp";
      break;
    default: throw new Error(`sing-box 不负责 ${node.protocol} 节点。`);
  }
  const tls = networkSingTls(node);
  const transport = networkSingTransport(node);
  if (tls) inbound.tls = tls;
  if (transport) inbound.transport = transport;
  return inbound;
}

export function buildSingBoxConfig(config: AppConfig): object | null {
  const c = validateConfig(config);
  const nodes = c.nodes.filter(node => node.enabled && nodeEngine(node) === "singBox");
  if (!nodes.length) return null;
  const warpTags = nodes.filter(node => node.egress === "warp").map(networkNodeTag);
  const generated: Record<string, unknown> = {
    log: { level: "warn", timestamp: true },
    dns: { servers: [{ type: "local", tag: "dns-local" }], final: "dns-local" },
    inbounds: nodes.map(networkSingInbound), outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct", default_domain_resolver: "dns-local" },
  };
  if (warpTags.length) {
    const w = c.warp!;
    generated.dns = { servers: [
      { type: "local", tag: "dns-local" },
      { type: "udp", tag: "dns-warp", server: "1.1.1.1", server_port: 53, detour: "warp-out" },
    ], final: "dns-local" };
    generated.endpoints = [{
      type: "wireguard", tag: "warp-out", system: false, mtu: 1280,
      address: w.addresses, private_key: w.privateKey, domain_resolver: "dns-local",
      peers: [{ address: w.endpointHost, port: w.endpointPort, public_key: w.peerPublicKey,
        allowed_ips: ["0.0.0.0/0", "::/0"], persistent_keepalive_interval: 25, reserved: w.reserved }],
    }];
    generated.route = { final: "direct", default_domain_resolver: "dns-local", rules: [
      { inbound: warpTags, action: "resolve", server: "dns-warp" },
      { inbound: warpTags, action: "route", outbound: "warp-out" },
    ] };
  }
  return generated;
}

function networkXrayInbound(node: NodeConfig): Record<string, unknown> {
  const stream: Record<string, unknown> = { network: node.transport.type, security: node.tls.mode };
  if (node.transport.type === "ws") stream.wsSettings = { path: node.transport.path };
  if (node.transport.type === "grpc") stream.grpcSettings = { serviceName: node.transport.serviceName };
  if (node.transport.type === "xhttp") stream.xhttpSettings = { path: node.transport.path, mode: node.transport.mode };
  if (node.tls.mode === "tls") {
    stream.tlsSettings = { ...(node.tls.serverName ? { serverName: node.tls.serverName } : {}),
      ...(node.tls.alpn.length ? { alpn: node.tls.alpn } : {}),
      certificates: [{ certificate: networkPemLines(node.tls.certificatePem), key: networkPemLines(node.tls.keyPem) }] };
  } else if (node.tls.mode === "reality") {
    const r = node.tls.reality;
    stream.realitySettings = { target: networkHostPort(r.handshakeServer, r.handshakePort), serverNames: [node.tls.serverName], privateKey: r.privateKey, shortIds: [r.shortId] };
  }
  return { tag: networkNodeTag(node), listen: node.listen, port: node.port, protocol: "vless",
    settings: { clients: [{ id: node.uuid, ...(node.flow ? { flow: node.flow } : {}) }], decryption: node.vlessDecryption }, streamSettings: stream };
}

export function buildXrayConfig(config: AppConfig): object | null {
  const c = validateConfig(config);
  const nodes = c.nodes.filter(node => node.enabled && nodeEngine(node) === "xray");
  if (!nodes.length) return null;
  const warpTags = nodes.filter(node => node.egress === "warp").map(networkNodeTag);
  const outbounds: Record<string, unknown>[] = [{ tag: "direct", protocol: "freedom", settings: { domainStrategy: "AsIs" } }];
  const generated: Record<string, unknown> = { log: { loglevel: "warning" }, inbounds: nodes.map(networkXrayInbound), outbounds };
  if (warpTags.length) {
    const w = c.warp!;
    outbounds.push({ tag: "warp-out", protocol: "wireguard", settings: {
      secretKey: w.privateKey, address: w.addresses, mtu: 1280, noKernelTun: true, reserved: w.reserved, domainStrategy: "ForceIP",
      peers: [{ publicKey: w.peerPublicKey, endpoint: networkHostPort(w.endpointHost, w.endpointPort), allowedIPs: ["0.0.0.0/0", "::/0"], keepAlive: 25 }],
    } });
    // The native WireGuard outbound resolves targets through the built-in DNS.
    // Resolve ONLY the peer hostname using system DNS, avoiding a recursive
    // attempt to establish WARP by sending its own bootstrap lookup over WARP.
    generated.dns = { tag: "warp-dns", queryStrategy: "UseIP", disableFallbackIfMatch: true, servers: [
      ...(!networkNet.isIP(w.endpointHost) ? [{ address: "localhost", domains: [`full:${w.endpointHost}`], skipFallback: true }] : []),
      { address: "1.1.1.1", port: 53 },
    ] };
    generated.routing = { domainStrategy: "AsIs", rules: [
      { type: "field", inboundTag: ["warp-dns"], outboundTag: "warp-out" },
      { type: "field", inboundTag: warpTags, outboundTag: "warp-out" },
    ] };
  }
  return generated;
}

function networkSafeNodeId(nodeId: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(nodeId)) throw new Error("节点 ID 不能用于隧道文件名。");
  return nodeId;
}
export function cloudflaredTokenPath(paths: AppPaths, nodeId: string): string { return networkPath.join(paths.data, `cloudflared-${networkSafeNodeId(nodeId)}.token`); }
export function cloudflaredConfigPath(paths: AppPaths, nodeId: string): string { return networkPath.join(paths.data, `cloudflared-${networkSafeNodeId(nodeId)}.yaml`); }

export function buildCloudflaredArgs(node: NodeConfig, paths: AppPaths, metricsPort: number): string[] {
  const n = validateNode(node);
  if (n.tunnel.mode === "none") throw new Error("此节点没有启用隧道。");
  if (!Number.isInteger(metricsPort) || metricsPort < 1024 || metricsPort > 65535) throw new Error("cloudflared 指标端口无效。");
  const args = [
    "tunnel", "--config", cloudflaredConfigPath(paths, n.id), "--no-autoupdate",
    // Quick tunnels otherwise override the unset default to QUIC, disabling fallback.
    "--protocol", n.tunnel.protocol, "--edge-ip-version", "auto",
    "--metrics", `127.0.0.1:${metricsPort}`, "--loglevel", "info", "--output", "json",
  ];
  const origin = n.listen === "0.0.0.0" ? "127.0.0.1" : n.listen === "::" ? "::1" : n.listen;
  return n.tunnel.mode === "fixed"
    ? [...args, "run", "--token-file", cloudflaredTokenPath(paths, n.id)]
    : [...args, "--url", `http://${networkHostPort(origin, n.port)}`];
}

/** Check all selected cores before publishing any generated runtime configuration. */
export async function preflightCores(paths: AppPaths, config: AppConfig, options: { releases?: CoreReleaseMap; publish?: boolean; report?: (message: string) => void } = {}): Promise<Binaries> {
  const c = validateConfig(config);
  if (!c.nodes.some(node => node.enabled)) throw new Error("没有启用的节点；请先创建或启用至少一个节点。");
  const binaries = await ensureBinaries(paths, c, options.report, options.releases);
  const jobs: { tool: "singBox" | "xray"; path: string; candidate: string; text: string }[] = [];
  for (const [tool, path, generated] of [
    ["singBox", paths.singConfig, buildSingBoxConfig(c)], ["xray", paths.xrayConfig, buildXrayConfig(c)],
  ] as const) if (generated) jobs.push({ tool, path, candidate: `${path}.${networkCrypto.randomUUID()}.candidate.json`, text: JSON.stringify(generated, null, 2) + "\n" });
  try {
    for (const job of jobs) atomicWrite(job.candidate, job.text);
    const checks = await Promise.allSettled(jobs.map(async job => {
      const executable = binaries[job.tool]!;
      const args = job.tool === "singBox" ? ["check", "-c", job.candidate] : ["run", "-test", "-config", job.candidate];
      const result = await runCommand(executable, args, { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
      if (result.code !== 0) {
        const detail = redact((result.stderr || result.stdout).trim(), collectConfigSecrets(c)).slice(-1500);
        throw new Error(`${job.tool === "singBox" ? "sing-box" : "Xray"} 配置检查失败：${detail || `退出码 ${result.code}`}`);
      }
    }));
    const errors = checks.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    if (errors.length) throw new Error(errors.map(error => error.reason instanceof Error ? error.reason.message : String(error.reason)).join("\n"));
    if (options.publish !== false) {
      for (const job of jobs) atomicWrite(job.path, job.text);
      for (const node of c.nodes) {
        if (node.enabled && node.tunnel.mode !== "none") {
          // Isolate each connector from other cloudflared installations/configs.
          atomicWrite(cloudflaredConfigPath(paths, node.id), "{}\n");
          if (node.tunnel.mode === "fixed") atomicWrite(cloudflaredTokenPath(paths, node.id), node.tunnel.token + "\n");
          else networkFs.rmSync(cloudflaredTokenPath(paths, node.id), { force: true });
        }
      }
    }
    return binaries;
  } finally { for (const job of jobs) networkFs.rmSync(job.candidate, { force: true }); }
}

export async function generateSelfSignedCertificate(paths: AppPaths, node: NodeConfig): Promise<{ certificatePem: string; keyPem: string }> {
  // This is deliberately usable by the wizard before its TLS draft is complete.
  assertSupportedPlatform();
  ensureDataDir(paths);
  const engine = nodeEngine(node);
  const executable = await networkInstallAsset(paths, engine, () => {});
  const requestedName = node.tls.serverName || node.address || "localhost";
  const name = requestedName === "localhost" ? "localhost" : normalizeConnectAddress(requestedName);
  if (!name || /[\u0000-\u0020\u007f]/.test(name)) throw new Error("自签证书需要有效的 Server Name / 地址。");
  const args = engine === "xray" ? ["tls", "cert", `--domain=${name}`, "--expire=8760h"] : ["generate", "tls-keypair", name, "--months", "12"];
  const result = await runCommand(executable, args, { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`${engine === "xray" ? "Xray" : "sing-box"} 生成自签证书失败（退出码 ${result.code}）。`);
  let certificatePem = "", keyPem = "";
  if (engine === "xray") {
    const generated = JSON.parse(result.stdout) as { certificate?: unknown; key?: unknown };
    if (Array.isArray(generated.certificate) && generated.certificate.every(line => typeof line === "string")) certificatePem = generated.certificate.join("\n") + "\n";
    if (Array.isArray(generated.key) && generated.key.every(line => typeof line === "string")) keyPem = generated.key.join("\n") + "\n";
  } else {
    certificatePem = (result.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0] ?? "") + "\n";
    keyPem = (result.stdout.match(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----/)?.[0] ?? "") + "\n";
  }
  try {
    const certificate = new networkCrypto.X509Certificate(certificatePem);
    let key: networkCrypto.KeyObject | undefined;
    try { key = networkCrypto.createPrivateKey(keyPem); }
    catch {
      // Xray v26.3.27 emits an EC key with a historical RSA PEM label. Go accepts
      // that label; OpenSSL-based runtimes do not. Parse its actual DER structure
      // and normalize below instead of carrying the misleading header forward.
      const encoded = keyPem.replace(/-----[^\n]+-----/g, "").replace(/\s/g, "");
      const der = Buffer.from(encoded, "base64");
      for (const type of ["pkcs8", "sec1", "pkcs1"] as const) {
        try { key = networkCrypto.createPrivateKey({ key: der, format: "der", type }); break; } catch { /* Try the next standard DER envelope. */ }
      }
    }
    if (!key) throw new Error("unrecognized private key");
    if (!certificate.checkPrivateKey(key)) throw new Error("mismatched key");
    keyPem = key.export({ format: "pem", type: "pkcs8" }).toString();
  } catch { throw new Error("内核没有返回有效且相互匹配的 PEM 证书和私钥。"); }
  return { certificatePem, keyPem };
}

export async function generateVlessEncryption(paths: AppPaths): Promise<{ vlessEncryption: string; vlessDecryption: string }> {
  assertSupportedPlatform();
  ensureDataDir(paths);
  const executable = await networkInstallAsset(paths, "xray", () => {});
  const result = await runCommand(executable, ["vlessenc"], { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`Xray 生成 VLESS ENC 失败（退出码 ${result.code}）。`);
  const section = result.stdout.split("Authentication: ML-KEM-768")[1];
  const encryption = section?.match(/"encryption"\s*:\s*"([^"\r\n]+)"/)?.[1];
  const decryption = section?.match(/"decryption"\s*:\s*"([^"\r\n]+)"/)?.[1];
  if (!encryption || !decryption) throw new Error("Xray 没有返回完整配对的 ML-KEM-768 ENC 参数。");
  return { vlessEncryption: encryption, vlessDecryption: decryption };
}

function networkObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} 缺失或不是对象。`);
  return value as Record<string, unknown>;
}

function networkReserved(value: unknown, clientId?: unknown): number[] {
  if (value !== undefined) {
    if (typeof value === "string") {
      const text = value.trim();
      if (text.startsWith("[")) value = JSON.parse(text);
      else {
        const fields = text.split(",").map(v => v.trim());
        if (fields.some(field => !/^\d{1,3}$/.test(field))) throw new Error("Reserved 必须是三个 0–255 整数。");
        value = fields.map(Number);
      }
    }
    if (!Array.isArray(value) || value.length !== 3 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error("Reserved 必须是三个 0–255 整数。");
    return [...value] as number[];
  }
  if (clientId !== undefined) {
    if (typeof clientId !== "string" || !/^[A-Za-z0-9+/]{4}$/.test(clientId)) throw new Error("WARP client_id 必须是准确三个字节的 Base64，不能截断或补零。");
    const decoded = Buffer.from(clientId, "base64");
    if (decoded.length !== 3 || decoded.toString("base64") !== clientId) throw new Error("WARP client_id 编码无效。");
    return Array.from(decoded);
  }
  // A standard wgcf-profile.conf cannot express the non-standard reserved bytes.
  // Its ordinary WireGuard behavior is zero. An explicit Reserved/JSON overrides it.
  return [0, 0, 0];
}

function networkEndpoint(value: unknown, fallbackPort = 2408): { endpointHost: string; endpointPort: number } {
  if (typeof value !== "string" || !value.trim()) throw new Error("WARP Endpoint 缺失。");
  const text = value.trim();
  let endpointHost = text;
  let endpointPort = fallbackPort;
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(text);
  if (bracketed) {
    if (networkNet.isIP(bracketed[1]!) !== 6) throw new Error("Endpoint 方括号内必须是 IPv6 地址。");
    endpointHost = bracketed[1]!;
    if (bracketed[2]) endpointPort = Number(bracketed[2]);
  } else if (networkNet.isIP(text) !== 6 && text.includes(":")) {
    const hostPort = /^([^:]+):(\d+)$/.exec(text);
    if (!hostPort) throw new Error("Endpoint 应为 host:port 或 [IPv6]:port。");
    endpointHost = hostPort[1]!; endpointPort = Number(hostPort[2]);
  }
  return { endpointHost, endpointPort };
}

function networkAddresses(value: unknown): string[] {
  const entries = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(entries)) throw new Error("WARP 地址列表缺失。");
  return entries.map(entry => {
    if (typeof entry !== "string") throw new Error("WARP 地址必须为文本。");
    const address = entry.trim();
    if (address.includes("/")) return address;
    const family = networkNet.isIP(address);
    if (!family) throw new Error("WARP 地址必须是 IPv4/IPv6，不能使用域名。");
    return `${address}/${family === 4 ? 32 : 128}`;
  });
}

function networkRegistrationProfile(value: unknown, privateKey: string): WarpProfile {
  const root = networkObject(value, "WARP 注册响应");
  if (root.tunnel_type !== undefined && root.tunnel_type !== "wireguard") throw new Error("注册接口没有返回 WireGuard 配置。");
  if (root.key_type !== undefined && root.key_type !== "curve25519") throw new Error("注册接口没有返回 Curve25519 密钥类型。");
  const config = networkObject(root.config, "WARP config");
  const iface = networkObject(config.interface, "WARP interface");
  const addresses = networkObject(iface.addresses, "WARP addresses");
  if (!Array.isArray(config.peers) || !config.peers.length) throw new Error("WARP 响应没有 peer。");
  const peer = networkObject(config.peers[0], "WARP peer");
  const endpoint = networkObject(peer.endpoint, "WARP peer endpoint");
  const ports = Array.isArray(endpoint.ports) ? endpoint.ports : [];
  const fallbackPort = ports.length ? Number(ports[0]) : 2408;
  const parsed = networkEndpoint(endpoint.host || endpoint.v4 || endpoint.v6, fallbackPort);
  // Current API responses may omit host and provide v4/v6 plus a separate ports
  // array. Match wgcf: in that form the ports array, not a stale address suffix,
  // selects the port. A complete endpoint.host still takes precedence.
  if (!endpoint.host) parsed.endpointPort = fallbackPort;
  if (config.client_id === undefined) throw new Error("WARP 注册响应缺少 client_id，不能确认 Reserved。");
  return validateWarpProfile({
    privateKey, addresses: networkAddresses([addresses.v4, addresses.v6].filter(v => typeof v === "string" && v)),
    peerPublicKey: peer.public_key, ...parsed, reserved: networkReserved(undefined, config.client_id),
  });
}

async function networkReadRegistration(response: Response): Promise<string> {
  if (!response.body) throw new Error("WARP 注册响应为空。");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024 * 1024) throw new Error("WARP 注册响应超过大小限制。");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Accept NexusEdge JSON, a sing-box WireGuard endpoint, or a standard WG profile. */
export function parseWarpProfile(text: string): WarpProfile {
  if (text.length > 1024 * 1024) throw new Error("WARP 配置文件超过 1 MiB。");
  const input = text.replace(/^\uFEFF/, "").trim();
  if (!input) throw new Error("WARP 配置为空。");
  if (input.startsWith("{")) {
    const data = networkObject(JSON.parse(input), "WARP JSON");
    if (data.config && (typeof data.privateKey === "string" || typeof data.private_key === "string")) {
      return networkRegistrationProfile(data, String(data.privateKey ?? data.private_key));
    }
    if (data.privateKey !== undefined) return validateWarpProfile({ ...data, reserved: networkReserved(data.reserved, data.client_id) });
    if (Array.isArray(data.peers)) {
      if (data.peers.length !== 1) throw new Error("仅支持单 peer 的 WARP 配置。");
      const peer = networkObject(data.peers[0], "WireGuard peer");
      return validateWarpProfile({
        privateKey: data.private_key, addresses: networkAddresses(data.address), peerPublicKey: peer.public_key,
        ...networkEndpoint(peer.address, Number(peer.port ?? 2408)), reserved: networkReserved(peer.reserved, data.client_id),
      });
    }
    return validateWarpProfile({
      privateKey: data.private_key, addresses: networkAddresses(data.local_address ?? data.addresses),
      peerPublicKey: data.peer_public_key,
      ...networkEndpoint(data.server ?? data.endpoint, Number(data.server_port ?? 2408)),
      reserved: networkReserved(data.reserved, data.client_id),
    });
  }
  // An optional trailing JSON object may carry reserved or a registration client_id.
  const suffixAt = input.search(/^\s*\{/m);
  const wgText = suffixAt < 0 ? input : input.slice(0, suffixAt);
  const metadata = suffixAt < 0 ? {} : networkObject(JSON.parse(input.slice(suffixAt)), "附加 WARP JSON");
  const metadataConfig = metadata.config ? networkObject(metadata.config, "附加 WARP config") : {};
  const iface = new Map<string, string>();
  const peer = new Map<string, string>();
  let section = "";
  let peerCount = 0;
  let commentReserved: string | undefined;
  for (const rawLine of wgText.split(/\r?\n/)) {
    const reservedComment = /^\s*[#;]\s*Reserved\s*=\s*(.+)$/i.exec(rawLine);
    if (reservedComment) commentReserved = reservedComment[1];
    const line = rawLine.replace(/\s*[#;].*$/, "").trim();
    if (!line) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.toLowerCase();
      if (section === "peer" && ++peerCount > 1) throw new Error("仅支持单 peer 的 WARP 配置。");
      continue;
    }
    const field = /^([^=]+)=(.*)$/.exec(line);
    if (!field) throw new Error("WireGuard 配置有无法识别的行。");
    const key = field[1]!.trim().toLowerCase();
    const target = section === "interface" ? iface : section === "peer" ? peer : undefined;
    if (!target) throw new Error("WireGuard 字段必须位于 [Interface] 或 [Peer]。");
    if (target.has(key)) throw new Error(`WireGuard 配置包含重复字段 ${key}。`);
    target.set(key, field[2]!.trim());
  }
  if (peerCount !== 1) throw new Error("WireGuard 配置必须包含一个 [Peer]。");
  return validateWarpProfile({
    privateKey: iface.get("privatekey"), addresses: networkAddresses(iface.get("address")),
    peerPublicKey: peer.get("publickey"), ...networkEndpoint(peer.get("endpoint")),
    reserved: networkReserved(peer.get("reserved") ?? iface.get("reserved") ?? commentReserved ?? metadata.reserved, metadata.client_id ?? metadataConfig.client_id),
  });
}

/** Best-effort compatibility registration, only called after the user's explicit action.
 * This is Cloudflare's client endpoint, NOT a supported public Cloudflare API.
 * Reference: ViRb3/wgcf commit 803310a27bf040ac831b74cf3b4b993482f48647.
 * wgcf also uses a custom TLS fingerprint; Bun fetch may be rejected by the service.
 * Never substitute shared credentials or silently switch an enabled WARP to direct.
 */
export async function registerWarp(): Promise<WarpProfile> {
  const pair = networkCrypto.generateKeyPairSync("x25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  if (!privateJwk.d || !publicJwk.x) throw new Error("当前 Bun 无法生成 X25519 WireGuard 密钥，请升级 Bun。");
  const privateKey = Buffer.from(privateJwk.d, "base64url").toString("base64");
  const publicKey = Buffer.from(publicJwk.x, "base64url").toString("base64");
  let response: Response;
  try {
    response = await fetch("https://api.cloudflareclient.com/v0a5641/reg", {
      method: "POST", signal: AbortSignal.timeout(25_000), redirect: "error",
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
        "CF-Client-Version": "a-6.38.9-5641",
      },
      body: JSON.stringify({
        key: publicKey, key_type: "curve25519", tunnel_type: "wireguard", os_version: "16.0.0",
        install_id: "", fcm_token: "", tos: new Date().toISOString(), model: "PC", serial_number: "", locale: "en_US",
      }),
    });
  } catch {
    throw new Error("WARP 兼容注册请求失败或超时。此接口可能限制普通客户端请求，请使用已有的 WireGuard/WARP 配置导入；未启用 WARP。");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`WARP 兼容注册失败（HTTP ${response.status}）。该接口不保证第三方调用可用，请导入已有配置；未启用 WARP。`);
  }
  if (Number(response.headers.get("content-length")) > 1024 * 1024) {
    await response.body?.cancel();
    throw new Error("WARP 注册响应异常，已拒绝保存。");
  }
  try {
    const data = networkObject(JSON.parse(await networkReadRegistration(response)), "WARP 注册响应");
    if (data.key !== undefined && data.key !== publicKey) throw new Error("WARP 注册响应的公钥不匹配。");
    return networkRegistrationProfile(data, privateKey);
  }
  catch {
    // Never include an upstream response here: it may contain account tokens.
    throw new Error("WARP 响应没有完整、有效的 WireGuard 地址、peer 或 Reserved。未保存也未启用；可导入已有配置。");
  }
}


// ==================== platform.ts ====================
import * as platformFs from "node:fs";
import * as platformPath from "node:path";
import * as platformCp from "node:child_process";
import * as platformCrypto from "node:crypto";

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
  if ($_.Exception.NativeErrorCode -eq 1223 -or $_.Exception.InnerException.NativeErrorCode -eq 1223) { [Console]::Error.WriteLine('UAC 已取消，系统级自启尚未启用。'); exit 1223 }
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


// ==================== daemon.ts ====================
import * as daemonFs from "node:fs";
import * as daemonPath from "node:path";
import * as daemonCp from "node:child_process";
import * as daemonCrypto from "node:crypto";
import * as daemonNet from "node:net";
import * as daemonHttp from "node:http";
import * as daemonDgram from "node:dgram";
import * as daemonSqlite from "bun:sqlite";

export class InstanceBusyError extends Error {
  constructor() { super("同一数据目录已有守护进程占用。请从管理面板停止它；不要删除锁文件或根据旧 PID 杀进程。"); }
}

/** SQLite's OS-backed lock is released after a crash; no stale PID can grant ownership. */
export function acquireDaemonLock(paths: AppPaths): () => void {
  ensureDataDir(paths);
  const db = new daemonSqlite.Database(paths.lockDb, { create: true });
  try { db.exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;"); }
  catch (e) { db.close(); if (/busy|locked/i.test(errorMessage(e))) throw new InstanceBusyError(); throw e; }
  if (process.platform !== "win32") daemonFs.chmodSync(paths.lockDb, 0o600);
  let released = false;
  return () => { if (!released) { released = true; try { db.exec("ROLLBACK;"); } finally { db.close(); } } };
}

export function readRuntimeRecord(paths: AppPaths): RuntimeRecord | null {
  let text: string;
  try { text = daemonFs.readFileSync(paths.runtimeState, "utf8"); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === "ENOENT") return null; throw e; }
  try {
    const r = JSON.parse(text) as RuntimeRecord;
    if (r.schema !== 1 || typeof r.instanceId !== "string" || !/^[0-9a-f-]{36}$/.test(r.instanceId) || !Number.isInteger(r.pid) || r.pid < 1 || !Number.isInteger(r.controlPort) || r.controlPort < 1 || r.controlPort > 65535 || !/^[0-9a-f]{64}$/.test(r.controlToken) || !/^[0-9a-f]{64}$/.test(r.configHash) || typeof r.startedAt !== "string") return null;
    return r;
  } catch { return null; }
}

// Node's direct HTTP client ignores HTTP_PROXY. Loopback control credentials must
// never be sent through a proxy inherited from the user's terminal environment.
async function daemonLocalRequest(port: number, path: string, timeoutMs: number, headers: Record<string, string> = {}, method = "GET"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = daemonHttp.request({ hostname: "127.0.0.1", port, path, method, headers, agent: false }, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => {
        body += chunk;
        if (Buffer.byteLength(body) > 1024 * 1024) request.destroy(new Error("本地控制响应超过大小限制。"));
      });
      response.once("error", reject);
      response.once("end", () => resolve({ status: response.statusCode ?? 0, body }));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("本地控制请求超时。")));
    request.once("error", reject);
    request.end();
  });
}

export async function getDaemonStatus(paths: AppPaths, timeoutMs = 1200): Promise<DaemonStatus | null> {
  const runtime = readRuntimeRecord(paths);
  if (!runtime) return null;
  try {
    const response = await daemonLocalRequest(runtime.controlPort, "/status", timeoutMs, { Authorization: `Bearer ${runtime.controlToken}`, "X-Nexus-Instance": runtime.instanceId });
    if (response.status !== 200) return null;
    const result = JSON.parse(response.body) as DaemonStatus;
    return result.instanceId === runtime.instanceId && result.pid === runtime.pid ? result : null;
  } catch { return null; }
}

export async function stopDaemonGracefully(paths: AppPaths, timeoutMs = 16000): Promise<void> {
  const runtime = readRuntimeRecord(paths);
  if (!runtime) {
    // Startup/preflight owns the lock before publishing its control endpoint.
    const release = acquireDaemonLock(paths); release();
    return;
  }
  const status = await getDaemonStatus(paths);
  if (!status) {
    // A dead process releases this lock. Never use the PID record as a kill target.
    const release = acquireDaemonLock(paths); release();
    return;
  }
  const response = await daemonLocalRequest(runtime.controlPort, "/stop", 3000, { Authorization: `Bearer ${runtime.controlToken}`, "X-Nexus-Instance": runtime.instanceId }, "POST");
  if (response.status !== 200) throw new Error(`守护进程拒绝停止请求（HTTP ${response.status}）。`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const latest = await getDaemonStatus(paths, 500);
    if (!latest || latest.instanceId !== runtime.instanceId) {
      try { const release = acquireDaemonLock(paths); release(); return; }
      catch (e) { if (!(e instanceof InstanceBusyError)) throw e; }
    }
    await delay(150);
  }
  throw new Error("等待停止超时，未强杀任何 PID。请查看日志或通过系统任务/服务管理器检查当前实例。");
}

export async function startDetachedDaemon(paths: AppPaths): Promise<void> {
  if (await getDaemonStatus(paths)) throw new Error("后台实例已经运行，请选择重启。");
  ensureDataDir(paths);
  const release = acquireDaemonLock(paths); release();
  const fd = daemonFs.openSync(paths.log, "a", 0o600);
  try {
    await new Promise<void>((resolve, reject) => {
      const child = daemonCp.spawn(paths.runtime, [paths.entry, "--worker"], {
        cwd: paths.root, shell: false, detached: true, windowsHide: true,
        stdio: ["ignore", fd, fd],
      });
      child.once("error", reject);
      child.once("spawn", () => { child.unref(); resolve(); });
    });
  } finally { daemonFs.closeSync(fd); }
}

export async function waitForReady(paths: AppPaths, timeoutMs = 45000, progress?: (status: DaemonStatus | null) => void): Promise<DaemonStatus | null> {
  const deadline = Date.now() + timeoutMs;
  let latest: DaemonStatus | null = null;
  while (Date.now() < deadline) {
    latest = await getDaemonStatus(paths);
    progress?.(latest);
    if (latest?.phase === "ready") return latest;
    await delay(750);
  }
  return latest;
}

export class RotatingLogger {
  private file: string;
  private secrets: string[];
  private size: number;
  constructor(file: string, secrets: string[]) {
    this.file = file; this.secrets = secrets;
    this.size = daemonFs.existsSync(file) ? daemonFs.statSync(file).size : 0;
  }
  write(message: string): void {
    const safe = redact(message, this.secrets).slice(0, 18000);
    const line = `[${new Date().toISOString()}] ${safe}\n`;
    if (this.size + Buffer.byteLength(line) > 2 * 1024 * 1024) {
      for (let n = 2; n >= 1; n--) {
        const source = n === 1 ? this.file : `${this.file}.${n - 1}`;
        const target = `${this.file}.${n}`;
        if (daemonFs.existsSync(target)) daemonFs.unlinkSync(target);
        if (daemonFs.existsSync(source)) daemonFs.renameSync(source, target);
      }
      this.size = 0;
    }
    daemonFs.appendFileSync(this.file, line, { mode: 0o600 });
    this.size += Buffer.byteLength(line);
  }
}

export function tailLog(paths: AppPaths, count = 25): string {
  if (!daemonFs.existsSync(paths.log)) return "暂无运行日志。";
  const fd = daemonFs.openSync(paths.log, "r");
  try {
    const size = daemonFs.fstatSync(fd).size;
    const buffer = Buffer.alloc(Math.min(size, 64 * 1024));
    daemonFs.readSync(fd, buffer, 0, buffer.length, Math.max(0, size - buffer.length));
    return buffer.toString("utf8").trimEnd().split("\n").slice(-count).join("\n");
  } finally { daemonFs.closeSync(fd); }
}

function daemonSameSecret(actual: string | null, expected: string): boolean {
  const a = Buffer.from(actual ?? ""); const b = Buffer.from(expected);
  return a.length === b.length && daemonCrypto.timingSafeEqual(a, b);
}

function daemonSerializeStatus(status: DaemonStatus): string {
  const text = JSON.stringify(status);
  if (Buffer.byteLength(text) <= 1024 * 1024) return text;
  // Long VLESS ENC values may make links larger than the local IPC budget.
  // Keep readiness and identity available so the user can still stop/restart.
  // The complete URIs stay in the export file; the panel can regenerate them.
  const conciseLink = (link: DaemonStatus["links"][number]) => link.uri
    ? { ...link, uri: null, error: "链接较长，请从节点导出菜单生成；完整 URI 仍保存在节点链接文件中。" }
    : link;
  return JSON.stringify({
    ...status,
    nodes: status.nodes.map(node => ({ ...node, links: node.links.map(conciseLink) })),
    links: status.links.map(conciseLink),
  });
}

export async function assertLocalPortAvailable(port: number, host = "127.0.0.1", network: "tcp" | "udp" = "tcp"): Promise<void> {
  if (network === "udp") {
    await new Promise<void>((resolve, reject) => {
      const socket = daemonDgram.createSocket({ type: daemonNet.isIP(host) === 6 ? "udp6" : "udp4", reuseAddr: false });
      socket.once("error", error => {
        try { socket.close(); } catch { /* A bind failure may leave no socket handle. */ }
        reject(new Error(`本机 UDP 端口 ${host}:${port} 无法使用：${errorMessage(error)}`));
      });
      socket.bind({ address: host, port, exclusive: true }, () => socket.close(() => resolve()));
    });
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const server = daemonNet.createServer();
    server.once("error", error => reject(new Error(`本机 TCP 端口 ${host}:${port} 无法使用：${errorMessage(error)}`)));
    server.listen({ host, port, exclusive: true }, () => server.close(error => error ? reject(error) : resolve()));
  });
}

async function daemonFreePort(excluded: Set<number>): Promise<number> {
  for (let attempt = 0; attempt < 64; attempt++) {
    const port = await new Promise<number>((resolve, reject) => {
      const server = daemonNet.createServer();
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
        const address = server.address();
        const value = typeof address === "object" && address ? address.port : 0;
        server.close(error => error ? reject(error) : resolve(value));
      });
    });
    if (port && !excluded.has(port)) { excluded.add(port); return port; }
  }
  throw new Error("无法分配不冲突的本机隧道指标端口。");
}

function daemonProbeAddress(listen: string): string {
  return listen === "0.0.0.0" ? "127.0.0.1" : listen === "::" ? "::1" : listen;
}

async function daemonProbeTcp(port: number, listen: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = daemonNet.connect({ host: daemonProbeAddress(listen), port });
    let done = false;
    const finish = (ok: boolean) => { if (!done) { done = true; socket.destroy(); resolve(ok); } };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(700, () => finish(false));
  });
}

/** A bound UDP port is a listener check, not a protocol handshake or proof of reachability. */
async function daemonProbeUdp(port: number, listen: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = daemonDgram.createSocket({ type: daemonNet.isIP(listen) === 6 ? "udp6" : "udp4", reuseAddr: false });
    let done = false;
    const timer = setTimeout(() => finish(false), 700);
    const finish = (inUse: boolean) => {
      if (done) return;
      done = true; clearTimeout(timer);
      try { socket.close(() => resolve(inUse)); } catch { resolve(inUse); }
    };
    socket.once("error", error => finish((error as NodeJS.ErrnoException).code === "EADDRINUSE"));
    socket.bind({ address: listen, port, exclusive: true }, () => finish(false));
  });
}

async function daemonSettleWithin(promises: Promise<void>[], milliseconds: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.allSettled(promises),
      new Promise<void>(resolve => { timer = setTimeout(resolve, milliseconds); }),
    ]);
  } finally { if (timer) clearTimeout(timer); }
}

export function buildWebhookPayload(kind: AppConfig["webhook"]["kind"], domain: string, link: string): unknown {
  const content = `NexusEdge 节点通路已就绪\n地址：${domain}\n${link}`;
  switch (kind) {
    case "feishu": return { msg_type: "text", content: { text: content } };
    case "wecom": case "dingtalk": return { msgtype: "text", text: { content } };
    case "bark": return { title: "NexusEdge 节点就绪", body: content };
    default: return { event: "nexus-edge.ready", domain, link, text: content };
  }
}

async function daemonNotify(config: AppConfig, domain: string, link: string, logger: RotatingLogger): Promise<void> {
  if (config.webhook.kind === "none") return;
  try {
    const response = await fetch(config.webhook.url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildWebhookPayload(config.webhook.kind, domain, link)),
      redirect: "error", signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (config.webhook.kind !== "generic") {
      const body = await response.json() as { code?: number; errcode?: number };
      const good = config.webhook.kind === "bark" ? body.code === 200 : config.webhook.kind === "feishu" ? body.code === 0 : body.errcode === 0;
      if (!good) throw new Error("接收方返回非成功业务状态；检查该机器人的认证/签名要求。");
    } else { await response.body?.cancel(); }
    logger.write("[webhook] 已发送当前节点通知。");
  } catch (e) { logger.write(`[webhook] 通知失败，后台继续运行：${errorMessage(e)}`); }
}

export interface DaemonCoreCommand { executable: string; args: string[] }
export interface DaemonOptions {
  /** Dependency injection for local tests only. The interactive program never sets these. */
  cores?: Partial<Record<CoreName, DaemonCoreCommand>>;
  tunnels?: Record<string, DaemonCoreCommand>;
  skipPreflight?: boolean;
  healthIntervalMs?: number;
  backoffBaseMs?: number;
}

interface DaemonJob {
  key: string;
  engine?: CoreName;
  nodeId?: string;
  command: DaemonCoreCommand;
  args: string[];
  state: CoreRuntimeStatus;
}

export async function runDaemonWorker(paths: AppPaths, options: DaemonOptions = {}): Promise<void> {
  const releaseLock = acquireDaemonLock(paths);
  const instanceId = daemonCrypto.randomUUID();
  const startedAt = new Date().toISOString();
  const runDirectory = daemonPath.join(paths.data, `run-${instanceId}`);
  const abort = new AbortController();
  let server: ReturnType<typeof Bun.serve> | undefined;
  let logger: RotatingLogger | undefined;
  let stopRequested = false;
  const children = new Set<daemonCp.ChildProcess>();
  const loops: Promise<void>[] = [];
  let fatalError: unknown;
  let requestStop: () => void = () => {};
  const stopPromise = new Promise<void>(resolve => { requestStop = () => { if (!stopRequested) { stopRequested = true; abort.abort(); resolve(); } }; });
  const signalStop = () => requestStop();
  process.on("SIGINT", signalStop);
  process.on("SIGTERM", signalStop);
  try {
    // A normalized immutable snapshot is used for all retries in this worker.
    const config = readConfig(paths);
    const runtimeHash = runtimeConfigFingerprint(config);
    const enabled = config.nodes.filter(node => node.enabled);
    if (!enabled.length) throw new Error("没有已启用的节点。请先在面板创建或启用至少一个节点。");
    logger = new RotatingLogger(paths.log, collectConfigSecrets(config));
    logger.write(`NexusEdge worker 启动，PID=${process.pid}，instance=${instanceId}，节点数=${enabled.length}`);
    daemonFs.mkdirSync(runDirectory, { mode: 0o700 });
    const runningPaths: AppPaths = {
      ...paths, data: runDirectory, singConfig: daemonPath.join(runDirectory, "sing-box.json"),
      xrayConfig: daemonPath.join(runDirectory, "xray.json"), tokenFile: daemonPath.join(runDirectory, "tunnel-token.txt"),
    };
    for (const node of enabled) for (const network of nodeListenNetworks(node)) await assertLocalPortAvailable(node.port, node.listen, network);
    const engines = [...new Set(enabled.map(nodeEngine))];
    const tunneled = enabled.filter(node => node.tunnel.mode !== "none");
    const injectedAll = engines.every(engine => options.cores?.[engine]) && tunneled.every(node => options.tunnels?.[node.id]);
    // A real first start records the default selection, so later script updates
    // cannot silently replace a user's chosen core set. Fully injected tests
    // do not install or claim ownership of real core binaries.
    const releases = (injectedAll && options.skipPreflight ? readCoreSelection(paths) : initializeCoreSelection(paths)).active;
    const releaseHash = coreReleaseFingerprint(releases);
    let binaries: Binaries = {};
    if (!options.skipPreflight) binaries = await preflightCores(runningPaths, config, { releases });
    else if (!injectedAll) binaries = await ensureBinaries(paths, config, message => logger!.write(message), releases);
    if (abort.signal.aborted) return;
    const runtime: RuntimeRecord = {
      schema: 1, instanceId, pid: process.pid, startedAt,
      controlPort: 0, controlToken: daemonCrypto.randomBytes(32).toString("hex"), configHash: configFingerprint(config),
    };
    const status: DaemonStatus = {
      instanceId, pid: process.pid, startedAt, configHash: runtime.configHash, runtimeConfigHash: runtimeHash, coreReleaseHash: releaseHash,
      phase: "starting", cores: {}, nodes: config.nodes.map(node => ({
        id: node.id, name: node.name, protocol: node.protocol, engine: nodeEngine(node), enabled: node.enabled,
        phase: node.enabled ? "starting" : "disabled", listenerReady: false,
        listenerCheck: nodeListenNetworks(node).join("+") as NodeRuntimeStatus["listenerCheck"],
        directReady: false, tunnelReady: false, tunnelMode: node.tunnel.mode,
        tunnelState: node.enabled && node.tunnel.mode !== "none" ? "starting" : "disabled", tunnelRestarts: 0,
        domain: node.tunnel.mode === "fixed" ? node.tunnel.domain : null,
        links: [], lastError: null, detail: node.enabled ? "等待本地核心监听。" : "节点已禁用，未启动监听或隧道。",
      })), links: [], lastError: null,
    };
    const nodeStates = new Map(status.nodes.map(node => [node.id, node]));
    const nodeConfigs = new Map(config.nodes.map(node => [node.id, node]));
    let clientMetadata = new Map(config.nodes.map(node => [node.id, { address: node.address, publicPort: node.publicPort }] as const));
    let lastMetadataText: string | undefined;
    const refreshClientMetadata = () => {
      try {
        // Read-only: a missing or partially edited file must not create defaults
        // or migrate configuration underneath the running worker.
        const text = daemonFs.readFileSync(paths.config, "utf8");
        if (text === lastMetadataText) return;
        lastMetadataText = text;
        const candidate = validateConfig(JSON.parse(text), { allowExpiredCertificate: true });
        if (runtimeConfigFingerprint(candidate) !== runtimeHash) return;
        // Replace only this overlay. Credentials, listeners, core retry arguments
        // and Quick Tunnel identity always keep using the immutable snapshot.
        clientMetadata = new Map(candidate.nodes.map(node => [node.id, { address: node.address, publicPort: node.publicPort }] as const));
      } catch { /* Keep the last accepted metadata while a saved edit is invalid or unreadable. */ }
    };
    const jobs: DaemonJob[] = [];
    const tunnelJobs = new Map<string, DaemonJob>();
    const metricsPorts = new Map<string, number>();
    const listenerCounts = new Map<string, number>();
    const tunnelCounts = new Map<string, number>();
    const initialState = (): CoreRuntimeStatus => ({ state: "starting", restarts: 0, lastError: null });
    for (const engine of engines) {
      const command = options.cores?.[engine] ?? (binaries[engine] ? { executable: binaries[engine]!, args: [] } : undefined);
      if (!command) throw new Error(`未获取节点所需的 ${engine} 核心。`);
      const state = initialState(); status.cores[engine] = state;
      jobs.push({ key: engine, engine, command, args: engine === "singBox" ? ["run", "-c", runningPaths.singConfig] : ["run", "-config", runningPaths.xrayConfig], state });
    }
    server = Bun.serve({
      hostname: "127.0.0.1", port: 0, maxRequestBodySize: 1024,
      fetch(request) {
        const url = new URL(request.url);
        if (request.headers.has("Origin") || !daemonSameSecret(request.headers.get("Authorization"), `Bearer ${runtime.controlToken}`) || !daemonSameSecret(request.headers.get("X-Nexus-Instance"), instanceId)) return new Response("Forbidden", { status: 403 });
        const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
        if (url.pathname === "/status" && request.method === "GET") return new Response(daemonSerializeStatus(status), { headers });
        if (url.pathname === "/stop" && request.method === "POST") {
          status.phase = "stopping";
          for (const node of status.nodes) if (node.enabled) { node.phase = "stopping"; node.links = []; }
          status.links = [];
          setTimeout(requestStop, 25);
          return new Response('{"accepted":true}', { headers });
        }
        return new Response("Not found", { status: 404 });
      },
    });
    runtime.controlPort = server.port!;
    const reservedPorts = new Set([...enabled.map(node => node.port), runtime.controlPort]);
    // No tunnel means no cloudflared job, metrics listener or /ready request.
    for (const node of tunneled) {
      const command = options.tunnels?.[node.id] ?? (binaries.cloudflared ? { executable: binaries.cloudflared, args: [] } : undefined);
      if (!command) throw new Error(`未获取节点 ${node.name} 所需的 cloudflared。`);
      const metricsPort = await daemonFreePort(reservedPorts); metricsPorts.set(node.id, metricsPort);
      const job: DaemonJob = { key: `cloudflared:${node.id}`, nodeId: node.id, command, args: buildCloudflaredArgs(node, runningPaths, metricsPort), state: initialState() };
      jobs.push(job); tunnelJobs.set(node.id, job);
    }
    atomicWrite(paths.runtimeState, JSON.stringify(runtime, null, 2) + "\n");
    daemonFs.rmSync(paths.link, { force: true });
    let publishedLinks = "";
    const publishLinks = () => {
      status.links = status.nodes.flatMap(node => node.enabled ? node.links : []);
      const text = status.links.filter(link => link.uri).map(link => link.uri!).join("\n");
      if (text === publishedLinks) return;
      publishedLinks = text;
      if (text) atomicWrite(paths.link, text + "\n");
      else daemonFs.rmSync(paths.link, { force: true });
    };
    const invalidateJob = (job: DaemonJob) => {
      const nextPhase = abort.signal.aborted || status.phase === "stopping" ? "stopping" : "degraded";
      for (const node of status.nodes) {
        if (!node.enabled) continue;
        if (job.engine && node.engine === job.engine) {
          node.listenerReady = false; node.directReady = false; node.tunnelReady = false; node.links = [];
          listenerCounts.set(node.id, 0); tunnelCounts.set(node.id, 0);
          node.phase = nextPhase;
        } else if (job.nodeId === node.id) {
          node.tunnelReady = false; node.links = node.links.filter(link => link.via === "direct");
          tunnelCounts.set(node.id, 0); node.phase = nextPhase;
        }
      }
      status.phase = nextPhase;
      publishLinks();
    };
    const setJobState = (job: DaemonJob, state: CoreProcessState) => {
      job.state.state = state;
      if (job.nodeId) {
        const node = nodeStates.get(job.nodeId)!;
        node.tunnelState = state; node.tunnelRestarts = job.state.restarts;
      }
    };
    const supervise = async (job: DaemonJob) => {
      let consecutiveFailures = 0;
      while (!abort.signal.aborted) {
        setJobState(job, "starting");
        if (job.nodeId && nodeConfigs.get(job.nodeId)!.tunnel.mode === "quick") nodeStates.get(job.nodeId)!.domain = null;
        const spawnTime = Date.now();
        logger!.write(`[${job.key}] 启动核心。`);
        const child = daemonCp.spawn(paths.runtime, [paths.entry, "--core-host", job.command.executable, ...job.command.args, ...job.args], {
          cwd: runDirectory, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
        });
        children.add(child);
        const consume = (line: string) => {
          logger!.write(`[${job.key}] ${line}`);
          if (job.nodeId && nodeConfigs.get(job.nodeId)!.tunnel.mode === "quick") {
            const match = line.match(/https:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com)(?=[\s/"'|]|$)/i);
            if (match) nodeStates.get(job.nodeId)!.domain = normalizeDomain(match[1]!);
          }
        };
        const stdout = new LineBuffer(consume); const stderr = new LineBuffer(consume);
        child.stdout!.on("data", chunk => stdout.feed(chunk));
        child.stderr!.on("data", chunk => stderr.feed(chunk));
        const outcome = await new Promise<string>(resolve => {
          child.once("spawn", () => setJobState(job, "running"));
          child.once("error", error => resolve(`spawn 失败：${errorMessage(error)}`));
          child.once("close", (code, signal) => resolve(`退出码=${code ?? "null"}，signal=${signal ?? "none"}`));
        });
        stdout.end(); stderr.end(); children.delete(child);
        setJobState(job, "stopped"); invalidateJob(job);
        if (abort.signal.aborted) break;
        job.state.restarts++;
        consecutiveFailures = Date.now() - spawnTime > 60000 ? 1 : consecutiveFailures + 1;
        const backoff = Math.min(30000, (options.backoffBaseMs ?? 1000) * 2 ** Math.min(5, consecutiveFailures - 1));
        job.state.lastError = `${job.key} ${outcome}；${Math.ceil(backoff / 1000)} 秒后重试。`;
        setJobState(job, "backoff"); logger!.write(job.state.lastError);
        await delay(backoff, abort.signal);
      }
    };

    const lastNotices = new Map<string, string>();
    // A helper also prevents TypeScript from assuming a mutable phase cannot
    // change across an await when /stop is handled by another callback.
    const monitorStopped = () => abort.signal.aborted || status.phase === "stopping";
    const monitorNode = async (node: NodeConfig) => {
      const state = nodeStates.get(node.id)!;
      const core = status.cores[nodeEngine(node)]!;
      const generation = core.restarts;
      let listening = false;
      if (core.state === "running") {
        const probes = await Promise.all(nodeListenNetworks(node).map(network => network === "tcp" ? daemonProbeTcp(node.port, node.listen) : daemonProbeUdp(node.port, node.listen)));
        listening = probes.every(Boolean) && core.state === "running" && core.restarts === generation;
      }
      if (monitorStopped()) return;
      listenerCounts.set(node.id, listening ? (listenerCounts.get(node.id) ?? 0) + 1 : 0);
      state.listenerReady = (listenerCounts.get(node.id) ?? 0) >= 2;
      state.directReady = node.direct && state.listenerReady;
      const tunnel = tunnelJobs.get(node.id);
      let tunnelHealthy = false;
      if (tunnel?.state.state === "running" && state.listenerReady && state.domain) {
        const tunnelGeneration = tunnel.state.restarts;
        try {
          const response = await daemonLocalRequest(metricsPorts.get(node.id)!, "/ready", 900);
          tunnelHealthy = response.status === 200 && tunnel.state.state === "running" && tunnel.state.restarts === tunnelGeneration && core.state === "running" && core.restarts === generation;
        } catch { /* Another node's healthy routes remain usable while this one retries. */ }
      }
      if (monitorStopped()) return;
      // A core may exit while its tunnel /ready request is in flight. Never
      // resurrect that generation's direct links after the exit handler cleared them.
      if (core.state !== "running" || core.restarts !== generation) {
        listenerCounts.set(node.id, 0); state.listenerReady = false; state.directReady = false;
        tunnelHealthy = false;
      }
      tunnelCounts.set(node.id, tunnelHealthy ? (tunnelCounts.get(node.id) ?? 0) + 1 : 0);
      state.tunnelReady = Boolean(tunnel) && (tunnelCounts.get(node.id) ?? 0) >= 2;
      const allReady = state.listenerReady && (!node.direct || state.directReady) && (!tunnel || state.tunnelReady);
      state.phase = allReady ? "ready" : state.directReady || state.tunnelReady || core.restarts > 0 || (tunnel?.state.restarts ?? 0) > 0 || Date.now() - Date.parse(startedAt) > 20000 ? "degraded" : "starting";
      const exportNode = { ...node, ...clientMetadata.get(node.id) };
      state.links = generateNodeLinks(exportNode, state.domain ?? undefined).filter(link => link.via === "direct" ? state.directReady : state.tunnelReady);
      state.lastError = allReady ? null : !state.listenerReady ? core.lastError ?? "本地核心监听尚未就绪。" : tunnel?.state.lastError ?? "Cloudflare 隧道尚未连接，或尚未取得临时域名。";
      state.detail = state.listenerReady
        ? `${state.listenerCheck.includes("udp") ? "已确认核心持续运行和 UDP 端口占用" + (state.listenerCheck === "tcp+udp" ? "、TCP 监听" : "") : "已确认本地 TCP 监听"}；尚未验证公网可达性或客户端协议握手。`
        : "等待所需的本地监听；进程存在本身不代表节点已就绪。";
      const exportErrors = state.links.flatMap(link => link.error ? [link.error] : []);
      if (exportErrors.length) state.detail += ` ${exportErrors.join(" ")}`;
      if (state.tunnelReady && tunnel) tunnel.state.lastError = null;
      for (const link of state.links) {
        const noticeId = `${node.id}:${link.via}`;
        // A direct path becoming ready is one event for this running config.
        // Remember it even if its public address is still missing: later client
        // metadata edits update exports without sending additional notifications.
        // Quick Tunnel hostname changes retain their original notification event.
        const noticeKey = `${runtime.configHash}:${link.via === "direct" ? "direct-ready" : link.uri}`;
        if (lastNotices.get(noticeId) === noticeKey) continue;
        if (link.via === "tunnel" && (!link.uri || link.error)) continue;
        lastNotices.set(noticeId, noticeKey);
        if (link.uri && !link.error) {
          void daemonNotify(config, link.via === "tunnel" ? state.domain! : exportNode.address, link.uri, logger!);
        }
      }
    };
    const monitor = async () => {
      while (!abort.signal.aborted) {
        refreshClientMetadata();
        await Promise.all(enabled.map(monitorNode));
        if (abort.signal.aborted || status.phase === "stopping") break;
        const active = status.nodes.filter(node => node.enabled);
        status.phase = active.every(node => node.phase === "ready") ? "ready" : active.some(node => node.phase === "degraded" || node.directReady || node.tunnelReady) ? "degraded" : "starting";
        status.lastError = active.find(node => node.phase !== "ready" && node.lastError)?.lastError ?? null;
        for (const engine of engines) if (active.filter(node => node.engine === engine).every(node => node.listenerReady)) status.cores[engine]!.lastError = null;
        publishLinks();
        await delay(options.healthIntervalMs ?? 1000, abort.signal);
      }
    };
    for (const promise of [...jobs.map(supervise), monitor()]) loops.push(promise.catch(error => { fatalError = error; logger!.write(`守护异常：${errorMessage(error)}`); requestStop(); }));
    await stopPromise;
    status.phase = "stopping"; status.links = [];
    for (const node of status.nodes) if (node.enabled) { node.phase = "stopping"; node.links = []; }
    publishLinks();
    logger.write("正在关闭所有本实例的核心、隧道与控制通道。");
  } finally {
    try {
      requestStop();
      // EOF on each host's stdin is its liveness signal. Hosts own and await their cores.
      for (const child of children) { try { child.stdin?.end(); } catch { /* Already exited. */ } }
      await daemonSettleWithin(loops, 12000);
      if (children.size) {
        for (const child of children) child.kill("SIGTERM");
        await daemonSettleWithin(loops, 3000);
      }
      if (server) await server.stop(true);
      const record = readRuntimeRecord(paths);
      if (record?.instanceId === instanceId) {
        daemonFs.rmSync(paths.runtimeState, { force: true });
        daemonFs.rmSync(paths.link, { force: true });
      }
      daemonFs.rmSync(runDirectory, { recursive: true, force: true });
      process.removeListener("SIGINT", signalStop);
      process.removeListener("SIGTERM", signalStop);
      logger?.write("后台实例已停止。");
    } finally { releaseLock(); }
  }
  if (fatalError) throw fatalError;
}

/**
 * A tiny core host keeps an open pipe to the supervisor. Even SIGKILL of the
 * supervisor closes that pipe, so the host terminates the core it owns.
 * This also avoids reliance on PID files when stopping a Windows child.
 */
export async function runCoreHost(executable: string, args: string[]): Promise<number> {
  if (!executable || !daemonPath.isAbsolute(executable)) throw new Error("core-host 需要绝对可执行文件路径。");
  const child = daemonCp.spawn(executable, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let stopping = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const cleanup = () => {
    if (stopping) return;
    stopping = true;
    child.kill("SIGTERM");
    killTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }, 6000);
    killTimer.unref();
  };
  const outputError = () => cleanup();
  process.stdout.on("error", outputError); process.stderr.on("error", outputError);
  process.stdin.on("end", cleanup); process.stdin.on("close", cleanup); process.stdin.on("error", cleanup);
  process.on("SIGINT", cleanup); process.on("SIGTERM", cleanup);
  process.stdin.resume();
  child.stdout!.pipe(process.stdout, { end: false });
  child.stderr!.pipe(process.stderr, { end: false });
  const code = await new Promise<number>(resolve => {
    child.once("error", e => { try { process.stderr.write(`core spawn: ${errorMessage(e)}\n`); } catch {} resolve(1); });
    child.once("close", value => resolve(stopping ? 0 : (value ?? 1)));
  });
  if (killTimer) clearTimeout(killTimer);
  process.stdin.pause();
  process.stdin.removeListener("end", cleanup); process.stdin.removeListener("close", cleanup); process.stdin.removeListener("error", cleanup);
  process.removeListener("SIGINT", cleanup); process.removeListener("SIGTERM", cleanup);
  process.stdout.removeListener("error", outputError); process.stderr.removeListener("error", outputError);
  return code;
}


// ==================== migration.ts ====================

export interface MigrationOperations {
  getStatus(paths: AppPaths): Promise<DaemonStatus | null>;
  getStartup(paths: AppPaths): Promise<StartupStatus>;
  copy(paths: AppPaths): Promise<AppPaths>;
  preflight(paths: AppPaths): Promise<void>;
  enable(paths: AppPaths, mode: "system" | "user"): Promise<void>;
  disable(paths: AppPaths): Promise<void>;
  startManaged(paths: AppPaths): Promise<void>;
  stopManaged(paths: AppPaths): Promise<void>;
  startPortable(paths: AppPaths): Promise<void>;
  stopPortable(paths: AppPaths): Promise<void>;
  waitReady(paths: AppPaths): Promise<DaemonStatus | null>;
  activate(paths: AppPaths): Promise<void>;
  deactivate(paths: AppPaths): Promise<void>;
}

const migrationDefaults: MigrationOperations = {
  getStatus: getDaemonStatus, getStartup: getStartupStatus, copy: installSystemCopy,
  preflight: async paths => { await preflightCores(paths, readConfig(paths)); }, enable: enableStartup, disable: disableStartup,
  startManaged, stopManaged, startPortable: startDetachedDaemon, stopPortable: stopDaemonGracefully,
  waitReady: paths => waitForReady(paths, 45000), activate: activateSystemInstallation, deactivate: deactivateSystemInstallation,
};

/**
 * The original node stays active during copy and validation. Once switched, the
 * old autostart definition is disabled only after the new worker reports ready.
 * Failed switches restore the old lifecycle instead of reporting a false success.
 */
export async function migrateSystemInstallation(paths: AppPaths, operations: MigrationOperations = migrationDefaults): Promise<AppPaths> {
  const sourceStartup = await operations.getStartup(paths);
  const sourceWasRunning = Boolean(await operations.getStatus(paths)) || sourceStartup.running;
  const target = await operations.copy(paths);
  await operations.preflight(target);
  let sourceStopped = false;
  let targetTouched = false;
  let targetStartAttempted = false;
  let sourceAutostartTouched = false;
  try {
    if (sourceStartup.mode === "none") await operations.stopPortable(paths);
    else await operations.stopManaged(paths);
    sourceStopped = true;
    targetTouched = true;
    await operations.enable(target, "system");
    targetStartAttempted = true;
    await operations.startManaged(target);
    const ready = await operations.waitReady(target);
    if (ready?.phase !== "ready") throw new Error(`系统副本尚未就绪${ready?.lastError ? `：${ready.lastError}` : "，请检查网络、隧道参数和日志"}。`);
    if (sourceStartup.enabled) {
      sourceAutostartTouched = true;
      await operations.disable(paths);
    }
    await operations.activate(target);
    return target;
  } catch (originalError) {
    const failures: string[] = [];
    let targetSafelyStopped = true;
    if (targetStartAttempted) {
      try { await operations.stopManaged(target); }
      catch (e) { targetSafelyStopped = false; failures.push(`系统副本停止失败：${errorMessage(e)}`); }
    }
    if (targetTouched) {
      try { await operations.disable(target); }
      catch (e) { targetSafelyStopped = false; failures.push(`系统副本自启关闭失败：${errorMessage(e)}`); }
    }
    try { await operations.deactivate(target); }
    catch (e) { failures.push(`系统副本激活标记恢复失败：${errorMessage(e)}`); }
    if (sourceAutostartTouched && sourceStartup.enabled) {
      try { await operations.enable(paths, sourceStartup.mode === "windows-user" ? "user" : "system"); }
      catch (e) { failures.push(`原自启设置恢复失败：${errorMessage(e)}`); }
    }
    let restored = false;
    if (sourceStopped && sourceWasRunning && targetSafelyStopped) {
      try {
        if (sourceStartup.mode === "none") await operations.startPortable(paths);
        else await operations.startManaged(paths);
        restored = true;
      } catch (e) { failures.push(`原后台启动恢复失败：${errorMessage(e)}`); }
    }
    const recovery = failures.length ? `\n恢复时遇到问题：\n${failures.join("\n")}\n请先检查日志和系统管理器，不要重复创建第二套后台。` : restored ? "\n已重新启动原后台，原自启设置已保留；临时隧道重连后请重新查看节点链接。" : "\n原来的自启设置已保留；原后台此前未运行时不会自动启动。";
    throw new Error(`系统安装切换失败：${errorMessage(originalError)}${recovery}`);
  }
}


// ==================== updates.ts ====================

export interface CoreUpdateOperations {
  acquireLock(paths: AppPaths): () => void;
  readConfig(paths: AppPaths): AppConfig;
  readSelection(paths: AppPaths): CoreSelectionState;
  writeSelection(paths: AppPaths, selection: CoreSelectionState): void;
  prepare(paths: AppPaths, candidate: CoreReleaseCandidate, report: (message: string) => void): Promise<CoreRelease>;
  ensure(paths: AppPaths, release: CoreRelease, report: (message: string) => void): Promise<string>;
  preflight(paths: AppPaths, config: AppConfig, releases: CoreReleaseMap, report: (message: string) => void): Promise<void>;
  getStatus(paths: AppPaths): Promise<DaemonStatus | null>;
  getStartup(paths: AppPaths): Promise<StartupStatus>;
  verifyStopped(paths: AppPaths): Promise<void>;
  startManaged(paths: AppPaths): Promise<void>;
  stopManaged(paths: AppPaths): Promise<void>;
  startPortable(paths: AppPaths): Promise<void>;
  stopPortable(paths: AppPaths): Promise<void>;
  waitReady(paths: AppPaths): Promise<DaemonStatus | null>;
}

export interface CoreUpdateResult {
  changed: boolean;
  restarted: boolean;
  versions: CoreReleaseMap;
}

/** An OS-backed lock is released on process exit, including an interrupted update. */
export function acquireCoreUpdateLock(paths: AppPaths): () => void {
  return acquireCoreSelectionLock(paths);
}

const updatesDefaults: CoreUpdateOperations = {
  acquireLock: acquireCoreUpdateLock, readConfig, readSelection: readCoreSelection, writeSelection: writeCoreSelection,
  prepare: prepareCoreRelease, ensure: ensureSingleCore,
  preflight: async (paths, config, releases, report) => { await preflightCores(paths, config, { releases, publish: false, report }); },
  getStatus: getDaemonStatus, getStartup: getStartupStatus,
  verifyStopped: async paths => { const release = acquireDaemonLock(paths); release(); },
  startManaged, stopManaged, startPortable: startDetachedDaemon, stopPortable: stopDaemonGracefully,
  waitReady: paths => waitForReady(paths, 45000),
};

function updatesRuntimeMatches(status: DaemonStatus, config: AppConfig): boolean {
  return status.runtimeConfigHash
    ? status.runtimeConfigHash === runtimeConfigFingerprint(config)
    : status.configHash === configFingerprint(config);
}

function updatesReportedReleaseHash(status: DaemonStatus): string | undefined {
  // Optional when inspecting a worker launched by an older script.
  return (status as DaemonStatus & { coreReleaseHash?: string }).coreReleaseHash;
}

function updatesRuntimeIdentity(status: DaemonStatus | null): string {
  return status ? JSON.stringify([status.instanceId, status.pid, status.configHash, status.runtimeConfigHash, updatesReportedReleaseHash(status)]) : "stopped";
}

function updatesStartupIdentity(status: StartupStatus): string {
  return JSON.stringify([status.mode, status.enabled, status.running]);
}

function updatesAssertReady(status: DaemonStatus | null, config: AppConfig, versions: CoreReleaseMap, oldInstance?: string): void {
  if (!status || status.phase !== "ready") throw new Error(`后台尚未就绪${status?.lastError ? `：${status.lastError}` : "，请查看节点状态和日志"}。`);
  if (oldInstance && status.instanceId === oldInstance) throw new Error("后台仍是切换前的实例，尚未确认新内核已启动。");
  if (!updatesRuntimeMatches(status, config)) throw new Error("后台加载的节点配置与预检配置不一致。");
  const selected = updatesReportedReleaseHash(status);
  if (!selected) throw new Error("后台没有报告内核版本，无法确认切换结果。请确认后台运行的是更新后的 NexusEdge 脚本。");
  if (selected !== coreReleaseFingerprint(versions)) throw new Error("后台加载的内核版本与本次选择不一致。");
}

interface UpdatesSnapshot {
  config: AppConfig;
  selection: CoreSelectionState;
  status: DaemonStatus | null;
  startup: StartupStatus;
}

async function updatesSnapshot(paths: AppPaths, ops: CoreUpdateOperations): Promise<UpdatesSnapshot> {
  const config = structuredClone(ops.readConfig(paths));
  const selection = structuredClone(ops.readSelection(paths));
  const [status, startup] = await Promise.all([ops.getStatus(paths), ops.getStartup(paths)]);
  if (!status && startup.running) throw new Error("系统后台正在运行，但暂时无法确认其配置和状态。请等后台启动完成后再更新内核。");
  if (status?.phase === "stopping") throw new Error("后台正在停止，请等停止完成后再更新内核。");
  if (status && !updatesRuntimeMatches(status, config)) throw new Error("已保存的节点配置尚未应用。请先在主菜单启动 / 重启全部节点，再更新内核。");
  const releaseHash = status && updatesReportedReleaseHash(status);
  if (releaseHash && releaseHash !== coreReleaseFingerprint(selection.active)) throw new Error("已选择的内核版本尚未应用。请先在主菜单启动 / 重启全部节点，再进行下一次内核更新。");
  return { config, selection, status: status && structuredClone(status), startup: structuredClone(startup) };
}

function updatesAssertSavedUnchanged(paths: AppPaths, snapshot: UpdatesSnapshot, ops: CoreUpdateOperations): void {
  if (configFingerprint(ops.readConfig(paths)) !== configFingerprint(snapshot.config)) throw new Error("检查期间节点配置发生了变化，已取消切换。请重新检查内核更新。");
  if (JSON.stringify(ops.readSelection(paths)) !== JSON.stringify(snapshot.selection)) throw new Error("检查期间内核版本选择发生了变化，已取消切换。请重新检查内核更新。");
}

function updatesAssertExpectedSelection(snapshot: UpdatesSnapshot, expectedSelection?: CoreSelectionState): void {
  if (expectedSelection && JSON.stringify(snapshot.selection) !== JSON.stringify(expectedSelection)) throw new Error("确认期间内核版本选择发生了变化，已取消本次操作。请重新检查版本后再确认。");
}

async function updatesAssertUnchanged(paths: AppPaths, snapshot: UpdatesSnapshot, ops: CoreUpdateOperations): Promise<void> {
  updatesAssertSavedUnchanged(paths, snapshot, ops);
  const [status, startup] = await Promise.all([ops.getStatus(paths), ops.getStartup(paths)]);
  if (updatesRuntimeIdentity(status) !== updatesRuntimeIdentity(snapshot.status) || updatesStartupIdentity(startup) !== updatesStartupIdentity(snapshot.startup) || status?.phase === "stopping") {
    throw new Error("检查期间后台或自启状态发生了变化，已取消切换。请在状态稳定后重试。");
  }
  if (!snapshot.status) await ops.verifyStopped(paths);
}

async function updatesSwitch(paths: AppPaths, snapshot: UpdatesSnapshot, versions: CoreReleaseMap, report: (message: string) => void, ops: CoreUpdateOperations): Promise<CoreUpdateResult> {
  if (coreReleaseFingerprint(versions) === coreReleaseFingerprint(snapshot.selection.active)) return { changed: false, restarted: false, versions: snapshot.selection.active };
  if (snapshot.config.nodes.some(node => node.enabled)) {
    report("使用现有节点配置检查候选内核，当前后台继续运行……");
    await ops.preflight(paths, snapshot.config, versions, report);
  }
  await updatesAssertUnchanged(paths, snapshot, ops);
  const stop = snapshot.startup.mode === "none" ? ops.stopPortable : ops.stopManaged;
  const start = snapshot.startup.mode === "none" ? ops.startPortable : ops.startManaged;
  const wasRunning = Boolean(snapshot.status);
  const next: CoreSelectionState = { schema: 1, active: structuredClone(versions), previous: structuredClone(snapshot.selection.active), updatedAt: new Date().toISOString() };
  let stopAttempted = false, selectionAttempted = false, startAttempted = false;
  try {
    if (wasRunning) {
      report("配置检查通过，正在重启后台以应用所选内核……");
      stopAttempted = true;
      await stop(paths);
      await ops.verifyStopped(paths);
    }
    // Stopping can take seconds; another panel may have saved configuration meanwhile.
    updatesAssertSavedUnchanged(paths, snapshot, ops);
    selectionAttempted = true;
    ops.writeSelection(paths, next);
    if (wasRunning) {
      startAttempted = true;
      await start(paths);
      updatesAssertReady(await ops.waitReady(paths), snapshot.config, versions, snapshot.status?.instanceId);
      if (coreReleaseFingerprint(ops.readSelection(paths).active) !== coreReleaseFingerprint(versions)) throw new Error("后台启动期间内核选择再次发生变化，无法确认本次切换结果。");
      report("内核已切换，后台已就绪。旧版本已保留，可从内核管理回退。");
    } else report("内核版本已保存，后台保持停止。下次启动节点时使用所选版本。");
    return { changed: true, restarted: wasRunning, versions: structuredClone(versions) };
  } catch (originalError) {
    const failures: string[] = [];
    let canRestart = true, originalStillRunning = false, restoredReady = false;
    if (startAttempted) {
      try { await stop(paths); await ops.verifyStopped(paths); }
      catch (error) { canRestart = false; failures.push(`候选后台停止未确认：${errorMessage(error)}`); }
    }
    if (selectionAttempted) {
      try { ops.writeSelection(paths, structuredClone(snapshot.selection)); }
      catch (error) { canRestart = false; failures.push(`原内核版本选择恢复失败：${errorMessage(error)}`); }
    }
    if (wasRunning && stopAttempted && !startAttempted) {
      try {
        const current = await ops.getStatus(paths);
        if (current && updatesRuntimeIdentity(current) === updatesRuntimeIdentity(snapshot.status) && current.phase !== "stopping") originalStillRunning = true;
        else if (current) { canRestart = false; failures.push("后台状态仍在变化，尚未确认原实例已停止。"); }
        else await ops.verifyStopped(paths);
      } catch (error) { canRestart = false; failures.push(`原后台停止未确认：${errorMessage(error)}`); }
    }
    if (wasRunning && stopAttempted && canRestart && !originalStillRunning) {
      try {
        if (runtimeConfigFingerprint(ops.readConfig(paths)) !== runtimeConfigFingerprint(snapshot.config)) throw new Error("恢复期间节点配置发生变化，请先检查已保存配置再启动后台。");
        if (JSON.stringify(ops.readSelection(paths)) !== JSON.stringify(snapshot.selection)) throw new Error("恢复期间内核版本选择发生变化，请先检查已保存版本再启动后台。");
        await start(paths);
        updatesAssertReady(await ops.waitReady(paths), snapshot.config, snapshot.selection.active, snapshot.status?.instanceId);
        restoredReady = true;
      } catch (error) { failures.push(`原版本后台恢复未就绪：${errorMessage(error)}`); }
    }
    const recovery = failures.length
      ? `\n恢复时遇到问题：\n${failures.join("\n")}\n请查看日志和当前后台状态，再从主菜单重启；不要重复创建另一套后台。`
      : restoredReady ? "\n已恢复原内核版本和原后台，并确认后台就绪。临时隧道重连后请重新查看链接。"
      : originalStillRunning ? "\n原内核版本选择已保留，原后台仍在运行。"
      : "\n原内核版本选择已恢复，后台保持停止。";
    throw new Error(redact(`内核切换失败：${errorMessage(originalError)}${recovery}`, collectConfigSecrets(snapshot.config)));
  }
}

/** Prepare every selected download before changing any runtime selection. */
export async function applyCoreUpdates(paths: AppPaths, candidates: CoreReleaseCandidate[], report: (message: string) => void = () => {}, operations: Partial<CoreUpdateOperations> = {}, expectedSelection?: CoreSelectionState): Promise<CoreUpdateResult> {
  const ops: CoreUpdateOperations = { ...updatesDefaults, ...operations };
  const releaseLock = ops.acquireLock(paths);
  try {
    const snapshot = await updatesSnapshot(paths, ops);
    updatesAssertExpectedSelection(snapshot, expectedSelection);
    if (!candidates.length) return { changed: false, restarted: false, versions: snapshot.selection.active };
    const tools = candidates.map(candidate => candidate.tool);
    if (new Set(tools).size !== tools.length) throw new Error("一次内核更新不能重复选择同一内核。");
    const versions = structuredClone(snapshot.selection.active);
    for (const candidate of candidates) {
      const prepared = await ops.prepare(paths, candidate, report);
      if (prepared.tool !== candidate.tool || prepared.version !== candidate.version || prepared.asset.sha256 !== candidate.asset.sha256) throw new Error("准备完成的发行包与所选版本不一致，已取消更新。");
      versions[prepared.tool] = prepared;
    }
    return await updatesSwitch(paths, snapshot, versions, report, ops);
  } finally { releaseLock(); }
}

/** A rollback has the same compatibility and recovery checks as an upgrade. */
export async function rollbackCoreUpdates(paths: AppPaths, report: (message: string) => void = () => {}, operations: Partial<CoreUpdateOperations> = {}, expectedSelection?: CoreSelectionState): Promise<CoreUpdateResult> {
  const ops: CoreUpdateOperations = { ...updatesDefaults, ...operations };
  const releaseLock = ops.acquireLock(paths);
  try {
    const snapshot = await updatesSnapshot(paths, ops);
    updatesAssertExpectedSelection(snapshot, expectedSelection);
    if (!snapshot.selection.previous) throw new Error("还没有可回退的内核版本。首次成功升级后会保留上一次版本。");
    const previous = structuredClone(snapshot.selection.previous);
    for (const tool of ["singBox", "xray", "cloudflared"] as const) {
      const current = snapshot.selection.active[tool], target = previous[tool];
      if (JSON.stringify(current) !== JSON.stringify(target)) await ops.ensure(paths, target, report);
    }
    return await updatesSwitch(paths, snapshot, previous, report, ops);
  } finally { releaseLock(); }
}


// ==================== ui.ts ====================
import * as uiReadline from "node:readline";
import * as uiStream from "node:stream";

export class UserCancelledError extends Error { constructor() { super("已取消当前操作。"); } }
export class UiExitRequestedError extends Error { constructor() { super("已退出管理面板。"); } }
const uiAnsi = { reset: "\x1b[0m", cyan: "\x1b[36m", green: "\x1b[32m", yellow: "\x1b[33m", dim: "\x1b[2m", bold: "\x1b[1m" };
let uiKeyEventsInitialized = false;

/** Raw mode is scoped to one menu. Every exit path restores the cursor and stdin. */
export async function selectMenu(title: string, information: string, choices: string[], initial = 0): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(`\n${title}\n${information}`);
    choices.forEach((item, index) => console.log(`${index + 1}. ${item}`));
    for (;;) {
      const answer = await promptInput("输入选项编号", String(initial + 1));
      const n = Number(answer);
      if (Number.isInteger(n) && n >= 1 && n <= choices.length) return n - 1;
      console.log("请输入列表中的编号。");
    }
  }
  if (!uiKeyEventsInitialized) { uiReadline.emitKeypressEvents(process.stdin); uiKeyEventsInitialized = true; }
  return new Promise((resolve, reject) => {
    let selected = Math.min(Math.max(initial, 0), choices.length - 1);
    const wasRaw = Boolean(process.stdin.isRaw);
    const render = () => {
      process.stdout.write("\x1b[2J\x1b[H\x1b[?25l");
      console.log(`${uiAnsi.bold}${uiAnsi.cyan}NexusEdge ${APP_VERSION}${uiAnsi.reset}\n`);
      if (information) console.log(information + "\n");
      console.log(`${uiAnsi.bold}${title}${uiAnsi.reset}\n`);
      choices.forEach((choice, index) => console.log(index === selected ? `${uiAnsi.cyan}  › ${index + 1}. ${choice}${uiAnsi.reset}` : `    ${index + 1}. ${choice}`));
      console.log(`\n${uiAnsi.dim}↑/↓ 或 j/k 选择 · Enter 确定 · 数字直接选择 · Esc 返回 · Ctrl+C 退出面板${uiAnsi.reset}`);
    };
    const cleanup = () => {
      process.stdin.removeListener("keypress", onKey);
      process.stdin.removeListener("end", onEnd);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\x1b[?25h");
    };
    const onEnd = () => { cleanup(); reject(new UserCancelledError()); };
    const onKey = (text: string, key: uiReadline.Key) => {
      if (key.ctrl && key.name === "c") { cleanup(); reject(new UiExitRequestedError()); return; }
      if (key.name === "escape") { cleanup(); reject(new UserCancelledError()); return; }
      if (key.name === "up" || key.name === "k") selected = (selected + choices.length - 1) % choices.length;
      else if (key.name === "down" || key.name === "j") selected = (selected + 1) % choices.length;
      else if (key.name === "return") { cleanup(); resolve(selected); return; }
      else if (/^[1-9]$/.test(text) && Number(text) <= choices.length) { cleanup(); resolve(Number(text) - 1); return; }
      else return;
      render();
    };
    process.stdin.on("keypress", onKey);
    process.stdin.once("end", onEnd);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    render();
  });
}

class UiMutedOutput extends uiStream.Writable {
  _write(_chunk: unknown, _encoding: string, callback: (error?: Error | null) => void): void { callback(); }
}

export async function promptInput(label: string, current = "", options: { secret?: boolean; clearable?: boolean } = {}): Promise<string> {
  const display = options.secret && current ? "已设置，回车保留" : current;
  const hint = [display ? `[${display}]` : "", options.clearable ? "输入 - 清除" : ""].filter(Boolean).join("；");
  return new Promise((resolve, reject) => {
    const hidden = Boolean(options.secret && process.stdin.isTTY);
    const output = hidden ? new UiMutedOutput() : process.stdout;
    const rl = uiReadline.createInterface({ input: process.stdin, output, terminal: Boolean(process.stdin.isTTY) });
    let answered = false;
    const cancel = () => { if (!answered) { answered = true; rl.close(); reject(new UiExitRequestedError()); } };
    rl.once("SIGINT", cancel);
    rl.once("close", () => { if (!answered) { answered = true; reject(new UserCancelledError()); } });
    const prompt = `${label}${hint ? `（${hint}）` : ""}：`;
    if (hidden) process.stdout.write(prompt);
    process.stdin.resume();
    rl.question(hidden ? "" : prompt, answer => {
      answered = true; rl.close();
      if (hidden) process.stdout.write("\n");
      const trimmed = answer.trim();
      resolve(options.clearable && trimmed === "-" ? "" : trimmed || current);
    });
  });
}

export async function uiPause(): Promise<void> { await promptInput("按 Enter 返回面板"); }

export async function uiValidatedInput(label: string, current: string, validate: (value: string) => string, options: { secret?: boolean; clearable?: boolean } = {}): Promise<string> {
  for (;;) {
    const value = await promptInput(label, current, options);
    try { return validate(value); }
    catch (e) { console.log(`输入有误：${errorMessage(e)}`); }
  }
}



// ==================== simple.ts ====================
import * as simpleNet from "node:net";
import * as simpleDgram from "node:dgram";
import * as simpleCrypto from "node:crypto";

export interface SimplePanelServices {
  detectAddresses: () => Promise<PublicAddressResult>;
  localAddresses: () => LocalAddressCandidate[];
  availablePort: (node: NodeConfig, others: NodeConfig[]) => Promise<number>;
  certificate: typeof generateSelfSignedCertificate;
  encryption: typeof generateVlessEncryption;
}
export interface SimplePanelActions {
  /** Preflight before saving, then apply. A failed preflight must keep the previous config. */
  apply: (config: AppConfig) => Promise<void>;
  advanced: (node: NodeConfig) => Promise<void>;
}

function simpleService(overrides: Partial<SimplePanelServices> = {}): SimplePanelServices {
  return { detectAddresses: detectPublicAddresses, localAddresses: listLocalAddresses,
    availablePort: findAvailableNodePort, certificate: generateSelfSignedCertificate,
    encryption: generateVlessEncryption, ...overrides };
}

function simpleProbePort(node: NodeConfig, port: number, network: "tcp" | "udp"): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const failed = (error: NodeJS.ErrnoException) => {
      if (error.code === "EADDRINUSE") resolve(false);
      else reject(new Error(`无法检查本机端口 ${port}：${error.code || error.message}`));
    };
    if (network === "tcp") {
      const server = simpleNet.createServer();
      server.once("error", failed);
      server.listen({ host: node.listen, port, exclusive: true }, () => server.close(() => resolve(true)));
    } else {
      const socket = simpleDgram.createSocket(simpleNet.isIP(node.listen) === 6 ? "udp6" : "udp4");
      socket.once("error", error => { try { socket.close(); } catch {} failed(error); });
      socket.bind({ address: node.listen, port, exclusive: true }, () => socket.close(() => resolve(true)));
    }
  });
}

/** Check both configured reservations and the actual TCP/UDP sockets. This is not a permanent reservation. */
export async function findAvailableNodePort(node: NodeConfig, others: NodeConfig[]): Promise<number> {
  const networks = nodeListenNetworks(node);
  for (let offset = 0; offset < 128 && node.port + offset <= 65535; offset++) {
    const port = node.port + offset;
    if (others.some(other => other.id !== node.id && other.enabled && other.port === port && nodeListenNetworks(other).some(network => networks.includes(network)))) continue;
    let available = true;
    for (const network of networks) if (!await simpleProbePort(node, port, network)) { available = false; break; }
    if (available) return port;
  }
  throw new Error("附近的默认端口均被占用，请在“连接地址与端口”里指定另一个端口。");
}

export function normalizeClientAddress(value: string): string {
  const address = normalizeConnectAddress(value);
  if (!address || address === "0.0.0.0" || address === "::") {
    throw new Error("请填手机 / 电脑实际连接的服务器 IP 或域名。0.0.0.0 / :: 是本机监听范围，不能用于连接。");
  }
  return address;
}

export function directListenerNotice(node: NodeConfig): string {
  if (!node.direct || !node.address) return "";
  const family = simpleNet.isIP(node.address);
  if (["127.0.0.1", "::1"].includes(node.listen) && !["127.0.0.1", "::1", "localhost"].includes(node.address)) {
    return "当前只接收本机连接；若没有反向代理，请在地址设置中改为对外监听并应用配置。";
  }
  if (family === 6 && simpleNet.isIP(node.listen) === 4) return "连接地址是 IPv6，本机却只监听 IPv4；请在地址设置中调整监听范围并应用配置。";
  if (family === 4 && simpleNet.isIP(node.listen) === 6 && node.listen !== "::") return "连接地址是 IPv4，本机却只监听指定 IPv6；请检查地址设置中的监听范围。";
  return "";
}

/** Only a new draft may automatically change wildcard listener family. Existing deliberate bindings stay intact. */
export function applyDetectedAddress(node: NodeConfig, result: PublicAddressResult, newDraft = false): { node: NodeConfig; notice: string } {
  const next = structuredClone(node);
  if (result.cancelled) return { node: next, notice: "公网 IP 探测已取消，连接地址保持原值。" };
  const v6Listener = simpleNet.isIP(node.listen) === 6;
  const address = newDraft ? result.ipv4 || result.ipv6 : v6Listener ? result.ipv6 || (node.listen === "::" ? result.ipv4 : null) : result.ipv4;
  if (!address) {
    const mismatch = !newDraft && !v6Listener && result.ipv6;
    return { node: next, notice: mismatch
      ? "只检测到公网 IPv6，当前节点监听 IPv4。可手动填 IPv6 并调整监听范围，或填写可达的 IPv4 / 域名。"
      : "暂未探测到公网 IP；可重试、手动填写服务器 IP / 域名，或选择局域网地址。" };
  }
  next.address = normalizeClientAddress(address);
  if (newDraft && ["0.0.0.0", "::"].includes(next.listen)) next.listen = simpleNet.isIP(address) === 6 ? "::" : "0.0.0.0";
  const extra = result.warnings.filter(item => /WARP/i.test(item));
  if (simpleNet.isIP(address) === 6) extra.unshift("使用 IPv6 地址时，客户端所在网络也需要能访问 IPv6。");
  return { node: next, notice: [`已自动填写公网 ${simpleNet.isIP(address) === 6 ? "IPv6" : "IPv4"}。探测得到的是出口地址；有 NAT / 系统 VPN 时，请核对实际可达地址。`, ...extra].join("\n") };
}

async function simpleDetect(node: NodeConfig, service: SimplePanelServices, newDraft: boolean): Promise<{ node: NodeConfig; notice: string }> {
  console.log("正在自动获取公网 IP（优先 IPv4，最多约 3 秒）……");
  try { return applyDetectedAddress(node, await service.detectAddresses(), newDraft); }
  catch { return { node: structuredClone(node), notice: "公网 IP 探测暂时失败。可手动填写 VPS 的 IP / 域名，或选择局域网地址。" }; }
}

async function simplePort(label: string, current: number): Promise<number> {
  return Number(await uiValidatedInput(label, String(current), value => {
    if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error("请输入 1–65535 的整数端口。");
    return value;
  }));
}

function simpleAssignManual(node: NodeConfig, address: string, newDraft: boolean): void {
  node.address = normalizeClientAddress(address);
  if (newDraft && ["0.0.0.0", "::"].includes(node.listen) && simpleNet.isIP(node.address)) node.listen = simpleNet.isIP(node.address) === 6 ? "::" : "0.0.0.0";
}

async function simpleLocalAddress(node: NodeConfig, service: SimplePanelServices, newDraft: boolean): Promise<string> {
  // Scoped IPv6 link-local addresses need an interface zone, which this client model does not support.
  const addresses = service.localAddresses().filter(item => item.scope !== "link-local");
  if (!addresses.length) return "没有可用的本机网卡地址，请手动填写。";
  let page = 0;
  for (;;) {
    const start = page * 6, visible = addresses.slice(start, start + 6);
    const labels = visible.map(item => `${item.address} · ${item.interfaceName} · ${item.scope === "public" ? "网卡公网地址" : item.scope === "shared" ? "运营商共享地址" : "局域网"}`);
    const previous = page ? labels.push("上一页") - 1 : -1;
    const next = start + visible.length < addresses.length ? labels.push("下一页") - 1 : -1;
    const back = labels.push("返回") - 1;
    const selected = await selectMenu("选择本机网卡地址", "局域网地址通常只供同一网络使用。这里不会把它当成公网 IP。", labels);
    if (selected === back) return "连接地址保持不变。";
    if (selected === previous) { page--; continue; }
    if (selected === next) { page++; continue; }
    simpleAssignManual(node, visible[selected]!.address, newDraft);
    return "已选择本机网卡地址，请确认客户端处于能够访问它的网络。";
  }
}

/** This screen edits only address/ports, except an explicitly chosen listener repair. */
export async function editConnectionAddress(node: NodeConfig, overrides: Partial<SimplePanelServices> = {}, newDraft = false): Promise<NodeConfig> {
  const service = simpleService(overrides);
  let draft = structuredClone(node), notice = "";
  for (;;) {
    const warning = directListenerNotice(draft);
    const actions = ["重新自动探测公网 IP", "手动填写服务器 IP / 域名", "选择局域网 / 本机网卡地址", "修改本机端口", "设置对外映射端口（NAT）",
      ...(warning ? ["调整为匹配连接地址的对外监听（应用后生效）"] : []), "返回摘要"];
    const selected = await selectMenu("连接地址与端口", [
      `客户端连接：${draft.address ? draft.address.includes(":") ? `[${draft.address}]` : draft.address : "尚未填写"}:${draft.publicPort}`,
      `本机端口：${draft.port}；监听范围：${draft.listen}`,
      "服务器 / VPS 的 IP 是客户端连接地址；0.0.0.0 表示接收所有本机 IPv4 网卡的连接。",
      "一般只需修改第一项地址；没有端口映射时，对外端口与本机端口相同。", warning, notice,
    ].filter(Boolean).join("\n"), actions);
    if (selected === actions.length - 1) return draft;
    try {
      if (selected === 0) { const result = await simpleDetect(draft, service, newDraft); draft = result.node; notice = result.notice; }
      else if (selected === 1) { simpleAssignManual(draft, await uiValidatedInput("客户端实际连接的 IP / 域名", draft.address, normalizeClientAddress), newDraft); notice = "已使用手动地址，自动探测不会覆盖它。"; }
      else if (selected === 2) notice = await simpleLocalAddress(draft, service, newDraft);
      else if (selected === 3) {
        const previous = draft.port;
        draft.port = await simplePort("本机服务端口", draft.port);
        if (draft.publicPort === previous) draft.publicPort = draft.port;
        notice = "修改本机端口需要应用配置；已独立设置的 NAT 映射端口会保留。";
      } else if (selected === 4) { draft.publicPort = await simplePort("客户端连接的对外端口", draft.publicPort); notice = "仅更新链接中的端口；请与已有的端口映射一致。"; }
      else if (selected === 5 && warning) {
        draft.listen = simpleNet.isIP(draft.address) === 6 ? "::" : "0.0.0.0";
        notice = "已在草稿中改为接收对应网卡的连接。保存并应用后生效。";
      }
    } catch (error) { if (error instanceof UiExitRequestedError) throw error; if (error instanceof UserCancelledError) continue; notice = errorMessage(error); }
  }
}

/** Missing-address recovery is the only exceptional path with extra required input. */
async function simpleMissingAddress(node: NodeConfig, service: SimplePanelServices, newDraft: boolean, allowDeferred: boolean): Promise<NodeConfig> {
  let draft = structuredClone(node), notice = "";
  while (!draft.address) {
    const selected = await selectMenu("补齐客户端连接地址", [
      "自动探测尚未得到与此节点匹配的公网 IP。这里需要客户端能访问的 VPS IP / 域名。",
      "0.0.0.0 仅表示本机监听范围，不是服务器的公网地址。", notice,
    ].filter(Boolean).join("\n"), ["重新自动探测", "手动填写 IP / 域名", "选择局域网地址", ...(allowDeferred ? ["仍然保存，稍后填写地址"] : []), "返回"]);
    if (selected === (allowDeferred ? 4 : 3)) throw new UserCancelledError();
    if (selected === 3 && allowDeferred) return draft;
    if (selected === 0) { const result = await simpleDetect(draft, service, newDraft); draft = result.node; notice = result.notice; }
    else if (selected === 1) simpleAssignManual(draft, await uiValidatedInput("客户端实际连接的 IP / 域名", "", normalizeClientAddress), newDraft);
    else notice = await simpleLocalAddress(draft, service, newDraft);
  }
  return draft;
}

/** Export repair writes only a missing address. It never changes UUID, mapping port, SNI or listener. */
export async function repairNodeAddress(paths: AppPaths, nodeId: string, overrides: Partial<SimplePanelServices> = {}): Promise<NodeConfig> {
  const service = simpleService(overrides);
  const node = readConfig(paths).nodes.find(item => item.id === nodeId);
  if (!node) throw new Error("节点已删除，请重新选择。");
  if (!node.direct || node.address) return node;
  let draft = (await simpleDetect(node, service, false)).node;
  if (!draft.address) draft = await simpleMissingAddress(draft, service, false, false);
  const config = readConfig(paths), current = config.nodes.find(item => item.id === nodeId);
  if (!current) throw new Error("节点已删除，请重新选择。");
  if (current.address) return current;
  if (current.listen !== node.listen || current.direct !== node.direct) throw new Error("节点监听设置已在另一处修改，请重新导出。");
  current.address = draft.address;
  writeConfig(paths, config);
  console.log(`已补入客户端地址：${current.address}。UUID、SNI、端口和监听设置保持原值。`);
  return current;
}

async function simpleAuthentication(node: NodeConfig): Promise<void> {
  const hasUuid = ["vless", "vmess", "tuic"].includes(node.protocol);
  const hasUser = ["socks", "naive"].includes(node.protocol);
  const hasPassword = !["vless", "vmess"].includes(node.protocol);
  const items = ["name", ...(hasUuid ? ["uuid"] : []), ...(hasUser ? ["username"] : []), ...(hasPassword ? ["password"] : []), "back"];
  const labels: Record<string, string> = { name: "修改节点名称", uuid: "修改 / 重新生成 UUID", username: "修改用户名", password: "修改 / 重新生成密码", back: "返回摘要" };
  for (;;) {
    const selected = items[await selectMenu("名称与认证", "认证信息已自动生成。只有希望使用自己的账号时才需要修改；不会因为编辑而自动重置。", items.map(item => labels[item]!))]!;
    if (selected === "back") return;
    if (selected === "name") node.name = await uiValidatedInput("节点名称", node.name, value => { validateNode({ ...node, name: value }, { allowIncomplete: true, allowExpiredCertificate: true }); return value; });
    else if (selected === "uuid") node.uuid = await uiValidatedInput("UUID（回车保留；new 生成新值）", node.uuid, value => {
      const next = value === "new" ? simpleCrypto.randomUUID() : value;
      validateNode({ ...node, uuid: next }, { allowIncomplete: true, allowExpiredCertificate: true });
      if (!next) throw new Error("UUID 不能为空。"); return next.toLowerCase();
    });
    else if (selected === "username") node.username = await uiValidatedInput("用户名", node.username, value => { if (!value) throw new Error("用户名不能为空。"); validateNode({ ...node, username: value }, { allowIncomplete: true, allowExpiredCertificate: true }); return value; });
    else node.password = await uiValidatedInput("密码（回车保留；new 生成新值）", node.password, value => {
      const next = value === "new" ? node.protocol === "shadowsocks" ? generateShadowsocksPassword(node.method) : simpleCrypto.randomBytes(24).toString("base64url") : value;
      if (!next) throw new Error("密码不能为空。");
      validateNode({ ...node, password: next }, { allowIncomplete: true, allowExpiredCertificate: true }); return next;
    }, { secret: true });
  }
}

async function simpleTunnel(node: NodeConfig): Promise<{ node: NodeConfig; prepareEncryption: boolean; notice: string }> {
  const mode = node.tunnel.mode;
  const convert = node.protocol === "vless" && mode === "none";
  const selected = await selectMenu("可选隧道", [
    "关闭：使用服务器地址直连。临时：自动分配域名。固定：使用你已有的 Token 和公共主机名。",
    "开启隧道保留当前直连选项；也可在这里明确改为仅隧道。",
    ...(convert ? ["VLESS 开启隧道时会自动改为 WebSocket；保留直连时自动准备 ENC 加密，需重新导入新链接。"] : []),
    `当前：${mode === "none" ? "关闭" : mode === "quick" ? "临时" : "固定"}；${node.direct ? "保留直连" : "仅隧道"}`,
  ].join("\n"), ["关闭隧道", "开启临时隧道（无需域名 / Token）", "开启固定隧道（域名 + Token）", ...(mode !== "none" ? [node.direct ? "改为仅隧道接入" : "同时保留直连接入"] : []), "返回摘要"], mode === "none" ? 0 : mode === "quick" ? 1 : 2);
  if (selected === (mode === "none" ? 3 : 4)) return { node, prepareEncryption: false, notice: "" };
  let next = structuredClone(node);
  if (selected === 3) {
    next.direct = !next.direct;
    next.listen = next.direct ? simpleNet.isIP(next.address) === 6 ? "::" : "0.0.0.0" : simpleNet.isIP(next.listen) === 6 ? "::1" : "127.0.0.1";
  } else {
    next = applySimpleTunnel(node, (["none", "quick", "fixed"] as const)[selected]!);
    if (next.tunnel.mode === "fixed") {
      next.tunnel.domain = await uiValidatedInput("固定隧道公共主机名（例如 node.example.com）", next.tunnel.domain, normalizeDomain);
      next.tunnel.token = await uiValidatedInput("Cloudflare 提供的完整 Tunnel Token", next.tunnel.token, value => {
        if (!/^[A-Za-z0-9_+/=-]{16,16384}$/.test(value)) throw new Error("请输入完整 Tunnel Token；不是 Tunnel ID 或 API Key。"); return value;
      }, { secret: true });
    }
  }
  const prepareEncryption = next.protocol === "vless" && next.tunnel.mode !== "none" && next.direct && next.vlessEncryption === "none" && (mode === "none" || !node.direct);
  const restoreVmessEncryption = next.protocol === "vmess" && next.tunnel.mode !== "none" && next.direct
    && ["none", "zero"].includes(next.vmessSecurity) && ((mode === "none" && node.tls.mode !== "none") || !node.direct);
  if (restoreVmessEncryption) next.vmessSecurity = "auto";
  let notice = "隧道选项已更新；UUID 与已有凭据保留。";
  if (next.protocol === "vless" && mode !== next.tunnel.mode) notice = next.tunnel.mode === "none"
    ? "隧道已关闭，VLESS 恢复 TCP + REALITY + Vision；保存应用后请重新导入链接。"
    : "VLESS 使用 WebSocket 隧道方案；实际直连安全设置见摘要，保存应用后请重新导入链接。";
  if (prepareEncryption) notice = "保留直连时会自动准备 VLESS ENC 加密。直连与隧道客户端都需要重新导入新链接。";
  if (restoreVmessEncryption) notice = "已为直连恢复 VMess 协议加密（auto）。保存应用后，直连与隧道客户端都需要重新导入新链接。";
  return { node: next, prepareEncryption, notice };
}

function simpleSummary(node: NodeConfig, existing: boolean, notice: string, prepareEncryption: boolean): string {
  const security = node.tls.mode === "reality" ? `REALITY（目标 ${node.tls.serverName}，密钥已准备）`
    : node.tls.mode === "tls" ? node.tls.certificatePem ? `TLS（已有证书，名称 ${node.tls.serverName}）` : "TLS（保存时自动生成独立证书，无需自备域名）"
    : node.protocol === "vless" ? prepareEncryption ? "ENC（保存时自动生成加密参数）" : node.vlessEncryption !== "none" ? "VLESS ENC" : "无附加 TLS / ENC"
    : node.protocol === "socks" ? "SOCKS5 用户名 / 密码认证" : node.protocol === "vmess" && ["none", "zero"].includes(node.vmessSecurity) ? "VMess 未开启协议加密 / TLS（已有高级配置）" : "协议自身加密";
  const endpoint = node.direct ? `${node.address ? node.address.includes(":") ? `[${node.address}]` : node.address : "尚未探测到 IP，可在下面补填"}:${node.publicPort}` : "仅隧道接入，无需填写 VPS IP";
  const tunnel = node.tunnel.mode === "none" ? "关闭（默认）" : node.tunnel.mode === "quick" ? "临时，启动后自动取得域名" : `固定，${node.tunnel.domain}`;
  const fixedOrigin = node.listen === "0.0.0.0" ? "127.0.0.1" : node.listen === "::" ? "::1" : node.listen;
  return [
    `${node.name} · ${node.protocol.toUpperCase()} / ${node.transport.type.toUpperCase()}`,
    `客户端连接：${endpoint}`, `认证：${existing ? "保留已有凭据" : "已自动生成，可自行修改"}`,
    `安全设置：${security}`, `隧道：${tunnel}；${node.direct ? "直连接入开启" : "直连接入关闭"}`,
    `节点状态：${node.enabled ? "启用" : "停用"}；出口：${node.egress === "direct" ? "本机网络" : "WARP"}`,
    ...(node.tunnel.mode === "fixed" ? [`Cloudflare 映射：${node.tunnel.domain} → http://${fixedOrigin.includes(":") ? `[${fixedOrigin}]` : fixedOrigin}:${node.port}`] : []),
    directListenerNotice(node), notice,
    "默认直接保存即可；只有自定义需求才需要高级配置。应用会重启当前后台，共享核心上的节点会短暂重连。",
  ].filter(Boolean).join("\n");
}

/** Default create path: protocol selection → summary → save/apply. Existing nodes open directly at the summary. */
export async function configureSimpleNode(paths: AppPaths, existing: NodeConfig | undefined, actions: SimplePanelActions, overrides: Partial<SimplePanelServices> = {}): Promise<void> {
  const service = simpleService(overrides), config = readConfig(paths);
  const original = existing ? config.nodes.find(item => item.id === existing.id) : undefined;
  let node: NodeConfig, notice = "", prepareEncryption = false;
  if (existing) node = structuredClone(original ?? existing);
  else {
    if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
    const protocol = NODE_PROTOCOLS[await selectMenu("选择节点协议 · 简易模式", "只选协议即可。IP、可用端口、UUID / 密码和必要的安全设置自动准备；隧道默认关闭。\n需要自己指定路径、SNI 等参数时，在下一页进入高级配置。", NODE_PROTOCOLS.map(item => SIMPLE_PROTOCOL_LABELS[item]))]!;
    node = createSimpleNode(protocol, config.nodes);
  }
  const newDraft = !original;
  if (node.direct && !node.address) { const detected = await simpleDetect(node, service, newDraft); node = detected.node; notice = detected.notice; }
  if (newDraft) {
    try { node.port = await service.availablePort(node, config.nodes); node.publicPort = node.port; }
    catch (error) { notice += `\n${errorMessage(error)}；可修改端口后重试。`; }
  }
  for (;;) {
    const items = ["apply", "save", ...(["vless", "vmess"].includes(node.protocol) ? ["tunnel"] : []), "address", "auth", "advanced", "cancel"];
    const labels: Record<string, string> = { apply: "保存并应用（准备核心 / 启动节点）", save: "仅保存，稍后启动", tunnel: "隧道设置（关闭 / 临时 / 固定）", address: "连接地址与端口", auth: "名称与 UUID / 密码", advanced: "高级配置（传输 / SNI / 证书 / 更多参数）", cancel: "取消，不保存" };
    const selected = items[await selectMenu("节点摘要 · 简易模式", simpleSummary(node, Boolean(original), notice, prepareEncryption), items.map(item => labels[item]!))]!;
    if (selected === "cancel") throw new UserCancelledError();
    try {
      if (selected === "tunnel") {
        const changed = await simpleTunnel(node); node = changed.node; notice = changed.notice;
        prepareEncryption = (prepareEncryption || changed.prepareEncryption) && node.tunnel.mode !== "none" && node.direct && node.vlessEncryption === "none";
      } else if (selected === "address") node = await editConnectionAddress(node, service, newDraft);
      else if (selected === "auth") await simpleAuthentication(node);
      else if (selected === "advanced") {
        if (prepareEncryption) { console.log("先准备已选择的 VLESS ENC 加密参数……"); Object.assign(node, await service.encryption(paths)); prepareEncryption = false; }
        await actions.advanced(structuredClone(node)); return;
      }
      else if (selected === "save" || selected === "apply") {
        if (node.direct && !node.address) node = await simpleMissingAddress(node, service, newDraft, true);
        if (prepareEncryption) {
          console.log("正在为 VLESS WebSocket 直连自动准备 ENC 加密参数……");
          Object.assign(node, await service.encryption(paths)); prepareEncryption = false;
        }
        if (node.enabled && node.tls.mode === "tls" && (!node.tls.certificatePem || !node.tls.keyPem)) {
          if (existing || node.tls.certificatePem || node.tls.keyPem) throw new Error("此节点已有的 TLS 证书 / 私钥不完整，请进入高级配置补齐；简易保存不会覆盖现有密钥。");
          console.log("正在自动生成此节点的 TLS 证书（首次会准备对应核心）……");
          Object.assign(node.tls, await service.certificate(paths, node));
          node.tls.insecure = true;
        }
        // Merge into the current file, preserving unrelated nodes and rejecting a concurrent edit to this node.
        const latest = readConfig(paths), current = latest.nodes.find(item => item.id === node.id);
        if (JSON.stringify(current) !== JSON.stringify(original)) throw new Error("这个节点已在另一处修改，请退出后重新打开，避免覆盖新设置。");
        const validated = validateNode(node, { allowExpiredCertificate: selected === "save" });
        const nodes = current ? latest.nodes.map(item => item.id === validated.id ? validated : item) : [...latest.nodes, validated];
        const candidate = validateConfig({ ...latest, nodes }, { allowExpiredCertificate: selected === "save" });
        if (selected === "apply") await actions.apply(candidate);
        else { writeConfig(paths, candidate); console.log("节点已保存。需要启用时选择主菜单的“启动 / 重启全部节点”。"); }
        return;
      }
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      if (error instanceof UserCancelledError) continue;
      notice = `操作未完成：${errorMessage(error)}`;
    }
  }
}


// ==================== core-panel.ts ====================

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


// ==================== panel.ts ====================
import * as panelFs from "node:fs";
import * as panelPath from "node:path";
import * as panelCrypto from "node:crypto";

const panelProtocolLabels: Record<NodeProtocol, string> = {
  vless: "VLESS", vmess: "VMess", shadowsocks: "Shadowsocks / SS2022", trojan: "Trojan",
  hysteria2: "Hysteria2", tuic: "TUIC", anytls: "AnyTLS", socks: "SOCKS5", naive: "NaiveProxy",
};
function panelEndpoint(node: NodeConfig): string {
  const mode = node.tunnel.mode === "none" ? "无隧道" : node.tunnel.mode === "quick" ? "临时隧道" : "固定隧道";
  return `${node.enabled ? "启用" : "停用"} · ${panelProtocolLabels[node.protocol]} / ${node.transport.type} · ${node.listen}:${node.port} · ${node.direct ? "直连" : "仅隧道"} · ${mode} · ${node.egress}`;
}
function panelTunnelOrigin(node: NodeConfig): string {
  const host = node.listen === "0.0.0.0" ? "127.0.0.1" : node.listen === "::" ? "::1" : node.listen;
  return `http://${host.includes(":") ? `[${host}]` : host}:${node.port}`;
}
async function panelInteger(label: string, current: number, minimum = 1, maximum = 65535): Promise<number> {
  return Number(await uiValidatedInput(label, String(current), value => {
    if (!/^\d+$/.test(value) || Number(value) < minimum || Number(value) > maximum) throw new Error(`请输入 ${minimum}–${maximum} 的整数。`);
    return value;
  }));
}
async function panelEnum<T extends string>(label: string, help: string, values: readonly T[], current: T, labels: readonly string[] = values): Promise<T> {
  return values[await selectMenu(label, help, [...labels], Math.max(0, values.indexOf(current)))]!;
}
async function panelPassword(node: NodeConfig): Promise<string> {
  const value = await promptInput("密码（回车保留；输入 new 重新生成）", node.password, { secret: true });
  return value === "new" ? node.protocol === "shadowsocks" ? generateShadowsocksPassword(node.method) : panelCrypto.randomBytes(24).toString("base64url") : value;
}
function panelReadPem(filename: string): string {
  const path = filename.trim().replace(/^"(.*)"$/, "$1");
  const info = panelFs.statSync(path);
  if (!info.isFile() || info.size > 512 * 1024) throw new Error("证书 / 私钥应为不超过 512 KiB 的普通 PEM 文件。");
  return panelFs.readFileSync(path, "utf8").replace(/^\uFEFF/, "");
}

async function panelWarp(config: AppConfig): Promise<AppConfig> {
  const choices = [...(config.warp ? ["保留已保存的 WARP 配置"] : []), "导入 WireGuard .conf / WARP JSON", "自动申请 WARP 配置", "取消"];
  const selected = await selectMenu("WARP 配置", "此处保存供节点共享的 WireGuard 凭据；各节点仍独立选择 Direct 或 WARP 出口。\n自动申请使用客户端兼容接口，失败时可导入已有配置。", choices);
  const offset = config.warp ? 1 : 0;
  if (config.warp && selected === 0) return config;
  if (selected === choices.length - 1) throw new UserCancelledError();
  if (selected === offset) {
    const path = (await promptInput("已有 WireGuard / WARP 配置文件路径")).replace(/^"(.*)"$/, "$1");
    const info = panelFs.statSync(path);
    if (!info.isFile() || info.size > 256 * 1024) throw new Error("请选择不超过 256 KiB 的普通配置文件。");
    return { ...config, warp: parseWarpProfile(panelFs.readFileSync(path, "utf8")) };
  }
  const consent = await selectMenu("申请新的 WARP 设备配置", "将向 Cloudflare 注册设备，并在本机保存私钥。请确认你接受 WARP 使用条款：\nhttps://www.cloudflare.com/application/terms/", ["同意并申请", "取消"]);
  if (consent !== 0) throw new UserCancelledError();
  console.log("正在申请 WARP 配置……");
  return { ...config, warp: await registerWarp() };
}

async function panelSecurity(paths: AppPaths, node: NodeConfig): Promise<void> {
  const previousSecurity = node.tls.mode;
  const plainOnly = ["shadowsocks", "socks"].includes(node.protocol) || node.tunnel.mode !== "none";
  if (plainOnly) { node.tls.mode = "none"; node.flow = ""; return; }
  const allowed: NodeConfig["tls"]["mode"][] = node.protocol === "vless" ? node.transport.type === "ws" ? ["none", "tls"] : ["none", "tls", "reality"]
    : node.protocol === "anytls" ? ["tls", "reality"] : node.protocol === "vmess" ? ["none", "tls"] : ["tls"];
  node.tls.mode = await panelEnum("节点安全层", "TLS 可以导入证书或生成自签证书；REALITY 使用握手目标与密钥。", allowed, node.tls.mode,
    allowed.map(value => value === "none" ? "不附加 TLS" : value === "tls" ? "TLS 证书" : "REALITY"));
  if (node.tls.mode === "none") { node.flow = ""; return; }
  const suggestedName = node.tls.mode === "reality" ? node.tls.serverName || node.tls.reality.handshakeServer : node.tls.serverName || node.address || "nexus.local";
  console.log(node.tls.mode === "reality"
    ? "SNI 是 REALITY 目标网站的域名，需要与下面的握手目标匹配；不是 VPS 的 IP，也不要求你拥有这个域名。"
    : "SNI 是证书对应的名称，不是本机监听 IP。使用自动证书时保留已有名称即可；使用自己的证书时填证书覆盖的域名。"
  );
  node.tls.serverName = await uiValidatedInput("TLS / REALITY 服务器名称（SNI；通常保留）", suggestedName, value => {
    const result = node.tls.mode === "reality" ? normalizeDomain(value) : normalizeConnectAddress(value);
    if (!result) throw new Error("请填写服务器名称或证书 IP。"); return result;
  });
  if (node.tls.mode === "reality") {
    node.tls.insecure = false;
    node.tls.reality.handshakeServer = await uiValidatedInput("REALITY 握手目标主机（支持 TLS 1.3 的真实站点）", node.tls.reality.handshakeServer || node.tls.serverName, value => {
      const result = normalizeConnectAddress(value); if (!result) throw new Error("握手目标不能为空。"); return result;
    });
    node.tls.reality.handshakePort = await panelInteger("REALITY 握手目标端口", node.tls.reality.handshakePort);
    const hasKey = Boolean(node.tls.reality.privateKey);
    const choices = [...(hasKey ? ["保留已有 REALITY 密钥"] : []), "生成新的 REALITY 密钥对", "输入自己的 REALITY 私钥"];
    const action = await selectMenu("REALITY 密钥", "公钥会从私钥派生，用于生成客户端配置；私钥只保存在服务端配置中。", choices);
    const offset = hasKey ? 1 : 0;
    if (action === offset) Object.assign(node.tls.reality, generateRealityKeyPair());
    if (action === offset + 1) {
      node.tls.reality.privateKey = await uiValidatedInput("REALITY 私钥", node.tls.reality.privateKey, value => { deriveRealityPublicKey(value); return value; }, { secret: true });
      node.tls.reality.publicKey = deriveRealityPublicKey(node.tls.reality.privateKey);
    }
    node.tls.reality.shortId = await uiValidatedInput("REALITY Short ID（偶数位十六进制，最长 16 位；- 留空）", node.tls.reality.shortId || (hasKey ? "" : panelCrypto.randomBytes(8).toString("hex")), value => {
      if (!/^(?:[0-9a-fA-F]{2}){0,8}$/.test(value)) throw new Error("Short ID 须为 0–16 位偶数长度的十六进制。"); return value.toLowerCase();
    }, { clearable: true });
  } else {
    const hasCertificate = Boolean(node.tls.certificatePem && node.tls.keyPem);
    const selfSignedDescription = node.protocol === "vless" ? "生成自签证书（客户端固定证书指纹）" : node.protocol === "naive" ? "生成自签证书（客户端信任此证书）" : "生成自签证书（客户端跳过 CA 校验）";
    const choices = [...(hasCertificate ? ["保留已有证书与私钥"] : []), "导入 PEM 证书与私钥文件", selfSignedDescription];
    const action = await selectMenu("TLS 证书", "证书与私钥内容会随节点配置保存，系统安装迁移时会一并复制。", choices);
    const offset = hasCertificate ? 1 : 0;
    if (action === offset) {
      node.tls.certificatePem = panelReadPem(await promptInput("PEM 证书文件路径"));
      node.tls.keyPem = panelReadPem(await promptInput("PEM 私钥文件路径"));
      node.tls.insecure = false;
    }
    if (action === offset + 1) {
      console.log("使用对应官方核心生成自签证书……");
      Object.assign(node.tls, await generateSelfSignedCertificate(paths, node));
      node.tls.insecure = true;
    }
    const localTrust = node.protocol === "vless" ? "固定此证书的 SHA-256 指纹（自签证书）" : node.protocol === "naive" ? "将此证书加入客户端信任配置（自签证书）" : "跳过 CA 校验（自签证书）";
    const trustHelp = node.protocol === "vless" ? "Xray 使用当前证书指纹校验自签证书。更换证书后，需要重新导出客户端配置。" : node.protocol === "naive" ? "Naive 自签模式在客户端 JSON 中内嵌公开证书，私钥不会导出。证书名称仍须匹配 SNI。" : "受信任证书建议严格校验；自签证书可使用跳过 CA 校验的客户端配置。";
    node.tls.insecure = (await selectMenu("客户端证书校验", trustHelp, ["使用系统受信任的 CA 校验证书", localTrust], node.tls.insecure ? 1 : 0)) === 1;
  }
  const suggestedAlpn = node.protocol === "hysteria2" || node.protocol === "tuic" ? "h3" : node.transport.type === "ws" ? "http/1.1" : node.transport.type === "grpc" || node.protocol === "naive" ? "h2" : "h2,http/1.1";
  const alpn = await promptInput("ALPN（英文逗号分隔；输入 - 留空交给核心）", node.tls.alpn.join(",") || (previousSecurity === "none" ? suggestedAlpn : ""), { clearable: true });
  node.tls.alpn = alpn ? alpn.split(",").map(value => value.trim()).filter(Boolean) : [];
}

/** Public for the real terminal workflow regression; it only saves after a final summary. */
export async function configureNode(paths: AppPaths, existing?: NodeConfig): Promise<void> {
  let config = readConfig(paths);
  const protocol = await panelEnum("选择节点协议 · 高级模式", "这里逐项自定义配置。通常可返回节点管理使用简易模式；编辑时回车保留已有参数。", NODE_PROTOCOLS, existing?.protocol ?? "vless", NODE_PROTOCOLS.map(item => panelProtocolLabels[item]));
  let node = existing?.protocol === protocol ? structuredClone(existing) : createDefaultNode(protocol, config.nodes.filter(item => item.id !== existing?.id));
  if (existing && existing.protocol !== protocol) { node.id = existing.id; node.name = existing.name; }
  node.name = await promptInput("节点名称", node.name);
  if (["vless", "vmess", "trojan"].includes(protocol)) {
    const transports: NodeConfig["transport"]["type"][] = protocol === "vless" ? ["tcp", "ws", "grpc", "xhttp"] : ["tcp", "ws", "grpc"];
    node.transport.type = await panelEnum("传输方式", "Cloudflare HTTP 隧道只适用于 VLESS / VMess 的 WebSocket 传输。", transports, node.transport.type);
  } else node.transport.type = "tcp";
  if (node.transport.type === "ws" || node.transport.type === "xhttp") {
    node.transport.path = await uiValidatedInput("传输路径，例如 /nexus-ws", node.transport.path, value => {
      if (!/^\/[A-Za-z0-9/._~-]*$/.test(value) || value.includes("//") || value.split("/").some(item => item === "." || item === "..")) throw new Error("路径仅允许 /、英文字母、数字、-._~，不要预先做 URL 编码。"); return value;
    });
    node.transport.host = await uiValidatedInput("传输 Host（留空使用连接地址）", node.transport.host, normalizeTransportHost, { clearable: true });
    if (node.transport.type === "xhttp") node.transport.mode = await panelEnum("XHTTP 模式", "服务端与导出客户端将使用相同模式。", ["auto", "packet-up", "stream-up", "stream-one"] as const, node.transport.mode);
  }
  if (node.transport.type === "grpc") node.transport.serviceName = await promptInput("gRPC serviceName", node.transport.serviceName);
  if (["vless", "vmess"].includes(protocol) && node.transport.type === "ws") {
    node.tunnel.mode = await panelEnum("是否额外开启隧道", "关闭时按节点 IP / 域名和端口直连；隧道与节点协议是独立选项。", ["none", "quick", "fixed"] as const, node.tunnel.mode, ["关闭隧道", "临时隧道（自动分配域名）", "固定隧道（Token + 公共主机名）"]);
  } else node.tunnel.mode = "none";
  if (node.tunnel.mode !== "none") {
    node.direct = (await selectMenu("节点接入方式", "仅隧道将监听本机回环地址；同时直连会开放所选监听地址。\n此组合的本机 WS 不附加 TLS，隧道客户端由 Cloudflare 提供 TLS。", ["仅通过隧道接入", "保留直连接入，同时开启隧道"], existing?.direct ? 1 : 0)) === 1;
    if (!node.direct) node.listen = node.listen.includes(":") ? "::1" : "127.0.0.1";
    if (node.tunnel.mode === "fixed") {
      node.tunnel.token = await uiValidatedInput("完整 Tunnel Token", node.tunnel.token, value => {
        if (!/^[A-Za-z0-9_+/=-]{16,16384}$/.test(value)) throw new Error("请输入完整 Tunnel Token。"); return value;
      }, { secret: true });
      node.tunnel.domain = await uiValidatedInput("隧道公共主机名", node.tunnel.domain, normalizeDomain);
    }
    node.tunnel.connectAddress = await uiValidatedInput("隧道客户端连接 IP / 域名（默认跟随隧道域名）", node.tunnel.connectAddress, normalizeConnectAddress, { clearable: true });
    node.tunnel.protocol = await panelEnum("隧道连接传输", "所在网络不允许 UDP 时可选择 HTTP2。", ["auto", "http2", "quic"] as const, node.tunnel.protocol, ["自动", "HTTP2", "QUIC"]);
  } else node.direct = true;
  if (node.direct) {
    console.log("监听 IP 控制本机哪些网卡接收连接，通常保持 0.0.0.0；它与下面供客户端使用的 VPS IP 是两项不同设置。");
    node.listen = await promptInput("监听 IP（本机范围；0.0.0.0 为全部 IPv4，:: 为 IPv6）", existing?.direct === false ? existing.listen === "::1" ? "::" : "0.0.0.0" : node.listen);
  }
  const previousPort = node.port;
  node.port = await panelInteger("本地监听端口", node.port);
  if (node.publicPort === previousPort) node.publicPort = node.port;
  if (node.direct) {
    node.address = await uiValidatedInput("客户端连接的公网 / 局域网 IP 或域名（可留空，之后补填）", node.address, normalizeConnectAddress, { clearable: true });
    node.publicPort = await panelInteger("客户端连接端口（NAT 映射时可与监听端口不同）", node.publicPort);
  }
  if (["vless", "vmess", "tuic"].includes(protocol)) {
    node.uuid = await uiValidatedInput("节点 UUID（回车保留；输入 new 重新生成）", node.uuid, value => {
      if (value === "new") return panelCrypto.randomUUID();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error("UUID 格式无效。"); return value.toLowerCase();
    });
  }
  if (["socks", "naive"].includes(protocol)) node.username = await promptInput("认证用户名", node.username);
  if (protocol === "shadowsocks") {
    const method = await panelEnum("Shadowsocks 加密方法", "SS2022 需要对应长度的 Base64 密钥；更换算法后会生成匹配的新密码。", SHADOWSOCKS_METHODS, node.method as typeof SHADOWSOCKS_METHODS[number]);
    if (method !== node.method) node.password = generateShadowsocksPassword(method);
    node.method = method;
  }
  if (["shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"].includes(protocol)) node.password = await panelPassword(node);
  if (protocol === "vmess") node.vmessSecurity = await panelEnum("VMess 客户端加密方式", "AEAD 节点，alterId 固定为 0。", ["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"] as const, node.vmessSecurity);
  await panelSecurity(paths, node);
  if (protocol === "vless") {
    const encryption = await selectMenu("VLESS Encryption", "按客户端支持情况选择；ENC 会生成并保存配对的服务端解密参数和客户端加密参数。", ["不使用额外 VLESS ENC", "保留当前 ENC（如已设置）", "生成新的 ML-KEM-768 ENC 参数", "手动输入成对 ENC 参数"], node.vlessEncryption === "none" ? 0 : 1);
    if (encryption === 0) { node.vlessEncryption = "none"; node.vlessDecryption = "none"; }
    if (encryption === 2) {
      console.log("正在使用官方 Xray 生成 ENC 参数……");
      const pair = await generateVlessEncryption(paths);
      node.vlessEncryption = pair.vlessEncryption; node.vlessDecryption = pair.vlessDecryption;
    }
    if (encryption === 3) {
      node.vlessDecryption = await promptInput("服务端 decryption", node.vlessDecryption, { secret: true });
      node.vlessEncryption = await promptInput("客户端 encryption", node.vlessEncryption, { secret: true });
    }
    let supportsVision = true;
    try { validateNode({ ...node, flow: "xtls-rprx-vision" }, { allowIncomplete: true }); } catch { supportsVision = false; }
    node.flow = supportsVision ? await panelEnum("VLESS Flow", "客户端需支持所选组合。", ["", "xtls-rprx-vision"] as const, node.flow, ["普通 VLESS", "XTLS Vision"]) : "";
  }
  if (protocol === "hysteria2") {
    node.hy2.obfsPassword = await promptInput("Salamander 混淆密码（可留空）", node.hy2.obfsPassword, { secret: true, clearable: true });
    node.hy2.upMbps = await panelInteger("服务端上行 Mbps（客户端下载）", node.hy2.upMbps, 0, 100000);
    node.hy2.downMbps = await panelInteger("服务端下行 Mbps（客户端上传）", node.hy2.downMbps, 0, 100000);
  }
  if (protocol === "tuic") {
    node.tuic.congestionControl = await panelEnum("TUIC 拥塞控制", "服务端与导出客户端使用所选算法。", ["bbr", "cubic", "new_reno"] as const, node.tuic.congestionControl);
    node.tuic.zeroRttHandshake = (await selectMenu("TUIC 0-RTT", "默认关闭。", ["关闭", "开启"], node.tuic.zeroRttHandshake ? 1 : 0)) === 1;
  }
  node.egress = await panelEnum("此节点的出口", "仅影响这个节点代理出去的流量，其他节点可使用不同出口。", ["direct", "warp"] as const, node.egress, ["本机 Direct", "WARP WireGuard"]);
  if (node.egress === "warp" && !config.warp) config = await panelWarp(config);
  node.enabled = (await selectMenu("保存后的节点状态", "保存不会自动中断当前后台；选择“启动 / 重启全部节点”后应用。", ["启用此节点", "保存为停用节点"], node.enabled ? 0 : 1)) === 0;
  node = validateNode(node);
  const nodes = config.nodes.some(item => item.id === node.id) ? config.nodes.map(item => item.id === node.id ? node : item) : [...config.nodes, node];
  const candidate = validateConfig({ ...config, nodes }, { allowExpiredCertificate: true });
  const decision = await selectMenu("保存节点", `${node.name}\n${panelEndpoint(node)}\n客户端地址：${node.address || "未填写（暂不导出直连链接）"}:${node.publicPort}\nTLS：${node.tls.mode}${node.tls.serverName ? ` / ${node.tls.serverName}` : ""}\n${node.tunnel.mode === "fixed" ? `Cloudflare 需将 ${node.tunnel.domain} 映射到 ${panelTunnelOrigin(node)}` : ""}`, ["保存", "取消"]);
  if (decision !== 0) throw new UserCancelledError();
  writeConfig(paths, candidate);
  console.log("节点已保存。选择“启动 / 重启全部节点”应用配置。");
}

async function panelPickNode(config: AppConfig, title: string): Promise<NodeConfig | null> {
  if (!config.nodes.length) { console.log("还没有节点，请先添加节点。"); return null; }
  let page = 0;
  for (;;) {
    const start = page * 6, visible = config.nodes.slice(start, start + 6);
    const labels = visible.map(node => `${node.name} · ${node.enabled ? "启用" : "停用"} · ${node.protocol} :${node.port}`);
    const previous = page > 0 ? labels.push("上一页") - 1 : -1;
    const next = start + visible.length < config.nodes.length ? labels.push("下一页") - 1 : -1;
    const back = labels.push("返回") - 1;
    const selected = await selectMenu(title, `共 ${config.nodes.length} 个节点，第 ${page + 1} 页`, labels);
    if (selected === back) return null;
    if (selected === previous) { page--; continue; }
    if (selected === next) { page++; continue; }
    return visible[selected]!;
  }
}

async function panelManageNodes(paths: AppPaths): Promise<void> {
  for (;;) {
    const config = readConfig(paths);
    const choice = await selectMenu("节点管理", `已创建 ${config.nodes.length} / 32 个节点。默认使用简易模式，选协议后即可保存。`, ["新增节点（简易模式）", "编辑节点（简易模式）", "高级配置（逐项自定义）", "启用 / 停用节点", "复制节点", "删除节点", "返回"]);
    if (choice === 6) return;
    const simpleActions = { apply: (candidate: AppConfig) => panelApplyConfiguration(paths, candidate), advanced: (draft: NodeConfig) => configureNode(paths, draft) };
    try {
      if (choice === 0) {
        if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
        await configureSimpleNode(paths, undefined, simpleActions);
      } else {
        const node = await panelPickNode(config, "选择节点");
        if (!node) continue;
        if (choice === 1) await configureSimpleNode(paths, node, simpleActions);
        else if (choice === 2) await configureNode(paths, node);
        else if (choice === 3) {
          node.enabled = !node.enabled;
          writeConfig(paths, validateConfig(config, { allowExpiredCertificate: true }));
          console.log(`已${node.enabled ? "启用" : "停用"}；重启全部节点后应用。`);
        } else if (choice === 4) {
          if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
          const fresh = createDefaultNode(node.protocol, config.nodes);
          const copy = { ...structuredClone(node), id: fresh.id, name: `${node.name}-副本`, port: fresh.port, publicPort: fresh.port };
          await configureSimpleNode(paths, copy, simpleActions);
        } else if (choice === 5) {
          if (await selectMenu("删除节点", `将删除配置中的 ${node.name}；重启全部节点后停止其监听。`, ["取消", "删除此节点"]) === 1) {
            writeConfig(paths, { ...config, nodes: config.nodes.filter(item => item.id !== node.id) });
            console.log("节点配置已删除。重启全部节点后应用；删除最后一个节点后请选择停止全部节点。");
          }
        }
      }
    } catch (e) {
      if (e instanceof UiExitRequestedError) throw e;
      if (e instanceof UserCancelledError) continue;
      console.log(errorMessage(e));
    }
    await uiPause();
  }
}

/** Address and NAT-port metadata can change without changing a running tunnel. Old workers retain the full-hash check. */
export function panelRuntimeMatches(status: DaemonStatus | null, config: AppConfig, paths?: AppPaths): boolean {
  if (!status || !(status.runtimeConfigHash ? status.runtimeConfigHash === runtimeConfigFingerprint(config) : status.configHash === configFingerprint(config))) return false;
  if (!paths) return true;
  // Older workers do not report their selected release set. Once a selection
  // exists, they must restart before the panel can claim it has been applied.
  if (!status.coreReleaseHash) return !panelFs.existsSync(coreSelectionPath(paths));
  try { return status.coreReleaseHash === coreReleaseFingerprint(readCoreSelection(paths).active); }
  catch { return false; }
}

export async function panelExport(paths: AppPaths, services: Partial<SimplePanelServices> = {}): Promise<void> {
  const selected = await panelPickNode(readConfig(paths), "选择要查看 / 导出的节点");
  if (!selected) return;
  let node = selected;
  const routes: NodeRoute[] = [...(node.direct ? ["direct" as const] : []), ...(node.tunnel.mode !== "none" ? ["tunnel" as const] : [])];
  let route = routes.length === 1 ? routes[0]! : await panelEnum("查看哪种接入链接", "直连使用服务器地址；隧道使用 Cloudflare 域名，不需要先填写 VPS IP。", routes, "direct", routes.map(item => item === "direct" ? "直连" : "隧道"));
  let notice = "";
  for (;;) {
    if (route === "direct" && !node.address) node = await repairNodeAddress(paths, node.id, services);
    const config = readConfig(paths);
    node = config.nodes.find(item => item.id === selected.id)!;
    if (!node) throw new Error("节点已删除，请重新选择。");
    const status = await getDaemonStatus(paths), running = status?.nodes?.find(item => item.id === node.id);
    const unchanged = panelRuntimeMatches(status, config, paths);
    // Never reuse a hostname with a different running UUID/path/TLS configuration.
    const assigned = unchanged ? running?.domain ?? undefined : undefined;
    const link = generateNodeLinks(node, assigned).find(item => item.via === route);
    let client: ReturnType<typeof generateClientConfig> | undefined;
    let failure = link?.error || "";
    try { client = generateClientConfig(node, route, assigned); } catch (error) { failure ||= errorMessage(error); }
    const items = ["back", ...(client ? ["saveJson", "showJson"] : []), ...(link?.uri ? ["saveLink"] : []), ...(route === "direct" ? ["address"] : []), ...(routes.length > 1 ? ["route"] : [])];
    const labels: Record<string, string> = { back: "返回（链接已显示在上方，可直接复制）", saveJson: "保存完整客户端 JSON", showJson: "显示完整客户端 JSON", saveLink: "保存节点链接到文本文件", address: "修改连接地址 / 端口", route: route === "direct" ? "查看隧道链接" : "查看直连链接" };
    const information = [
      `${node.name} · ${route === "direct" ? "直连" : "隧道"}`,
      !node.enabled ? "此节点已停用。以下为保存配置，启用并应用后才会监听。"
        : unchanged ? `运行状态：${running?.phase ?? "未运行"}；${running?.detail ?? ""}` : "以下为保存配置；当前后台尚未运行这份服务端配置。",
      route === "direct" ? directListenerNotice(node) : "",
      failure || link?.uri || "此组合使用完整客户端 JSON。请选择保存或显示。",
      ...(client ? [`客户端 JSON：${client.format} 格式，本地代理端口 1080。`] : []), notice,
    ].filter(Boolean).join("\n\n");
    const action = items[await selectMenu("节点链接与客户端配置", information, items.map(item => labels[item]!))]!;
    if (action === "back") return;
    if (action === "route") { route = route === "direct" ? "tunnel" : "direct"; notice = ""; continue; }
    if (action === "showJson" && client) { console.log(JSON.stringify(client.config, null, 2)); await uiPause(); }
    else if ((action === "saveJson" && client) || (action === "saveLink" && link?.uri)) {
      const extension = action === "saveLink" ? "txt" : "json";
      const filename = await promptInput("保存路径", panelPath.join(paths.data, "exports", `${node.id}-${route}.${extension}`));
      const destination = panelPath.resolve(filename.replace(/^"(.*)"$/, "$1"));
      atomicWrite(destination, action === "saveLink" ? link!.uri! + "\n" : JSON.stringify(client!.config, null, 2) + "\n");
      notice = `已保存：${destination}`;
    } else if (action === "address") {
      const changed = await editConnectionAddress(node, services);
      const latest = readConfig(paths), current = latest.nodes.find(item => item.id === node.id);
      if (JSON.stringify(current) !== JSON.stringify(node)) throw new Error("节点已在另一处修改，请重新打开导出界面。");
      writeConfig(paths, { ...latest, nodes: latest.nodes.map(item => item.id === node.id ? changed : item) });
      node = changed;
      notice = "连接设置已保存。只改 IP / 对外端口立即更新链接；修改本机端口或监听范围需在主菜单应用。";
    }
  }
}

async function panelSharedSettings(paths: AppPaths): Promise<void> {
  let config = readConfig(paths);
  const selected = await selectMenu("共享设置", "节点协议和出口在节点编辑器中设置；这里管理共享 WARP 凭据和可选通知。", ["导入 / 申请 WARP 配置", "通知设置", "返回"]);
  if (selected === 2) return;
  if (selected === 0) config = await panelWarp(config);
  if (selected === 1) {
    const kinds: AppConfig["webhook"]["kind"][] = ["none", "generic", "feishu", "wecom", "dingtalk", "bark"];
    const kind = await panelEnum("通知类型", "启用后，节点就绪通知会将完整链接发送到指定 HTTPS 接口。签名机器人需使用自己的适配器。", kinds, config.webhook.kind, ["关闭通知", "通用 JSON", "飞书", "企业微信", "钉钉", "Bark"]);
    const url = kind === "none" ? "" : await uiValidatedInput("HTTPS 通知接口", config.webhook.url, value => { validateConfig({ ...config, webhook: { kind, url: value } }, { allowExpiredCertificate: true }); return value; }, { secret: true });
    config.webhook = { kind, url };
  }
  writeConfig(paths, config);
  console.log("共享设置已保存，重启全部节点后应用。");
}

export async function prepareRuntime(paths: AppPaths, config = readConfig(paths)): Promise<AppConfig> {
  const validated = validateConfig(config);
  if (!validated.nodes.some(node => node.enabled)) throw new Error("没有启用的节点。请先进入节点管理添加或启用节点。");
  console.log("按已启用节点准备所需核心并校验配置……");
  await preflightCores(paths, validated);
  console.log("所需核心与配置预检通过。");
  return validated;
}

async function panelReadiness(paths: AppPaths): Promise<void> {
  console.log("等待已启用节点监听，以及所选隧道连接，最多 45 秒……");
  let last = "";
  const status = await waitForReady(paths, 45000, current => {
    const next = current ? Array.isArray(current.nodes) ? `${current.phase} · ${current.nodes.filter(node => node.phase === "ready").length}/${current.nodes.filter(node => node.enabled).length} 个节点就绪` : "旧版后台仍在运行，请从主菜单重启全部节点应用新版本" : "等待后台响应";
    if (next !== last) { console.log(next); last = next; }
  });
  if (!status) { console.log("未确认后台响应，请查看日志。"); console.log(tailLog(paths, 15)); return; }
  if (!Array.isArray(status.nodes)) { console.log("当前仍为旧版后台。请在新版面板选择“启动 / 重启全部节点”应用升级。"); return; }
  for (const node of status.nodes) {
    console.log(`\n${node.name}：${node.phase} · ${node.detail}`);
    for (const link of node.links) console.log(`${link.label}：${link.error || link.uri || "请从导出菜单取得客户端 JSON"}`);
    if (node.lastError) console.log(node.lastError);
  }
  console.log("\n就绪检查确认本机监听及所选隧道连接。直连的公网端口 / NAT / 防火墙和客户端实际访问仍需现场验证。");
  console.log("关闭面板后后台继续运行；部分节点未就绪时，其他已就绪节点可以继续使用。");
}

async function panelStop(paths: AppPaths, startup: StartupStatus): Promise<void> {
  if (startup.mode !== "none") await stopManaged(paths); else await stopDaemonGracefully(paths);
}

async function panelApplyConfiguration(paths: AppPaths, candidate: AppConfig): Promise<void> {
  const current = await getDaemonStatus(paths);
  if (panelRuntimeMatches(current, candidate, paths)) {
    writeConfig(paths, candidate);
    console.log("配置已保存。服务端参数保持一致，后台继续运行；链接地址会自动刷新。");
    return;
  }
  if (candidate.nodes.some(node => node.enabled)) await prepareRuntime(paths, candidate);
  writeConfig(paths, candidate);
  try {
    const startup = await getStartupStatus(paths);
    await panelStop(paths, startup);
    if (!candidate.nodes.some(node => node.enabled)) { console.log("已保存停用状态，并停止后台节点。"); return; }
    if (startup.mode !== "none") await startManaged(paths); else await startDetachedDaemon(paths);
    await panelReadiness(paths);
  } catch (error) {
    console.log(`配置已保存，但后台应用未完成：${errorMessage(error)}\n处理后可从主菜单选择“启动 / 重启全部节点”重试。`);
  }
}

async function panelStartup(paths: AppPaths, current: StartupStatus): Promise<boolean> {
  if (current.enabled) { await disableStartup(paths); console.log("自动启动已关闭，当前后台继续运行。需要停止时请选择停止全部节点。"); return false; }
  await prepareRuntime(paths);
  if (isSystemInstallation(paths)) {
    await enableStartup(paths, "system"); await startManaged(paths); await panelReadiness(paths); return false;
  }
  const mode = process.platform === "win32" ? await selectMenu("自动启动模式", "系统模式会安装到受保护目录，需要时请求 UAC。用户模式只在该用户登录后运行。", ["系统开机启动（SYSTEM，无需登录）", "当前用户登录后启动", "取消"]) : await selectMenu("启用系统自启", "需要 systemd，程序将安装到 /opt/nexus-edge；必要时请求 sudo。", ["启用系统自启", "取消"]);
  if ((process.platform === "win32" && mode === 2) || (process.platform !== "win32" && mode === 1)) return false;
  if (mode === 1 && process.platform === "win32") {
    await panelStop(paths, current); await enableStartup(paths, "user"); await startManaged(paths); await panelReadiness(paths); return false;
  }
  const requestId = panelCrypto.randomUUID();
  try { await runElevated(paths, ["--install-system", requestId]); }
  catch (e) {
    let result: { requestId?: string; message?: string } | undefined;
    try { result = JSON.parse(panelFs.readFileSync(panelPath.join(paths.data, "installation-result.json"), "utf8")); } catch {}
    if (result?.requestId === requestId && result.message) throw new Error(result.message);
    throw e;
  }
  if (!discoverSystemInstallation()) throw new Error("安装命令已退出，但未确认激活的系统副本。");
  return true;
}

export async function runPanel(paths: AppPaths): Promise<"exit" | "handoff"> {
  if (!process.stdin.isTTY) throw new Error("管理面板需要交互式 PowerShell / cmd / Windows Terminal / Linux 终端。");
  for (;;) {
    const config = readConfig(paths);
    const [status, admin, startup] = await Promise.all([getDaemonStatus(paths), isAdministrator(), getStartupStatus(paths)]);
    const dirty = Boolean(status && !panelRuntimeMatches(status, config, paths));
    const enabled = config.nodes.filter(node => node.enabled);
    const information = [
      `后台：${status?.phase ?? "未运行"}    权限：${admin ? "管理员 / root" : "普通用户"}`,
      `节点：${config.nodes.length} 个（${enabled.length} 个启用）    隧道：${enabled.filter(node => node.tunnel.mode !== "none").length} 个`,
      `自启：${startup.detail}`, `数据：${paths.data}`,
      ...(dirty ? ["已保存的配置或内核版本尚未应用。重启全部节点后生效。"] : []),
      ...(!config.nodes.length ? ["节点管理 → 新增节点：选协议 → 保存并应用。隧道默认关闭。"] : []),
    ].join("\n");
    const choice = await selectMenu(`NexusEdge ${APP_VERSION} 节点管理`, information, ["启动 / 重启全部节点", "停止全部节点", "节点管理（新增 / 编辑 / 启停 / 删除）", "查看链接 / 导出客户端配置", "WARP 与通知设置", "查看运行日志", startup.enabled ? "关闭自动启动" : "开启自动启动", "内核管理 / 更新", "退出面板（保留后台）"]);
    if (choice === 8) return "exit";
    try {
      if (choice === 0) { await prepareRuntime(paths); await panelStop(paths, startup); if (startup.mode !== "none") await startManaged(paths); else await startDetachedDaemon(paths); await panelReadiness(paths); }
      else if (choice === 1) { await panelStop(paths, startup); console.log("后台及各节点核心已停止，自动启动设置保持不变。"); }
      else if (choice === 2) { await panelManageNodes(paths); continue; }
      else if (choice === 3) { await panelExport(paths); continue; }
      else if (choice === 4) await panelSharedSettings(paths);
      else if (choice === 5) console.log(tailLog(paths));
      else if (choice === 6 && await panelStartup(paths, startup)) return "handoff";
      else if (choice === 7) { await runCorePanel(paths); continue; }
    } catch (e) {
      if (e instanceof UiExitRequestedError) throw e;
      if (e instanceof UserCancelledError) continue;
      console.log(`\n${errorMessage(e)}`);
    }
    await uiPause();
  }
}


// ==================== main.ts ====================
import * as mainUrl from "node:url";
import * as mainPath from "node:path";

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
