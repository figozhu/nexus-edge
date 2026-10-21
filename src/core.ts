import * as coreFs from "node:fs";
import * as corePath from "node:path";
import * as coreCrypto from "node:crypto";
import * as coreNet from "node:net";
import * as coreUrl from "node:url";
import * as coreCp from "node:child_process";
import * as coreDecoder from "node:string_decoder";

export const APP_VERSION = "2.3.0";

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

export interface FirewallSettings {
  mode: "auto" | "manual";
  linuxBackend: "auto" | "ufw" | "firewalld" | "iptables";
  /** Empty selects the active interface's zone without changing its assignment. */
  firewalldZone: string;
}

export interface AppConfig {
  schema: 2;
  nodes: NodeConfig[];
  warp?: WarpProfile;
  webhook: { kind: "none" | "generic" | "feishu" | "wecom" | "dingtalk" | "bark"; url: string };
  /** Older schema-2 configurations use automatic firewall management by default. */
  firewall?: FirewallSettings;
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
  /** Separate from local listener readiness; this does not prove public reachability. */
  firewall?: { status: string; backend: string; detail: string; warnings: string[] };
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

export function validateFirewallSettings(value: unknown): FirewallSettings {
  const settings = coreObject(value, "防火墙设置");
  const firewalldZone = coreString(settings.firewalldZone, "firewalld zone", 32);
  if (firewalldZone && !/^[a-zA-Z0-9_-]{1,32}$/.test(firewalldZone)) throw new Error("firewalld zone 只能包含字母、数字、下划线或连字符；留空可自动选择。");
  return {
    mode: coreChoice(settings.mode, ["auto", "manual"] as const, "防火墙管理模式"),
    linuxBackend: coreChoice(settings.linuxBackend, ["auto", "ufw", "firewalld", "iptables"] as const, "Linux 防火墙管理器"),
    firewalldZone,
  };
}

export function getFirewallSettings(config: AppConfig): FirewallSettings {
  return config.firewall === undefined ? { mode: "auto", linuxBackend: "auto", firewalldZone: "" } : validateFirewallSettings(config.firewall);
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
  return { schema: 2, nodes, ...(warp ? { warp } : {}), webhook: coreValidateWebhook(v.webhook), ...(v.firewall === undefined ? {} : { firewall: validateFirewallSettings(v.firewall) }) };
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

/** Client endpoint metadata and firewall preferences do not change a running core.
 * Keep every other field, including node names and shared settings, conservative. */
export function runtimeConfigFingerprint(config: AppConfig): string {
  const normalized = validateConfig(config, { allowExpiredCertificate: true });
  const { firewall: _firewall, ...coreSettings } = normalized;
  const runtimeConfig = {
    ...coreSettings,
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
