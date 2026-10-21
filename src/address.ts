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
