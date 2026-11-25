import * as trafficHttp2 from "node:http2";
import * as trafficNet from "node:net";
import { type CoreName, type NodeConfig } from "./core.ts";

export interface TrafficEndpoint { port: number; secret: string }
export interface TrafficCounter { id: string; up: number; down: number }
export interface TrafficConnection extends TrafficCounter { nodeId: string; ip: string; closed: boolean; closedAt?: number }
export interface TrafficSnapshot {
  up: number; down: number;
  nodes: TrafficCounter[];
  connections: TrafficConnection[];
  peers: { nodeId: string; ip: string; seenAt: number }[];
  peersAvailable: boolean;
}

/** Only attach instrumentation to the worker's generated configuration, never saved credentials. */
export function withTrafficInstrumentation(generated: object, engine: CoreName, endpoint: TrafficEndpoint): object {
  if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535 || !/^[a-f0-9]{64}$/.test(endpoint.secret)) throw new Error("无效的本地统计接口。");
  const config = structuredClone(generated) as Record<string, any>;
  if (engine === "xray") {
    config.stats = {};
    // Xray's direct API listener has no authentication. Route a password-only
    // loopback SOCKS inbound into StatsService instead, so a proxy client cannot
    // reach/reset statistics by requesting the server's loopback TCP address.
    config.api = { tag: "nexus-traffic-api", services: ["StatsService"] };
    config.policy = { levels: { "0": { statsUserUplink: true, statsUserDownlink: true, statsUserOnline: true } } };
    for (const inbound of config.inbounds) for (const client of inbound.settings.clients) client.email = `nexus:${inbound.tag.slice(5)}`;
    config.inbounds.push({ tag: "nexus-traffic", listen: "127.0.0.1", port: endpoint.port, protocol: "socks", settings: { auth: "password", accounts: [{ user: "nexus-traffic", pass: endpoint.secret }], udp: false } });
    config.routing ??= { domainStrategy: "AsIs", rules: [] };
    config.routing.rules.unshift({ type: "field", inboundTag: ["nexus-traffic"], outboundTag: "nexus-traffic-api" });
  } else {
    config.services = [{ type: "api", tag: "nexus-traffic", listen: "127.0.0.1", listen_port: endpoint.port, secret: endpoint.secret,
      access_control_allow_origin: ["http://nexus.invalid"], access_control_allow_private_network: false }];
  }
  return config;
}

const trafficMaxMessage = 8 * 1024 * 1024;
type TrafficProtoFields = Map<number, (Buffer | bigint)[]>;

/** Bounded protobuf wire reader; accepts only ordinary wire types, never evals schemas or payloads. */
export function trafficReadProto(bytes: Buffer): TrafficProtoFields {
  if (bytes.length > trafficMaxMessage) throw new Error("统计响应过大。");
  let offset = 0;
  const variable = (): bigint => {
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      if (offset >= bytes.length) throw new Error("统计响应截断。");
      const b = bytes[offset++]!;
      if (shift === 63n && b > 1) throw new Error("统计数值溢出。");
      value |= BigInt(b & 127) << shift;
      if (!(b & 128)) return value;
    }
    throw new Error("统计数值溢出。");
  };
  const fields: TrafficProtoFields = new Map(); let count = 0;
  while (offset < bytes.length) {
    if (++count > 65536) throw new Error("统计字段数量超限。");
    const tag = variable();
    const field = Number(tag >> 3n), wire = Number(tag & 7n);
    if (field < 1 || field > 536870911) throw new Error("无效的统计字段。");
    let value: Buffer | bigint;
    if (wire === 0) value = variable();
    else {
      const length = wire === 2 ? Number(variable()) : wire === 1 ? 8 : wire === 5 ? 4 : -1;
      if (!Number.isSafeInteger(length) || length < 0 || length > bytes.length - offset) throw new Error("无效的统计字段长度。");
      value = bytes.subarray(offset, offset + length); offset += length;
      if (wire !== 2) continue;
    }
    const values = fields.get(field) ?? []; values.push(value); fields.set(field, values);
  }
  return fields;
}

function trafficProtoBytes(fields: TrafficProtoFields, field: number): Buffer {
  const value = fields.get(field)?.[0];
  if (value === undefined) return Buffer.alloc(0);
  if (!Buffer.isBuffer(value)) throw new Error("统计字段类型不符。");
  return value;
}
function trafficProtoText(fields: TrafficProtoFields, field: number): string { return trafficProtoBytes(fields, field).toString("utf8"); }
function trafficProtoNumber(fields: TrafficProtoFields, field: number): number {
  const value = fields.get(field)?.[0] ?? 0n;
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("统计数值超出安全范围。");
  return Number(value);
}
function trafficProtoString(value: string): Buffer {
  const bytes = Buffer.from(value), length: number[] = [];
  let n = bytes.length;
  do { length.push((n & 127) | (n > 127 ? 128 : 0)); n >>>= 7; } while (n);
  return Buffer.concat([Buffer.from([10, ...length]), bytes]);
}

/** Authenticate before speaking HTTP/2; the secret never enters URLs or logs. */
async function trafficXrayConnection(endpoint: TrafficEndpoint): Promise<trafficNet.Socket> {
  if (!/^[a-f0-9]{64}$/.test(endpoint.secret)) throw new Error("无效的统计接口认证。");
  const socket = trafficNet.createConnection({ host: "127.0.0.1", port: endpoint.port });
  return new Promise((resolve, reject) => {
    let stage = 0, pending = Buffer.alloc(0), done = false;
    const timer = setTimeout(() => fail(), 1500);
    const cleanup = () => { clearTimeout(timer); socket.off("data", receive); socket.off("error", fail); socket.off("close", fail); };
    const fail = () => { if (done) return; done = true; cleanup(); socket.destroy(); reject(new Error("统计接口连接或认证失败。")); };
    const receive = (data: Buffer) => {
      pending = Buffer.concat([pending, data]);
      if (pending.length > 512) return fail();
      if (stage < 2 && pending.length < 2) return;
      if (stage === 0) {
        if (pending[0] !== 5 || pending[1] !== 2) return fail(); pending = pending.subarray(2); stage = 1;
        const user = Buffer.from("nexus-traffic"), password = Buffer.from(endpoint.secret);
        socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([password.length]), password]));
      } else if (stage === 1) {
        if (pending[0] !== 1 || pending[1] !== 0) return fail(); pending = pending.subarray(2); stage = 2;
        socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 0, 1]));
      } else {
        if (pending.length < 4) return;
        if (pending[0] !== 5 || pending[1] !== 0 || ![1, 4].includes(pending[3]!)) return fail();
        const length = pending[3] === 4 ? 22 : 10;
        if (pending.length < length) return;
        done = true; cleanup(); socket.pause();
        if (pending.length > length) socket.unshift(pending.subarray(length));
        resolve(socket);
      }
    };
    socket.on("error", fail); socket.on("close", fail); socket.on("data", receive);
    socket.once("connect", () => socket.write(Buffer.from([5, 1, 2])));
  });
}

/** Calls only loopback, bypassing environment proxies. Read-only RPCs never set reset=true. */
export async function trafficRpc(endpoint: TrafficEndpoint, method: string, payload: Buffer = Buffer.alloc(0), firstMessage = false): Promise<Buffer> {
  if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) throw new Error("无效的统计端口。");
  const xray = method.startsWith("/xray.app.stats.command.StatsService/");
  const socket = xray ? await trafficXrayConnection(endpoint) : undefined;
  return new Promise((resolve, reject) => {
    const client = trafficHttp2.connect(`http://127.0.0.1:${endpoint.port}`, socket ? { createConnection: () => socket } : {});
    let settled = false, response: Buffer | undefined, pending = Buffer.alloc(0), received = 0, grpcStatus = "";
    const timer = setTimeout(() => finish(new Error("统计接口超时。")), 1800);
    const finish = (error?: Error) => {
      if (settled) return; settled = true; clearTimeout(timer);
      stream.close(); client.destroy();
      if (error) reject(error); else resolve(response!);
    };
    client.on("error", () => finish(new Error("统计接口暂不可用。")));
    const stream = client.request({ ":method": "POST", ":path": method, "content-type": "application/grpc", te: "trailers", "grpc-timeout": "1500m",
      ...(!xray && endpoint.secret ? { authorization: `Bearer ${endpoint.secret}` } : {}) });
    stream.on("response", headers => {
      if (headers[":status"] !== 200 || !String(headers["content-type"] ?? "").startsWith("application/grpc")) finish(new Error("统计接口响应无效。"));
      if (headers["grpc-status"] !== undefined) grpcStatus = String(headers["grpc-status"]);
    });
    stream.on("trailers", headers => { grpcStatus = String(headers["grpc-status"] ?? ""); });
    stream.on("data", (chunk: Buffer) => {
      if (settled) return;
      received += chunk.length;
      if (received > trafficMaxMessage + 5) { finish(new Error("统计响应过大。")); return; }
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 5) return;
      const size = pending.readUInt32BE(1);
      if (pending[0] !== 0 || size > trafficMaxMessage) { finish(new Error("统计响应格式不支持。")); return; }
      if (pending.length < size + 5) return;
      if (response) { finish(new Error("统计响应包含多余数据。")); return; }
      response = pending.subarray(5, size + 5); pending = pending.subarray(size + 5);
      if (firstMessage) finish();
    });
    stream.on("error", () => finish(new Error("统计连接中断。")));
    stream.on("end", () => {
      if (grpcStatus !== "0" || !response || pending.length) finish(new Error(`统计接口不可用（gRPC ${/^[0-9]+$/.test(grpcStatus) ? grpcStatus : "unknown"}）。`));
      else finish();
    });
    const frame = Buffer.alloc(5); frame.writeUInt32BE(payload.length, 1); stream.end(Buffer.concat([frame, payload]));
  });
}

function trafficSourceIp(source: string): string {
  if (trafficNet.isIP(source)) return source;
  const ip = source.startsWith("[") ? source.slice(1, source.indexOf("]")) : source.replace(/:\d+$/, "");
  return trafficNet.isIP(ip) ? ip : "";
}

export function parseXrayTraffic(bytes: Buffer, nodeIds: string[]): TrafficSnapshot {
  const counters = new Map(nodeIds.map(id => [id, { id, up: 0, down: 0 }]));
  const seen = new Set<string>();
  for (const item of trafficReadProto(bytes).get(1) ?? []) {
    if (!Buffer.isBuffer(item)) throw new Error("无效的入站计数。");
    const stat = trafficReadProto(item), name = trafficProtoText(stat, 1);
    const match = /^user>>>nexus:(.+)>>>traffic>>>(uplink|downlink)$/.exec(name);
    if (!match || !counters.has(match[1]!)) continue;
    if (seen.has(name)) throw new Error("重复的入站计数。"); seen.add(name);
    counters.get(match[1]!)![match[2] === "uplink" ? "up" : "down"] = trafficProtoNumber(stat, 2);
  }
  const nodes = [...counters.values()];
  return { up: nodes.reduce((sum, n) => sum + n.up, 0), down: nodes.reduce((sum, n) => sum + n.down, 0), nodes, connections: [], peers: [], peersAvailable: true };
}

export function parseSingTraffic(statusBytes: Buffer, connectionBytes: Buffer, nodeIds: string[]): TrafficSnapshot {
  const status = trafficReadProto(statusBytes), messages = trafficReadProto(connectionBytes);
  if (!trafficProtoNumber(status, 5) || trafficProtoNumber(messages, 2) !== 1) throw new Error("该核心未提供完整统计快照。");
  const nodes = new Set(nodeIds), connections: TrafficConnection[] = [], ids = new Set<string>();
  for (const item of messages.get(1) ?? []) {
    if (!Buffer.isBuffer(item)) throw new Error("无效的连接统计。");
    const event = trafficReadProto(item), c = trafficReadProto(trafficProtoBytes(event, 3));
    const id = trafficProtoText(c, 1), tag = trafficProtoText(c, 2);
    if (!tag.startsWith("node:") || !nodes.has(tag.slice(5))) continue;
    if (!/^[a-f0-9-]{36}$/.test(id) || ids.has(id)) throw new Error("无效或重复的连接标识。"); ids.add(id);
    const closedAt = trafficProtoNumber(c, 13);
    connections.push({ id, nodeId: tag.slice(5), ip: trafficSourceIp(trafficProtoText(c, 6)), up: trafficProtoNumber(c, 16), down: trafficProtoNumber(c, 17), closed: closedAt > 0, closedAt });
  }
  return { up: trafficProtoNumber(status, 8), down: trafficProtoNumber(status, 9), nodes: [], connections, peers: [], peersAvailable: true };
}

/** Fixed-version native adapters. Only safe node IDs/IPs/counters leave this module, never destinations or credentials. */
export async function collectCoreTraffic(engine: CoreName, endpoint: TrafficEndpoint, nodes: Pick<NodeConfig, "id">[]): Promise<TrafficSnapshot> {
  if (engine === "singBox") {
    const connections = await trafficRpc(endpoint, "/daemon.StartedService/SubscribeConnections", undefined, true);
    const status = await trafficRpc(endpoint, "/daemon.StartedService/SubscribeStatus", undefined, true);
    return parseSingTraffic(status, connections, nodes.map(n => n.id));
  }
  const prefix = "/xray.app.stats.command.StatsService/";
  const result = parseXrayTraffic(await trafficRpc(endpoint, prefix + "QueryStats", trafficProtoString("user>>>nexus:")), nodes.map(n => n.id));
  // Bounded concurrency; a missing online-user map is normal until the first authenticated connection.
  const start = (Math.floor(Date.now() / 10_000) % Math.max(1, Math.ceil(nodes.length / 8))) * 8;
  await Promise.all(nodes.slice(start, start + 8).map(async node => {
    try {
      const bytes = await trafficRpc(endpoint, prefix + "GetStatsOnlineIpList", trafficProtoString(`user>>>nexus:${node.id}>>>online`));
      for (const entry of trafficReadProto(bytes).get(2) ?? []) {
        if (!Buffer.isBuffer(entry)) throw new Error("无效的来源信息。");
        // The upstream timestamp is the last connection's start, not its last
        // activity. Membership means an active connection at this observation.
        const fields = trafficReadProto(entry), ip = trafficSourceIp(trafficProtoText(fields, 1));
        if (ip) result.peers.push({ nodeId: node.id, ip, seenAt: Date.now() });
      }
    } catch (error) { if (!(error instanceof Error && error.message.includes("gRPC 5"))) result.peersAvailable = false; }
  }));
  return result;
}
