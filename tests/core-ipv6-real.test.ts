import { expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import * as dgram from "node:dgram";
import * as cp from "node:child_process";
import * as crypto from "node:crypto";
import { createDefaultNode, createPaths, defaultConfig, generateClientConfig, generateRealityKeyPair, runCommand, type CoreName } from "../src/core.ts";
import { buildSingBoxConfig, buildXrayConfig, buildRuntimeXrayConfig, coreBinaryPath, preflightCores, readCoreSelection, NETWORK_RELEASES } from "../src/network.ts";

// 仅在显式指定、且 SHA-256 与固定官方版本匹配时运行；全部通信限于本机回环。
const binaries = { singBox: process.env.NEXUS_EDGE_SINGBOX_TEST_BINARY, xray: process.env.NEXUS_EDGE_XRAY_TEST_BINARY };
interface OwnedCore { child: cp.ChildProcess; closed: Promise<void>; stopped: boolean; log: string }

/** 校验 engine 指定的可执行文件；返回通过校验的绝对路径，未提供或哈希不符时抛出。 */
function verifiedBinary(engine: CoreName): string {
  const binary = binaries[engine];
  if (!binary) throw new Error(`未指定 ${engine} 官方测试核心。`);
  const asset = NETWORK_RELEASES[engine].assets[`${process.platform}-${process.arch}`];
  if (!asset) throw new Error("当前平台没有固定测试核心。");
  expect(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex")).toBe(asset.files[asset.executable]!);
  return binary;
}

/** 在 IPv4 回环上申请短暂空闲 TCP 端口；关闭探测监听后返回端口，最终绑定仍由核心验证。 */
async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

/** 使用 engine 官方解析器预检 file 配置；成功无返回值，失败附带核心诊断。 */
async function checkConfig(engine: CoreName, file: string): Promise<void> {
  const binary = verifiedBinary(engine);
  const result = await runCommand(binary, engine === "xray" ? ["run", "-test", "-config", file] : ["check", "-c", file], { cwd: path.dirname(binary), timeoutMs: 10_000 });
  if (result.code !== 0) throw new Error(`${engine} 配置预检失败：${result.stderr || result.stdout}`);
}

/** 启动本测试持有的核心进程，参数为核心名及配置路径；返回用于日志与清理的句柄。 */
function startCore(engine: CoreName, file: string): OwnedCore {
  const binary = verifiedBinary(engine);
  const child = cp.spawn(binary, ["run", engine === "xray" ? "-config" : "-c", file], { cwd: path.dirname(binary), shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  const owned: OwnedCore = { child, closed: Promise.resolve(), stopped: false, log: "" };
  owned.closed = new Promise(resolve => child.once("close", () => { owned.stopped = true; resolve(); }));
  child.once("error", error => { owned.log += error.message; });
  const drain = (chunk: Buffer): void => { owned.log = (owned.log + chunk.toString("utf8")).slice(-8000); };
  child.stdout!.on("data", drain); child.stderr!.on("data", drain);
  return owned;
}

/** 轮询 owned 核心的 IPv4 TCP port，最多等待五秒；核心提前退出即报告日志。 */
async function waitListening(owned: OwnedCore, port: number): Promise<void> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (owned.stopped) throw new Error(`测试核心提前退出：${owned.log}`);
    const connected = await new Promise<boolean>(resolve => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value: boolean): void => { socket.destroy(); resolve(value); };
      socket.once("connect", () => finish(true)); socket.once("error", () => finish(false)); socket.setTimeout(200, () => finish(false));
    });
    if (connected) return;
    await Bun.sleep(25);
  }
  throw new Error(`测试核心未监听 ${port}：${owned.log}`);
}

/** 结束本测试持有的进程并等待回收；超时强制终止，永不按名称结束其他用户进程。 */
async function stopCore(owned: OwnedCore): Promise<void> {
  if (owned.stopped) return;
  owned.child.kill("SIGTERM");
  const timer = setTimeout(() => { if (!owned.stopped) owned.child.kill("SIGKILL"); }, 2000);
  try { await owned.closed; } finally { clearTimeout(timer); }
}

/**
 * 经导出的 SOCKS5 客户端连接 target 指定的回环目标，并验证 payload 完整回显。
 * proxyPort / targetPort 为本机端口；返回是否完成回显。拒绝、关闭或超时均返回 false。
 * 使用实际 SOCKS 地址类型验证服务器出站策略，避免客户端先把 IPv6 解析成 IPv4。
 */
async function echoThroughSocks(proxyPort: number, targetPort: number, target: "127.0.0.1" | "::1" | "dual-stack.test", payload: Buffer): Promise<boolean> {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: "127.0.0.1", port: proxyPort });
    let phase: "greeting" | "connect" | "echo" = "greeting", pending = Buffer.alloc(0), settled = false;
    const finish = (value: boolean): void => { if (!settled) { settled = true; socket.destroy(); resolve(value); } };
    socket.once("error", () => finish(false)); socket.once("close", () => finish(false)); socket.setTimeout(1800, () => finish(false));
    socket.once("connect", () => socket.write(Buffer.from([5, 1, 0])));
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (phase === "greeting") {
        if (pending.length < 2) return;
        if (pending[0] !== 5 || pending[1] !== 0) { finish(false); return; }
        pending = pending.subarray(2); phase = "connect";
        const address = target === "127.0.0.1" ? Buffer.from([1, 127, 0, 0, 1]) : target === "::1" ? Buffer.from([4, ...Array(15).fill(0), 1]) : Buffer.concat([Buffer.from([3, target.length]), Buffer.from(target)]);
        socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, Buffer.from([targetPort >> 8, targetPort & 255])]));
      }
      if (phase === "connect") {
        if (pending.length < 5) return;
        if (pending[0] !== 5 || pending[1] !== 0) { finish(false); return; }
        const length = pending[3] === 1 ? 10 : pending[3] === 4 ? 22 : pending[3] === 3 ? 7 + pending[4]! : 0;
        if (!length) { finish(false); return; }
        if (pending.length < length) return;
        pending = pending.subarray(length); phase = "echo"; socket.write(payload);
      }
      if (phase === "echo" && pending.length >= payload.length) finish(pending.subarray(0, payload.length).equals(payload));
    });
  });
}

/**
 * 以生产生成器和生产导出的客户端运行 engine，分别验证默认、关闭、开启三个设置。
 * 独立 IPv4/IPv6 回环回显服务记录实际收到的连接；finally 回收核心、套接字及临时配置。
 */
async function verifyEgress(engine: CoreName): Promise<void> {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-ipv6-real-"));
  const sockets = new Set<net.Socket>(), owned: OwnedCore[] = [];
  let v6Connections = 0;
  const dns = dgram.createSocket("udp4"), queryTypes: number[] = [];
  // 测试DNS只响应回环目标：A=127.0.0.1，AAAA=::1。记录请求类型以验证IPv4解析策略。
  dns.on("message", (query, remote) => {
    let end = 12;
    while (end < query.length && query[end] !== 0) end += query[end]! + 1;
    if (end + 5 > query.length) return;
    const type = query.readUInt16BE(end + 1); queryTypes.push(type);
    const data = type === 1 ? Buffer.from([127, 0, 0, 1]) : type === 28 ? Buffer.from([...Array(15).fill(0), 1]) : Buffer.alloc(0);
    const header = Buffer.from(query.subarray(0, 12)); header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(data.length ? 1 : 0, 6);
    header.writeUInt16BE(0, 8); header.writeUInt16BE(0, 10);
    const answer = Buffer.from([0xc0, 0x0c, 0, type, 0, 1, 0, 0, 0, 0, 0, data.length]);
    dns.send(Buffer.concat([header, query.subarray(12, end + 5), ...(data.length ? [answer, data] : [])]), remote.port, remote.address);
  });
  const echo4 = net.createServer(socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.pipe(socket); });
  const echo6 = net.createServer(socket => { v6Connections++; sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.pipe(socket); });
  try {
    await new Promise<void>((resolve, reject) => { dns.once("error", reject); dns.bind(0, "127.0.0.1", resolve); });
    const dnsPort = dns.address().port;
    await new Promise<void>((resolve, reject) => { echo4.once("error", reject); echo4.listen(0, "127.0.0.1", resolve); });
    await new Promise<void>((resolve, reject) => { echo6.once("error", reject); echo6.listen({ port: 0, host: "::1", ipv6Only: true }, resolve); });
    const v4Port = (echo4.address() as net.AddressInfo).port, v6Port = (echo6.address() as net.AddressInfo).port;
    for (const enabled of [undefined, false, true]) {
      const node = createDefaultNode(engine === "xray" ? "vless" : "socks");
      node.port = await freePort(); node.publicPort = node.port; node.listen = "127.0.0.1"; node.address = "127.0.0.1";
      const config = { ...defaultConfig(), ...(enabled === undefined ? {} : { coreIpv6: enabled }), nodes: [node] };
      const generated = (engine === "xray" ? buildXrayConfig(config) : buildSingBoxConfig(config)) as any;
      // 仅将解析器指向本测试的UDP服务，策略字段仍来自生产生成器，不改路由或出站。
      if (engine === "singBox") generated.dns.servers = [{ type: "udp", tag: "dns-local", server: "127.0.0.1", server_port: dnsPort }];
      else if (generated.dns) generated.dns.servers = [{ address: "127.0.0.1", port: dnsPort }];
      const client = generateClientConfig(node).config as any;
      // 调试环境变量仅增加测试副本日志，生产生成器和网络策略保持原值。
      if (process.env.NEXUS_EDGE_TEST_CORE_DEBUG === "1") {
        if (engine === "xray") { generated.log.loglevel = "debug"; client.log.loglevel = "debug"; }
        else { generated.log.level = "debug"; client.log.level = "debug"; }
      }
      let clientPort = await freePort(); while (clientPort === node.port) clientPort = await freePort();
      if (engine === "xray") client.inbounds[0].port = clientPort; else client.inbounds[0].listen_port = clientPort;
      const serverFile = path.join(directory, "server.json"), clientFile = path.join(directory, "client.json");
      fs.writeFileSync(serverFile, JSON.stringify(generated)); fs.writeFileSync(clientFile, JSON.stringify(client));
      await checkConfig(engine, serverFile); await checkConfig(engine, clientFile);
      const server = startCore(engine, serverFile); owned.push(server); await waitListening(server, node.port);
      const proxy = startCore(engine, clientFile); owned.push(proxy); await waitListening(proxy, clientPort);
      const payload = Buffer.from(`IPv6策略验证 ${crypto.randomUUID()}`);
      expect(await echoThroughSocks(clientPort, v4Port, "127.0.0.1", payload), `${engine}/${enabled}: IPv4 字面量`).toBe(true);
      if (!enabled) {
        queryTypes.length = 0;
        expect(await echoThroughSocks(clientPort, v4Port, "dual-stack.test", payload), `${engine}/${enabled}: 双栈域名仅使用IPv4`).toBe(true);
        expect(queryTypes).toContain(1); expect(queryTypes).not.toContain(28);
      }
      const before = v6Connections;
      expect(await echoThroughSocks(clientPort, v6Port, "::1", payload), `${engine}/${enabled}: IPv6 字面量`).toBe(enabled === true);
      expect(v6Connections - before).toBe(enabled === true ? 1 : 0);
      await stopCore(proxy); await stopCore(server);
    }
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${owned.map(core => core.log).join("\n")}`);
  } finally {
    await Promise.all(owned.map(stopCore));
    for (const socket of sockets) socket.destroy();
    await Promise.all([echo4, echo6].map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    await new Promise<void>(resolve => { try { dns.close(resolve); } catch { resolve(); } });
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

for (const engine of ["singBox", "xray"] as const) {
  (binaries[engine] ? test : test.skip)(`real ${engine} blocks IPv6 by default, preserves IPv4 and restores IPv6 only after opt-in`, async () => { await verifyEgress(engine); }, 30_000);
  (binaries[engine] ? test : test.skip)(`real ${engine} validates REALITY and WARP with both IPv6 settings`, async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-ipv6-check-"));
    try {
      for (const coreIpv6 of [false, true]) for (const useWarp of [false, true]) {
        const node = createDefaultNode(engine === "xray" ? "vless" : "anytls");
        node.tls.mode = "reality"; node.tls.serverName = "example.com";
        node.tls.reality = { ...generateRealityKeyPair(), shortId: "12ab", handshakeServer: "example.com", handshakePort: 443 };
        node.egress = useWarp ? "warp" : "direct";
        const config = { ...defaultConfig(), coreIpv6, nodes: [node], warp: {
          privateKey: Buffer.alloc(32, 7).toString("base64"), peerPublicKey: Buffer.alloc(32, 9).toString("base64"),
          addresses: ["172.16.0.2/32", "2606:4700:110:8123::2/128"], endpointHost: "engage.cloudflareclient.com", endpointPort: 2408, reserved: [1, 2, 3],
        } };
        const file = path.join(directory, "candidate.json");
        const generated = (engine === "xray" ? await buildRuntimeXrayConfig(config, { lookup: async (_host, options) => { expect(options.family).toBe(4); return { address: "192.0.2.9", family: 4 }; } }) : buildSingBoxConfig(config)) as any;
        if (engine === "xray") expect(generated.inbounds[0].streamSettings.realitySettings.target).toBe(coreIpv6 ? "example.com:443" : "192.0.2.9:443");
        expect(node.tls.reality.handshakeServer).toBe("example.com");
        fs.writeFileSync(file, JSON.stringify(generated));
        await checkConfig(engine, file);
      }
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }, 30_000);
}

(binaries.xray ? test : test.skip)("real Xray preflight publishes only the resolved IPv4 REALITY target without changing saved domain", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-reality-publish-"));
  const paths = createPaths(path.join(directory, "nexus-edge.ts")), binary = verifiedBinary("xray");
  const releases = readCoreSelection(paths).active, release = releases.xray;
  const cache = path.dirname(coreBinaryPath(paths, release));
  const originalFetch = globalThis.fetch;
  try {
    fs.mkdirSync(cache, { recursive: true });
    // 将官方固定版本的全部认证文件复制到独立缓存，生产安装器仍执行完整哈希校验。
    for (const [name, hash] of Object.entries(release.asset.files)) {
      const content = fs.readFileSync(path.join(path.dirname(binary), name));
      expect(crypto.createHash("sha256").update(content).digest("hex")).toBe(hash);
      fs.writeFileSync(path.join(cache, name), content);
    }
    const node = createDefaultNode("vless"); node.tls.mode = "reality"; node.tls.serverName = "sni.test";
    node.tls.reality = { ...generateRealityKeyPair(), shortId: "12ab", handshakeServer: "dual-stack.test", handshakePort: 443 };
    const config = { ...defaultConfig(), nodes: [node] };
    fs.writeFileSync(paths.config, JSON.stringify(config));
    const saved = fs.readFileSync(paths.config, "utf8"); let calls = 0;
    globalThis.fetch = (async () => { throw new Error("已校验缓存存在，不允许外部下载。"); }) as unknown as typeof fetch;
    await preflightCores(paths, config, { releases, realityDns: { lookup: async (hostname, options) => {
      calls++; expect(hostname).toBe("dual-stack.test"); expect(options.family).toBe(4);
      return { address: "192.0.2.10", family: 4 };
    } } });
    const generated = JSON.parse(fs.readFileSync(paths.xrayConfig, "utf8"));
    expect(calls).toBe(1); expect(generated.inbounds[0].streamSettings.realitySettings.target).toBe("192.0.2.10:443");
    expect(generated.inbounds[0].streamSettings.realitySettings.serverNames).toEqual(["sni.test"]);
    expect(fs.readFileSync(paths.config, "utf8")).toBe(saved);
    expect(fs.readdirSync(paths.data).some(name => name.endsWith(".candidate.json"))).toBe(false);
  } finally { globalThis.fetch = originalFetch; fs.rmSync(directory, { recursive: true, force: true }); }
}, 30_000);
