import { expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import * as dgram from "node:dgram";
import * as crypto from "node:crypto";
import * as cp from "node:child_process";
import * as http2 from "node:http2";
import { defaultConfig, createDefaultNode, generateClientConfig, generateNodeLinks, generateRealityKeyPair, nodeListenNetworks, runCommand } from "../src/core.ts";
import type { CoreName, NodeConfig, NodeProtocol } from "../src/core.ts";
import { buildSingBoxConfig, buildXrayConfig, compareCoreVersions, NETWORK_RELEASES } from "../src/network.ts";

// Opt-in tests: authenticated local official binaries, loopback services only.
// No download, Cloudflare/WARP traffic, daemon, or system service is used.
const binaries = { singBox: process.env.NEXUS_EDGE_SINGBOX_TEST_BINARY, xray: process.env.NEXUS_EDGE_XRAY_TEST_BINARY };
const checked = new Map<CoreName, Promise<void>>();
let certificate: Promise<{ certificatePem: string; keyPem: string }> | undefined;
let encryption: Promise<{ vlessEncryption: string; vlessDecryption: string }> | undefined;
async function verifyBinary(engine: CoreName): Promise<void> {
  if (!checked.has(engine)) checked.set(engine, (async () => {
    const asset = NETWORK_RELEASES[engine].assets[`${process.platform}-${process.arch}`];
    const executable = binaries[engine];
    if (!asset || !executable) throw new Error(`No pinned ${engine} fixture.`);
    const digest = crypto.createHash("sha256");
    for await (const chunk of fs.createReadStream(executable)) digest.update(chunk);
    expect(digest.digest("hex")).toBe(asset.files[asset.executable]!);
  })());
  return checked.get(engine)!;
}
async function getCertificate(): Promise<{ certificatePem: string; keyPem: string }> {
  if (!certificate) certificate = (async () => {
    await verifyBinary("singBox");
    const result = await runCommand(binaries.singBox!, ["generate", "tls-keypair", "example.com", "--months", "1"]);
    expect(result.code).toBe(0);
    return { certificatePem: result.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)![0] + "\n",
      keyPem: result.stdout.match(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----/)![0] + "\n" };
  })();
  return certificate;
}
async function getEncryption(): Promise<{ vlessEncryption: string; vlessDecryption: string }> {
  if (!encryption) encryption = (async () => {
    await verifyBinary("xray");
    const result = await runCommand(binaries.xray!, ["vlessenc"]);
    expect(result.code).toBe(0);
    const pq = result.stdout.split("Authentication: ML-KEM-768")[1]!;
    return { vlessEncryption: pq.match(/"encryption"\s*:\s*"([^"\r\n]+)"/)![1]!, vlessDecryption: pq.match(/"decryption"\s*:\s*"([^"\r\n]+)"/)![1]! };
  })();
  return encryption;
}
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const listener = net.createServer(); listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const address = listener.address();
      if (!address || typeof address === "string") { listener.close(); reject(new Error("No test port.")); return; }
      listener.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}
interface OwnedCore { child: cp.ChildProcess; closed: Promise<void>; didClose: boolean; failure?: Error; log: string }
function startCore(engine: CoreName, configPath: string): OwnedCore {
  const executable = binaries[engine]!;
  const child = cp.spawn(executable, ["run", engine === "xray" ? "-config" : "-c", configPath], {
    cwd: path.dirname(executable), shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  const core: OwnedCore = { child, closed: Promise.resolve(), didClose: false, log: "" };
  core.closed = new Promise(resolve => child.once("close", () => { core.didClose = true; resolve(); }));
  child.once("error", error => { core.failure = error; });
  const drain = (chunk: Buffer) => { core.log = (core.log + chunk.toString("utf8")).slice(-8000); };
  child.stdout!.on("data", drain); child.stderr!.on("data", drain);
  return core;
}
async function canConnect(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const finish = (ok: boolean) => { socket.destroy(); resolve(ok); };
    socket.once("connect", () => finish(true)); socket.once("error", () => finish(false)); socket.setTimeout(200, () => finish(false));
  });
}
async function canBindUdp(port: number): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", error => { socket.close(); if ((error as NodeJS.ErrnoException).code === "EADDRINUSE") resolve(false); else reject(error); });
    socket.bind({ address: "127.0.0.1", port, exclusive: true }, () => socket.close(() => resolve(true)));
  });
}
async function waitUdpListening(core: OwnedCore, port: number): Promise<void> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (core.failure || core.didClose) throw new Error(`Owned UDP core failed: ${core.failure?.message ?? core.log}`);
    if (!await canBindUdp(port)) return;
    await Bun.sleep(30);
  }
  throw new Error(`Owned core did not bind UDP 127.0.0.1:${port}`);
}
async function waitListening(core: OwnedCore, port: number): Promise<void> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (core.failure || core.didClose) throw new Error(`Owned core failed: ${core.failure?.message ?? core.log}`);
    if (await canConnect(port)) return;
    await Bun.sleep(30);
  }
  throw new Error(`Owned core did not listen on 127.0.0.1:${port}\n${core.log}`);
}
async function waitClosed(core: OwnedCore, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([core.closed.then(() => true), new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); })]); }
  finally { if (timer) clearTimeout(timer); }
}
async function stopCore(core: OwnedCore): Promise<void> {
  if (core.didClose) return; core.child.kill("SIGTERM");
  if (await waitClosed(core, 2000)) return; core.child.kill("SIGKILL");
  if (!await waitClosed(core, 5000)) throw new Error(`Owned process did not exit: ${core.child.pid}`);
}
/** Send HTTP over the unmodified exported SOCKS5/mixed client listener. */
async function requestOverSocks(proxyPort: number, targetPort: number, nonce: string, payload: Uint8Array): Promise<{ status: number; nonce: string; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port: proxyPort });
    let phase: "greeting" | "connect" | "response" = "greeting", pending = Buffer.alloc(0), settled = false;
    const fail = (error: Error) => { if (!settled) { settled = true; socket.destroy(); reject(error); } };
    socket.on("error", fail); socket.setTimeout(6000, () => fail(new Error(`SOCKS ${phase} timed out`)));
    socket.on("connect", () => socket.write(Buffer.from([5, 1, 0])));
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      try {
        if (phase === "greeting") {
          if (pending.length < 2) return;
          if (pending[0] !== 5 || pending[1] !== 0) throw new Error("Exported SOCKS5 listener rejected authentication negotiation.");
          pending = pending.subarray(2); phase = "connect";
          socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, targetPort >> 8, targetPort & 255]));
        }
        if (phase === "connect") {
          if (pending.length < 5) return;
          if (pending[0] !== 5 || pending[1] !== 0) throw new Error(`SOCKS5 target connection rejected: ${pending[1]}`);
          const size = pending[3] === 1 ? 10 : pending[3] === 4 ? 22 : pending[3] === 3 ? 7 + pending[4]! : 0;
          if (!size) throw new Error("Invalid SOCKS5 response address.");
          if (pending.length < size) return;
          pending = pending.subarray(size); phase = "response";
          const header = Buffer.from(`POST /echo HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nX-Test-Nonce: ${nonce}\r\nContent-Length: ${payload.length}\r\n\r\n`);
          socket.write(Buffer.concat([header, Buffer.from(payload)]));
        }
        if (phase === "response") {
          const split = pending.indexOf("\r\n\r\n"); if (split < 0) return;
          const header = pending.subarray(0, split).toString("ascii");
          const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(header)?.[1]);
          const length = Number(/\r\nContent-Length: (\d+)/i.exec(header)?.[1]);
          if (!Number.isInteger(length)) throw new Error("Local echo did not provide an HTTP Content-Length.");
          const body = pending.subarray(split + 4); if (body.length < length) return;
          settled = true; socket.destroy(); resolve({ status, nonce: /\r\nX-Echo-Nonce: ([^\r\n]+)/i.exec(header)?.[1] ?? "", body: Buffer.from(body.subarray(0, length)) });
        }
      } catch (error) { fail(error instanceof Error ? error : new Error(String(error))); }
    });
    socket.on("close", () => { if (!settled) fail(new Error(`SOCKS ${phase} closed before the complete response.`)); });
  });
}
interface RoundtripCase { label: string; protocol: NodeProtocol; transport?: NodeConfig["transport"]["type"]; tls?: NodeConfig["tls"]["mode"]; vision?: boolean; enc?: boolean; method?: string; obfs?: boolean; path?: string }
async function roundtrip(spec: RoundtripCase): Promise<void> {
  const engine: CoreName = spec.protocol === "vless" ? "xray" : "singBox";
  await verifyBinary(engine);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-real-proxy-"));
  const owned: OwnedCore[] = [];
  let echo: ReturnType<typeof Bun.serve> | undefined;
  let target: http2.Http2SecureServer | undefined;
  const targetSockets = new Set<net.Socket>();
  try {
    const node = createDefaultNode(spec.protocol);
    node.port = await freePort(); node.publicPort = node.port; node.listen = "127.0.0.1"; node.address = "127.0.0.1";
    while (nodeListenNetworks(node).includes("udp") && !await canBindUdp(node.port)) { node.port = await freePort(); node.publicPort = node.port; }
    if (spec.transport) node.transport.type = spec.transport;
    if (spec.path) node.transport.path = spec.path;
    if (spec.tls) node.tls.mode = spec.tls;
    if (spec.vision) node.flow = "xtls-rprx-vision";
    if (spec.enc) Object.assign(node, await getEncryption());
    if (spec.method) { node.method = spec.method; node.password = crypto.randomBytes(spec.method === "2022-blake3-aes-128-gcm" ? 16 : 32).toString("base64"); }
    if (spec.obfs) node.hy2.obfsPassword = "local-obfs-" + crypto.randomUUID();
    if (node.tls.mode !== "none") { Object.assign(node.tls, await getCertificate()); node.tls.serverName = "example.com"; node.tls.insecure = true; }
    if (node.tls.mode === "reality") {
      target = http2.createSecureServer({ cert: node.tls.certificatePem, key: node.tls.keyPem, allowHTTP1: true, minVersion: "TLSv1.3" });
      target.on("error", () => {});
      target.on("connection", socket => { targetSockets.add(socket); socket.on("close", () => targetSockets.delete(socket)); });
      target.on("stream", (stream: http2.ServerHttp2Stream) => { stream.respond({ ":status": 200 }); stream.end("local TLS target"); });
      await new Promise<void>((resolve, reject) => { target!.once("error", reject); target!.listen(0, "127.0.0.1", resolve); });
      node.tls.reality = { ...generateRealityKeyPair(), shortId: "12ab", handshakeServer: "127.0.0.1", handshakePort: (target.address() as net.AddressInfo).port };
    }
    const config = { ...defaultConfig(), nodes: [node] };
    const client = generateClientConfig(node).config as any;
    let mixedPort = await freePort(); while (mixedPort === node.port) mixedPort = await freePort();
    // Only the local port changes to avoid collisions; all protocol and client
    // listener settings remain exactly as exported for the user.
    if (engine === "xray") client.inbounds[0].port = mixedPort;
    else client.inbounds[0].listen_port = mixedPort;
    if (spec.protocol === "vless" && node.transport.type === "ws") {
      const link = generateNodeLinks(node)[0]!; expect(link.error).toBeUndefined();
      expect(new URL(link.uri!).searchParams.get("path")).toBe(node.transport.path);
    }
    const serverPath = path.join(directory, "server.json"), clientPath = path.join(directory, "client.json");
    const generated = (engine === "xray" ? buildXrayConfig(config) : buildSingBoxConfig(config)) as any;
    // The newer Xray v26.10.17 preview blocks private destinations by default;
    // its loopback-only fixture needs this test-only allowance. Stable v26.3.27
    // runs with the production-generated outbound settings unchanged. Neither
    // case dials a public or other private address.
    if (engine === "xray" && compareCoreVersions(NETWORK_RELEASES.xray.version, "26.10.17") >= 0) generated.outbounds[0].settings.finalRules = [{ action: "allow", network: "tcp", ip: ["127.0.0.1/32"] }];
    if (engine === "xray" && process.env.NEXUS_EDGE_TEST_CORE_DEBUG === "1") { generated.log.loglevel = "debug"; client.log.loglevel = "debug"; }
    fs.writeFileSync(serverPath, JSON.stringify(generated), { mode: 0o600 });
    fs.writeFileSync(clientPath, JSON.stringify(client), { mode: 0o600 });
    for (const file of [serverPath, clientPath]) {
      const result = await runCommand(binaries[engine]!, engine === "xray" ? ["run", "-test", "-config", file] : ["check", "-c", file], { cwd: path.dirname(binaries[engine]!), timeoutMs: 10_000 });
      if (result.code !== 0) throw new Error(`Generated config rejected by ${engine}: ${result.stderr || result.stdout}`);
    }
    const server = startCore(engine, serverPath); owned.push(server);
    if (nodeListenNetworks(node).includes("tcp")) await waitListening(server, node.port);
    if (nodeListenNetworks(node).includes("udp")) await waitUdpListening(server, node.port);
    const proxy = startCore(engine, clientPath); owned.push(proxy); await waitListening(proxy, mixedPort);
    const nonce = crypto.randomUUID();
    const payload = new TextEncoder().encode(`NexusEdge 本机 ${spec.label} ${nonce}\n` + "abcdef0123456789\u0000".repeat(2048));
    let requests = 0;
    echo = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
      requests++; expect(request.method).toBe("POST"); expect(request.headers.get("x-test-nonce")).toBe(nonce);
      return new Response(await request.arrayBuffer(), { headers: { "x-echo-nonce": nonce, "content-type": "application/octet-stream" } });
    } });
    const response = await requestOverSocks(mixedPort, echo.port!, nonce, payload);
    expect(response.status).toBe(200); expect(response.nonce).toBe(nonce);
    const returned = response.body; expect(returned.byteLength).toBe(payload.byteLength);
    expect(crypto.createHash("sha256").update(returned).digest("hex")).toBe(crypto.createHash("sha256").update(payload).digest("hex"));
    expect(requests).toBe(1);
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\nOwned core diagnostics:\n${owned.map((core, index) => `${index === 0 ? "server" : "client"}: ${core.log}`).join("\n")}`);
  } finally {
    if (echo) await echo.stop(true);
    const stopped = await Promise.allSettled(owned.map(stopCore));
    for (const socket of targetSockets) socket.destroy();
    if (target) await new Promise<void>(resolve => target!.close(() => resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
    const failed = stopped.find((result): result is PromiseRejectedResult => result.status === "rejected"); if (failed) throw failed.reason;
  }
}
const cases: RoundtripCase[] = [
  { label: "VLESS TCP", protocol: "vless" },
  { label: "VLESS WS custom path", protocol: "vless", transport: "ws", path: "/nexus-._~/subpath" },
  { label: "VLESS gRPC", protocol: "vless", transport: "grpc" },
  { label: "VLESS XHTTP", protocol: "vless", transport: "xhttp" },
  { label: "VLESS TCP TLS Vision", protocol: "vless", tls: "tls", vision: true },
  { label: "VLESS TCP REALITY Vision", protocol: "vless", tls: "reality", vision: true },
  { label: "VLESS WS Vision ENC", protocol: "vless", transport: "ws", vision: true, enc: true },
  { label: "VLESS XHTTP Vision ENC", protocol: "vless", transport: "xhttp", vision: true, enc: true },
  { label: "VMess TCP", protocol: "vmess" },
  { label: "VMess WS", protocol: "vmess", transport: "ws" },
  { label: "VMess gRPC TLS", protocol: "vmess", transport: "grpc", tls: "tls" },
  { label: "Shadowsocks AEAD", protocol: "shadowsocks", method: "chacha20-ietf-poly1305" },
  { label: "Shadowsocks 2022 AES128", protocol: "shadowsocks" },
  { label: "Shadowsocks 2022 AES256", protocol: "shadowsocks", method: "2022-blake3-aes-256-gcm" },
  { label: "Shadowsocks 2022 ChaCha20", protocol: "shadowsocks", method: "2022-blake3-chacha20-poly1305" },
  { label: "Trojan TLS", protocol: "trojan" },
  { label: "Trojan WS TLS", protocol: "trojan", transport: "ws" },
  { label: "Hysteria2 TLS", protocol: "hysteria2" },
  { label: "Hysteria2 Salamander", protocol: "hysteria2", obfs: true },
  { label: "TUIC TLS", protocol: "tuic" },
  { label: "AnyTLS TLS", protocol: "anytls" },
  { label: "AnyTLS REALITY", protocol: "anytls", tls: "reality" },
  { label: "SOCKS5 password", protocol: "socks" },
  { label: "Naive HTTP2 trusted self-signed", protocol: "naive" },
];
if (process.env.NEXUS_EDGE_TEST_EXTENDED_MATRIX === "1") for (const transport of ["tcp", "ws", "grpc", "xhttp"] as const) for (const tls of ["none", "tls", "reality"] as const) for (const vision of [false, true]) for (const enc of [false, true]) {
  if (transport === "ws" && tls === "reality") continue;
  // Invalid combinations were established by real data tests, not -test alone:
  // without ENC, Vision requires a direct TCP TLS/REALITY stream.
  if (vision && !enc && (transport !== "tcp" || tls === "none")) continue;
  cases.push({ label: `Matrix VLESS/${transport}/${tls}/${vision ? "vision" : "plain"}/${enc ? "ENC" : "none"}`, protocol: "vless", transport, tls, vision, enc });
}
for (const spec of cases) {
  const available = !!binaries[spec.protocol === "vless" ? "xray" : "singBox"] && !!binaries.singBox;
  (available ? test : test.skip)(`real Direct ${spec.label} carries authenticated local bytes both ways`, async () => { await roundtrip(spec); }, 20_000);
}
