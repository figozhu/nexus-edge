/** Real simple-panel PTY fixture. All runtime/network operations are local mocks. */
import * as simpleFixturePath from "node:path";
import * as simpleFixtureFs from "node:fs";
import * as simpleFixtureCrypto from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { type NodeConfig, createPaths, createDefaultNode, defaultConfig, readConfig, writeConfig, generateRealityKeyPair } from "../../src/core.ts";
import { configureSimpleNode, type SimplePanelServices, type SimplePanelActions } from "../../src/simple.ts";
import { createSimpleNode } from "../../src/presets.ts";
import { panelExport } from "../../src/panel.ts";
import { UserCancelledError } from "../../src/ui.ts";
import { certificatePem, keyPem } from "./tls.ts";

// Generated once by official Xray v26.10.17 `vlessenc` (ML-KEM-768 section).
// Public test material: never use this fixed pair for a real node. The fixture
// returns the pair without running/downloading a core or opening any sockets.
const testEncryption = {
  vlessDecryption: "mlkem768x25519plus.native.600s.orDQXtLHcMTDquBHDvThrSmBeoWytwWBZ-O2ly0ruCIzQkRTUBr33yQkGeIFo9FiyXd6l_3Ce3HbzCx3mpSG3Q",
  vlessEncryption: "mlkem768x25519plus.native.0rtt.tyuVF6FlLUU_TfGlHePB1eqPfPpo4JGZYaEx-KIx3BqzS4QNnjlJwAIkKhKrj3mnBHlaNhQW_bpDYQiy8SG9kEefVRkUpnNYQJKLcYgs2lUSkCtKwoNWH8t-4myyfAmytjS5iXOFf6yvgYhK4ROZ7Za0cjuslYk6X3x7RZkJd2C-S_F7IPNmnXOs4ly_h0gbdXqfivtHU9xrzTNw3BdEXyeVo0FLhVjPSeGHJ_Ow3Rpcp9o27bKh7KcYRbc40CUlpAooqZOAciuZ-lO-82iRfvSLDwN_qvzIWQGyr5c3S4IoOZgQQKqeyRWOpHiXNUwHuRYW3Fhf6ER6f6FbA6yM-Fw7oFWoWTN9lRnEOdygT9RsA-dmzJho7oogJdEn5gtuFBU62bCeAcfHOBi3cQFdwHnM2VwSs_pSi8vAOQGJyYuelbGDPCIUv1p8Dqh-4yZHBOgGM_YxCEKakYWSyREND8w_QcRiJCSsmMAsdAYSG9GW1KlTunKKezBdN5k5lGy306nPQ-Bdt8wVrvl8nrksxIEUz8oEcPS-lgRJBHGrAbJ5raDHsqKkFAS01zdAbVmHi8awzmww4mZdpXdlIOmrBGVKMQzJqbmaIRzBEadCOWmSkbwIZTB1YXio0OeTs8sCgCkDp_QgWYhsVfsEwfzLRotjWMxZ33k9RXJgqzh7j4KhzGsAcmGvhGGIzBA75sfOyhMOdQCy6RKO2QQ8jqzMB3BqxZhi1wURMWRkNBCQ0hmNclWLZVKogXF0PMVy6puaI3zHvYo9rnuhs7SiJrU8HARv4lM5e_LIVVtGjMQa76gG8vVJ_QYEH_pJfQCTblzJm_WoiazDmgYVigJ_-gx0bNlj0sskRQOa7nUpOfSj9_JaUXZzv9GKJUEMIOkuDDICirZdV-ch5Qdd42etKoqg90c3qkCYo1c6BQp5ZrxZbtFffaNEWmKmVXynPnJ30bq71cTBNKsJwiwrehIYzqlK1hVazhgzLsy0BcdXCzgHk0BMEgOO6Re2XRtXwiIR8vFV3nhITWud3EuUZDJWedrNe3JdgwqN2TSYvmd4G3zLpcOW2YkBmssG1PXDroCqw-hqtNQP6_GBxQgTKVBx4icraXAtRZaQFkNvYIUkjYl3HoBLmqhnZ0wLUjEEbmdIQcKrjMqfc1dVRjXON4dJXWmN2lmAtVpzTSu_KMOFVaqehQjCAIPBIXea9WgaYZGLz3ogerMv4_GhabvLEBNLSzXFyLLMCdqckXFy6OpHkLyS0Fsw46gVB0inLyxcbqeO9Hu3ZQY-uVKkOteNsTw3KTIUmmRYMliTdhE5Vspc1Cg30Fl_jdw6RzkVBZo3nXOgU9KGsZnEJslWVsKG9nBdfywJrwFn5uZyoEkAQ8cBkvpeUvU5skVkKeAqgLc1_IoaGidU2BKWq-vI7nqnPZyXBdocy3kCNIrOwFBgs1JFSKLB3gbCnJgrEOTE-YqVz8yzJrRCY0tRuGBEA9AvkKhCYoNtfapK2ReulGy56HIJ5QUk3SWSpOYmiIqjEmKqMhAB-YtRbx84HxLKNmrd5DK731bIWxDYqfHC0tD5N7wTvFl5riU",
};

const scenario = process.argv[2] ?? "";
const paths = createPaths(simpleFixturePath.join(process.cwd(), "nexus-edge.ts"));
const calls = { detect: 0, local: 0, port: 0, certificate: 0, encryption: 0, apply: 0, advanced: 0, forbiddenIO: 0 };
const portChecks: { protocol: string; listen: string; port: number }[] = [];
const denyIO = () => { calls.forbiddenIO++; throw new Error("Simple PTY fixtures must not access a network, start a process, or listen on a socket."); };
globalThis.fetch = (async () => denyIO()) as unknown as typeof fetch;
// Fail closed if a regression bypasses the service mocks. Existing stdin/stdout
// PTY handles keep working; no new network socket or child process is needed.
const fixtureRequire = createRequire(import.meta.url);
for (const [name, functions] of [
  ["node:http", ["request", "get"]], ["node:https", ["request", "get"]],
  ["node:net", ["connect", "createConnection"]], ["node:dgram", ["createSocket"]],
  ["node:child_process", ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
] as const) {
  const module = fixtureRequire(name) as Record<string, unknown>;
  for (const method of functions) module[method] = denyIO;
}
fixtureRequire("node:net").Socket.prototype.connect = denyIO;
fixtureRequire("node:net").Server.prototype.listen = denyIO;
Object.assign(Bun, { spawn: denyIO, spawnSync: denyIO, connect: denyIO, listen: denyIO, serve: denyIO });
syncBuiltinESMExports();

function digest(value: string): string { return simpleFixtureCrypto.createHash("sha256").update(value).digest("hex"); }
function trace(event: string, value: Record<string, unknown> = {}): void {
  process.stdout.write(`\r\n__NEXUS_PTY__${JSON.stringify({ event, ...value, raw: Boolean(process.stdin.isRaw) })}\r\n`);
}
function nodeView(node: NodeConfig) {
  return {
    id: node.id, name: node.name, protocol: node.protocol, enabled: node.enabled,
    uuid: node.uuid, username: node.username, passwordHash: digest(node.password),
    address: node.address, listen: node.listen, port: node.port, publicPort: node.publicPort,
    direct: node.direct, egress: node.egress, method: node.method, transport: node.transport,
    tls: { mode: node.tls.mode, serverName: node.tls.serverName, alpn: node.tls.alpn, insecure: node.tls.insecure,
      certificateHash: digest(node.tls.certificatePem), keyHash: digest(node.tls.keyPem),
      reality: { ...node.tls.reality, privateKey: undefined, privateKeyHash: digest(node.tls.reality.privateKey) } },
    flow: node.flow, hasEncryption: node.vlessEncryption !== "none", hasDecryption: node.vlessDecryption !== "none",
    encryptionHash: digest(node.vlessEncryption), decryptionHash: digest(node.vlessDecryption),
    vmessSecurity: node.vmessSecurity,
    tunnel: { ...node.tunnel, token: undefined, tokenHash: digest(node.tunnel.token), hasToken: Boolean(node.tunnel.token) },
    fingerprint: digest(JSON.stringify(node)),
    withoutAddressFingerprint: digest(JSON.stringify({ ...node, address: "" })),
  };
}
function snapshot(event: string): void {
  const config = readConfig(paths);
  trace(event, { nodes: config.nodes.map(nodeView), calls, portChecks,
    configHash: digest(simpleFixtureFs.readFileSync(paths.config, "utf8")) });
}

const services: SimplePanelServices = {
  detectAddresses: async () => {
    calls.detect++;
    const failed = scenario === "ip-failure-manual";
    const ipv6 = scenario === "new-ipv6" ? "2a01:4f9:3b:1234::2" : null;
    const ipv4 = failed || ipv6 ? null : "45.32.22.10";
    return { ipv4, ipv6, preferredAddress: ipv4 || ipv6,
      source: { ipv4: ipv4 ? "https://api.ipify.org/?format=json" : null, ipv6: ipv6 ? "https://api6.ipify.org/?format=json" : null },
      warnings: failed ? ["模拟探测失败；请手动填写。"] : ipv6 ? ["本次仅识别到 IPv6；客户端网络也需要支持 IPv6。"] : ["探测得到出口公网 IP，仍需确认 NAT / 防火墙。"],
      cancelled: false, checkedAt: "2026-10-21T00:00:00.000Z" };
  },
  localAddresses: () => { calls.local++; return [{ address: "192.168.7.2", family: 4, interfaceName: "mock-ethernet", scope: "private" }]; },
  availablePort: async node => { calls.port++; portChecks.push({ protocol: node.protocol, listen: node.listen, port: node.port }); return node.port + 7; },
  certificate: async () => { calls.certificate++; return { certificatePem, keyPem }; },
  encryption: async () => { calls.encryption++; return { ...testEncryption }; },
};
const actions: SimplePanelActions = {
  apply: async config => { calls.apply++; writeConfig(paths, config); },
  advanced: async () => { calls.advanced++; throw new UserCancelledError(); },
};

function seed(node: NodeConfig): void { writeConfig(paths, { ...defaultConfig(), nodes: [node] }); snapshot("seed"); }
function existingVmess(): NodeConfig {
  const node = createSimpleNode("vmess");
  Object.assign(node, { name: "已有 VMess", uuid: "88888888-1111-4222-8333-444444444444", address: "45.77.12.34", port: 18086, publicPort: 28086 });
  node.transport.path = "/keep-existing-ws";
  node.transport.host = "ws.example.test:9443";
  return node;
}
async function editor(existing = true): Promise<void> { await configureSimpleNode(paths, existing ? readConfig(paths).nodes[0] : undefined, actions, services); }
async function cancelledEditor(existing: boolean, event: string): Promise<void> {
  const before = simpleFixtureFs.readFileSync(paths.config, "utf8");
  let cancelled = false;
  try { await editor(existing); } catch (error) { if (!(error instanceof UserCancelledError)) throw error; cancelled = true; }
  if (!cancelled || simpleFixtureFs.readFileSync(paths.config, "utf8") !== before) throw new Error("Cancelled simple editor changed persistent configuration.");
  snapshot(event);
}

if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("This fixture requires a real PTY.");
writeConfig(paths, defaultConfig());
trace("start", { stdinTTY: process.stdin.isTTY, stdoutTTY: process.stdout.isTTY });
switch (scenario) {
  case "default-ss": case "default-vmess": case "default-vless": case "ip-failure-manual": case "new-ipv6":
    await editor(false); snapshot("saved"); break;
  case "default-trojan":
    trace("expected-material", { certificateHash: digest(certificatePem), keyHash: digest(keyPem) });
    await editor(false); snapshot("saved"); break;
  case "disabled-partial-tls": {
    const node = createDefaultNode("trojan");
    Object.assign(node, { name: "停用的半组 TLS 材料", enabled: false, address: "old-tls.example.test", port: 28043, publicPort: 38043 });
    Object.assign(node.tls, { serverName: "node.example.com", certificatePem, keyPem: "", insecure: false, alpn: ["h2"] });
    seed(node); await editor(); snapshot("saved"); break;
  }
  case "existing-complex": {
    const node = createDefaultNode("vless");
    Object.assign(node, { name: "已有复杂 XHTTP 节点", uuid: "22222222-1111-4222-8333-444444444444", username: "custom-user",
      password: "DORMANT_PASSWORD_8759", address: "complex.example.test", listen: "127.0.0.1", port: 29311, publicPort: 49311 });
    node.transport = { type: "xhttp", path: "/keep-xhttp-path", host: "front.example.test:8443", serviceName: "dormant-grpc", mode: "packet-up" };
    node.tls = { mode: "reality", serverName: "target.example.test", alpn: ["h2"], certificatePem, keyPem, insecure: false,
      reality: { ...generateRealityKeyPair(), shortId: "abcdef0123", handshakeServer: "target.example.test", handshakePort: 8443 } };
    node.hy2 = { obfsPassword: "DORMANT_OBFS_642", upMbps: 99, downMbps: 321 };
    node.tuic = { congestionControl: "cubic", zeroRttHandshake: true };
    node.tunnel = { mode: "none", token: "DORMANT_TOKEN_0123456789", domain: "saved.example.test", connectAddress: "edge.example.test", protocol: "http2" };
    seed(node); await editor(); snapshot("saved"); break;
  }
  case "vmess-tunnel-modes":
    seed(existingVmess());
    for (let i = 1; i <= 3; i++) { await editor(); snapshot(`saved-${i}`); }
    break;
  case "vless-tunnel-enc": {
    const node = createSimpleNode("vless");
    Object.assign(node, { name: "VLESS 保留直连", address: "45.77.12.34", port: 29443, publicPort: 39443 });
    seed(node); await editor(); snapshot("saved"); break;
  }
  case "vmess-tls-to-tunnel": {
    const node = existingVmess();
    node.vmessSecurity = "zero";
    Object.assign(node.tls, { mode: "tls", serverName: "node.example.com", certificatePem, keyPem, insecure: true, alpn: ["http/1.1"] });
    seed(node); await editor(); snapshot("saved"); break;
  }
  case "cancel":
    seed(existingVmess());
    await cancelledEditor(true, "cancelled-1");
    await cancelledEditor(false, "cancelled-2");
    break;
  case "export-missing-ss": {
    const node = createDefaultNode("shadowsocks");
    Object.assign(node, { name: "旧 SS 缺地址", uuid: "77777777-1111-4222-8333-444444444444", username: "preserved-user",
      password: Buffer.from("0123456789abcdef").toString("base64"), port: 18388, publicPort: 48388 });
    node.tls.serverName = "preserve-sni.example.test";
    node.transport.path = "/preserve-dormant-path";
    seed(node); await panelExport(paths, services); snapshot("exported"); break;
  }
  default: throw new Error(`Unknown scenario ${scenario}`);
}
if (calls.forbiddenIO) throw new Error(`The simple panel attempted ${calls.forbiddenIO} unexpected IO operations.`);
if (simpleFixtureFs.existsSync(paths.bin) && simpleFixtureFs.readdirSync(paths.bin).length) throw new Error("The simple panel downloaded a core.");
for (const file of [paths.runtimeState, paths.lockDb, paths.singConfig, paths.xrayConfig]) {
  if (simpleFixtureFs.existsSync(file)) throw new Error("The simple panel unexpectedly created runtime state.");
}
if (simpleFixtureFs.existsSync(simpleFixturePath.join(paths.data, "exports"))) throw new Error("The fixture unexpectedly required writing a client export.");
trace("done");
