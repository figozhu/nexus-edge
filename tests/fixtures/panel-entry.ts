/** 高级节点编辑真实终端夹具：只允许在测试临时目录写配置，所有外部操作均禁止。 */
import * as panelFixturePath from "node:path";
import * as panelFixtureCrypto from "node:crypto";
import * as panelFixtureFs from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { type NodeConfig, type NodeProtocol, createPaths, defaultConfig, readConfig, writeConfig, ensureDataDir, generateClientConfig, generateNodeLinks } from "../../src/core.ts";
import { createSimpleNode } from "../../src/presets.ts";
import { buildXrayConfig, buildSingBoxConfig } from "../../src/network.ts";
import { configureNode, type PanelEditorServices } from "../../src/panel.ts";
import { UserCancelledError, UiExitRequestedError } from "../../src/ui.ts";
import { certificatePem, keyPem } from "./tls.ts";

if (!panelFixturePath.basename(process.cwd()).startsWith("nexus-ui-pty-")) throw new Error("仅允许在 PTY 夹具的独立临时目录执行。");
if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("夹具需要真实 PTY。");
const paths = createPaths(panelFixturePath.join(process.cwd(), "nexus-edge.ts"));
// Windows 只在此处允许临时目录 ACL 初始化；之后的网络、进程、监听一律拒绝。
ensureDataDir(paths);
// 导入单文件时 import.meta.main=false，不运行主面板，避免跳转本机已有系统安装。
const standalone = process.env.NEXUS_EDGE_PTY_STANDALONE === "1" ? await import("../../nexus-edge.ts") : undefined;
standalone?.ensureDataDir(paths);
const configureEditor: typeof configureNode = standalone?.configureNode ?? configureNode;
const EditorCancelledError = standalone?.UserCancelledError ?? UserCancelledError;
const EditorExitRequestedError = standalone?.UiExitRequestedError ?? UiExitRequestedError;
const calls = { certificate: 0, encryption: 0, forbiddenIO: 0 };
/** 拒绝任何非注入的外部操作并记数，返回 never，使测试不会误触正式核心或网络。 */
const denyIO = (): never => { calls.forbiddenIO++; throw new Error("高级 PTY 夹具禁止网络、进程及监听操作。"); };
globalThis.fetch = (async () => denyIO()) as unknown as typeof fetch;
const fixtureRequire = createRequire(import.meta.url);
for (const [name, methods] of [
  ["node:http", ["request", "get"]], ["node:https", ["request", "get"]],
  ["node:net", ["connect", "createConnection"]], ["node:dgram", ["createSocket"]],
  ["node:child_process", ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
] as const) {
  const module = fixtureRequire(name) as Record<string, unknown>;
  for (const method of methods) module[method] = denyIO;
}
fixtureRequire("node:net").Socket.prototype.connect = denyIO;
fixtureRequire("node:net").Server.prototype.listen = denyIO;
Object.assign(Bun, { spawn: denyIO, spawnSync: denyIO, connect: denyIO, listen: denyIO, serve: denyIO });
syncBuiltinESMExports();
// 公开测试 ENC 对，来自官方 Xray；仅注入夹具，不运行核心或读取真实凭据。
const testEncryption = {
  vlessDecryption: "mlkem768x25519plus.native.600s.orDQXtLHcMTDquBHDvThrSmBeoWytwWBZ-O2ly0ruCIzQkRTUBr33yQkGeIFo9FiyXd6l_3Ce3HbzCx3mpSG3Q",
  vlessEncryption: "mlkem768x25519plus.native.0rtt.tyuVF6FlLUU_TfGlHePB1eqPfPpo4JGZYaEx-KIx3BqzS4QNnjlJwAIkKhKrj3mnBHlaNhQW_bpDYQiy8SG9kEefVRkUpnNYQJKLcYgs2lUSkCtKwoNWH8t-4myyfAmytjS5iXOFf6yvgYhK4ROZ7Za0cjuslYk6X3x7RZkJd2C-S_F7IPNmnXOs4ly_h0gbdXqfivtHU9xrzTNw3BdEXyeVo0FLhVjPSeGHJ_Ow3Rpcp9o27bKh7KcYRbc40CUlpAooqZOAciuZ-lO-82iRfvSLDwN_qvzIWQGyr5c3S4IoOZgQQKqeyRWOpHiXNUwHuRYW3Fhf6ER6f6FbA6yM-Fw7oFWoWTN9lRnEOdygT9RsA-dmzJho7oogJdEn5gtuFBU62bCeAcfHOBi3cQFdwHnM2VwSs_pSi8vAOQGJyYuelbGDPCIUv1p8Dqh-4yZHBOgGM_YxCEKakYWSyREND8w_QcRiJCSsmMAsdAYSG9GW1KlTunKKezBdN5k5lGy306nPQ-Bdt8wVrvl8nrksxIEUz8oEcPS-lgRJBHGrAbJ5raDHsqKkFAS01zdAbVmHi8awzmww4mZdpXdlIOmrBGVKMQzJqbmaIRzBEadCOWmSkbwIZTB1YXio0OeTs8sCgCkDp_QgWYhsVfsEwfzLRotjWMxZ33k9RXJgqzh7j4KhzGsAcmGvhGGIzBA75sfOyhMOdQCy6RKO2QQ8jqzMB3BqxZhi1wURMWRkNBCQ0hmNclWLZVKogXF0PMVy6puaI3zHvYo9rnuhs7SiJrU8HARv4lM5e_LIVVtGjMQa76gG8vVJ_QYEH_pJfQCTblzJm_WoiazDmgYVigJ_-gx0bNlj0sskRQOa7nUpOfSj9_JaUXZzv9GKJUEMIOkuDDICirZdV-ch5Qdd42etKoqg90c3qkCYo1c6BQp5ZrxZbtFffaNEWmKmVXynPnJ30bq71cTBNKsJwiwrehIYzqlK1hVazhgzLsy0BcdXCzgHk0BMEgOO6Re2XRtXwiIR8vFV3nhITWud3EuUZDJWedrNe3JdgwqN2TSYvmd4G3zLpcOW2YkBmssG1PXDroCqw-hqtNQP6_GBxQgTKVBx4icraXAtRZaQFkNvYIUkjYl3HoBLmqhnZ0wLUjEEbmdIQcKrjMqfc1dVRjXON4dJXWmN2lmAtVpzTSu_KMOFVaqehQjCAIPBIXea9WgaYZGLz3ogerMv4_GhabvLEBNLSzXFyLLMCdqckXFy6OpHkLyS0Fsw46gVB0inLyxcbqeO9Hu3ZQY-uVKkOteNsTw3KTIUmmRYMliTdhE5Vspc1Cg30Fl_jdw6RzkVBZo3nXOgU9KGsZnEJslWVsKG9nBdfywJrwFn5uZyoEkAQ8cBkvpeUvU5skVkKeAqgLc1_IoaGidU2BKWq-vI7nqnPZyXBdocy3kCNIrOwFBgs1JFSKLB3gbCnJgrEOTE-YqVz8yzJrRCY0tRuGBEA9AvkKhCYoNtfapK2ReulGy56HIJ5QUk3SWSpOYmiIqjEmKqMhAB-YtRbx84HxLKNmrd5DK731bIWxDYqfHC0tD5N7wTvFl5riU",
};
const services: PanelEditorServices = {
  certificate: async () => { calls.certificate++; return { certificatePem, keyPem }; },
  encryption: async () => { calls.encryption++; return { ...testEncryption }; },
};

/** 返回文本 SHA-256；快照只输出密钥/密码摘要，避免终端泄漏完整凭据。 */
function digest(value: string): string { return panelFixtureCrypto.createHash("sha256").update(value).digest("hex"); }
/** 输出可由 PTY 驱动读取的事件；value 为非秘密测试数据，返回 void。 */
function trace(event: string, value: Record<string, unknown> = {}): void {
  process.stdout.write(`\r\n__NEXUS_PTY__${JSON.stringify({ event, ...value, raw: Boolean(process.stdin.isRaw) })}\r\n`);
}
/** 验证保存的 REALITY 参数确实流向服务端、客户端和分享链接，错误直接终止测试。 */
function checkReality(node: NodeConfig): void {
  if (node.tls.mode !== "reality" || !node.enabled) return;
  const r = node.tls.reality;
  const config = { ...defaultConfig(), coreIpv6: true, nodes: [node] };
  if (node.protocol === "vless") {
    const server = (buildXrayConfig(config) as any).inbounds[0].streamSettings.realitySettings;
    const target = `${r.handshakeServer.includes(":") ? `[${r.handshakeServer}]` : r.handshakeServer}:${r.handshakePort}`;
    if (server.target !== target || server.serverNames[0] !== node.tls.serverName) throw new Error("服务端 REALITY 目标或 SNI 与保存配置不同。");
  } else {
    const server = (buildSingBoxConfig(config) as any).inbounds[0].tls;
    if (server.reality.handshake.server !== r.handshakeServer || server.server_name !== node.tls.serverName) throw new Error("sing-box REALITY 参数不一致。");
  }
  if (!node.address || !node.direct) return;
  const client = generateClientConfig(node);
  const outbound = (client.config as any).outbounds[0];
  const sni = client.format === "xray" ? outbound.streamSettings.realitySettings.serverName : outbound.tls.server_name;
  if (sni !== node.tls.serverName) throw new Error("客户端 SNI 未正确导出。");
  const link = generateNodeLinks(node)[0];
  if (node.protocol === "vless" && (!link?.uri || new URL(link.uri).searchParams.get("sni") !== node.tls.serverName)) throw new Error("分享链接 SNI 未正确导出。");
}
/** 返回节点可比较的脱敏快照，包含整个节点指纹以发现未列出字段的意外变化。 */
function nodeView(node: NodeConfig) {
  checkReality(node);
  // 仅在已有连接地址时核对实际导出；缺地址的新建草稿允许稍后补齐。
  if (node.protocol === "vless" && node.vlessEncryption !== "none" && node.address && node.direct) {
    const outbound = (generateClientConfig(node).config as any).outbounds[0];
    const server = (buildXrayConfig({ ...defaultConfig(), coreIpv6: true, nodes: [node] }) as any).inbounds[0];
    if (outbound.settings.vnext[0].users[0].encryption !== node.vlessEncryption || server.settings.decryption !== node.vlessDecryption) throw new Error("ENC 未正确进入客户端/服务端配置。");
  }
  return {
    id: node.id, name: node.name, protocol: node.protocol, enabled: node.enabled, uuid: node.uuid, username: node.username,
    passwordHash: digest(node.password), fingerprint: digest(JSON.stringify(node)), address: node.address,
    port: node.port, publicPort: node.publicPort, listen: node.listen, direct: node.direct, method: node.method,
    transport: node.transport, flow: node.flow, vmessSecurity: node.vmessSecurity, hy2: { ...node.hy2, obfsPassword: undefined, obfsHash: digest(node.hy2.obfsPassword) }, tuic: node.tuic,
    hasEncryption: node.vlessEncryption !== "none", encryptionHash: digest(node.vlessEncryption), decryptionHash: digest(node.vlessDecryption),
    tls: { mode: node.tls.mode, serverName: node.tls.serverName, alpn: node.tls.alpn, insecure: node.tls.insecure,
      certificateHash: digest(node.tls.certificatePem), keyHash: digest(node.tls.keyPem),
      reality: { ...node.tls.reality, privateKey: undefined, privateKeyHash: digest(node.tls.reality.privateKey) } },
    tunnel: { ...node.tunnel, token: undefined, tokenHash: digest(node.tunnel.token), hasToken: Boolean(node.tunnel.token) },
  };
}
/** 读取测试配置并输出快照；快照不包含服务端私钥、密码、证书私钥或隧道 Token。 */
function snapshot(event: string): void {
  trace(event, { nodes: readConfig(paths).nodes.map(nodeView), configHash: digest(panelFixtureFs.readFileSync(paths.config, "utf8")), calls });
}
/** 创建已有测试节点；地址均为文档保留地址，protocol 决定预设，永不启动。 */
function seedNode(protocol: NodeProtocol = "vless"): NodeConfig {
  const node = createSimpleNode(protocol);
  Object.assign(node, { name: "已有测试节点", address: "198.51.100.25", port: 28443, publicPort: 28443 });
  if (node.tls.mode === "tls") Object.assign(node.tls, { certificatePem, keyPem, serverName: "node.example.com" });
  return node;
}

const scenario = process.argv[2] ?? "";
const sentinel = createSimpleNode("socks");
Object.assign(sentinel, { name: "不应被修改的旁路节点", address: "192.0.2.10", port: 28000, publicPort: 28000 });
const isDefault = scenario.startsWith("default-");
const existing = seedNode(scenario === "tunnel-modes" || scenario === "vmess-tunnel-encryption" ? "vmess" : scenario === "tls-only" ? "trojan" : scenario === "auth-password" ? "shadowsocks" : scenario === "options-hy2" ? "hysteria2" : scenario === "options-tuic" ? "tuic" : "vless");
if (scenario === "vmess-tunnel-encryption") {
  Object.assign(existing.tls, { mode: "tls", certificatePem, keyPem, serverName: "node.example.com" });
  existing.vmessSecurity = "zero";
}
if (scenario === "reality-preserve") {
  existing.tls.serverName = "cert.example.test";
  Object.assign(existing.tls.reality, { handshakeServer: "192.0.2.17", handshakePort: 9443, shortId: "" });
}
writeConfig(paths, { ...defaultConfig(), nodes: isDefault ? [sentinel] : [sentinel, existing] });
trace("start", { stdinTTY: process.stdin.isTTY, stdoutTTY: process.stdout.isTTY });
snapshot("seed");
if (scenario === "tunnel-modes" || scenario === "ports") {
  for (let i = 1; i <= 3; i++) { await configureEditor(paths, readConfig(paths).nodes[1]!, services); snapshot(`saved-${i}`); }
} else {
  try {
    await configureEditor(paths, isDefault ? undefined : readConfig(paths).nodes[1]!, services);
    snapshot("saved");
  } catch (error) {
    if (error instanceof EditorExitRequestedError) snapshot("exited");
    else if (error instanceof EditorCancelledError) snapshot("cancelled");
    else throw error;
  }
}
if (calls.forbiddenIO) throw new Error("测试期间发生了禁止的外部操作。");
if (panelFixtureFs.readdirSync(paths.bin).length) throw new Error("编辑器意外下载了核心。");
if (panelFixtureFs.existsSync(paths.runtimeState)) throw new Error("编辑器意外启动了后台。");
trace("done");
