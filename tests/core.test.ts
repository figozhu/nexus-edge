import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import {
  type AppConfig, type NodeConfig, type NodeProtocol, type WarpProfile,
  NODE_PROTOCOLS, SHADOWSOCKS_METHODS, LineBuffer, assertSupportedPlatform, atomicWrite, collectConfigSecrets,
  configFingerprint, createDefaultNode, createPaths, defaultConfig, deriveRealityPublicKey, generateClientConfig,
  generateNodeLinks, generateRealityKeyPair, generateShadowsocksPassword, migrateLegacyConfig,
  nodeAllowsTunnel, nodeEngine, nodeListenNetworks, normalizeConnectAddress, normalizeDomain,
  normalizeTransportHost,
  readConfig, redact, validateConfig, validateNode, validateWarpProfile, writeConfig,
} from "../src/core.ts";
import { certificatePem, keyPem } from "./fixtures/tls.ts";

const temporaryDirectories: string[] = [];
function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "nexus-edge-core-test-"));
  temporaryDirectories.push(directory);
  return directory;
}
function warpProfile(): WarpProfile {
  return { privateKey: Buffer.alloc(32, 7).toString("base64"), addresses: ["172.16.0.2/32", "2606:4700:110:abcd::2/128"],
    peerPublicKey: Buffer.alloc(32, 11).toString("base64"), endpointHost: "engage.cloudflareclient.com", endpointPort: 2408, reserved: [0, 128, 255] };
}
function testNode(protocol: NodeProtocol = "vless"): NodeConfig {
  const node = createDefaultNode(protocol);
  node.address = "node.example.com";
  if (node.tls.mode === "tls") { node.tls.certificatePem = certificatePem; node.tls.keyPem = keyPem; node.tls.serverName = "node.example.com"; }
  return node;
}
function testConfig(node = testNode()): AppConfig { return { ...defaultConfig(), nodes: [node] }; }
function tunnelNode(mode: "quick" | "fixed" = "quick"): NodeConfig {
  const node = testNode();
  node.direct = false; node.listen = "127.0.0.1"; node.transport.type = "ws";
  node.tunnel.mode = mode;
  if (mode === "fixed") { node.tunnel.token = "test_TunnelToken_abcdefghijklmnop123456"; node.tunnel.domain = "node.example.com"; }
  return node;
}
function realityNode(protocol: "vless" | "anytls" = "vless"): NodeConfig {
  const node = testNode(protocol);
  node.tls.mode = "reality"; node.tls.serverName = "www.example.com";
  node.tls.reality = { ...generateRealityKeyPair(), shortId: "a123b456", handshakeServer: "www.example.com", handshakePort: 443 };
  return node;
}
function legacyConfig() {
  return { schema: 1, uuid: "2b3916ee-51de-491e-8c5c-9319dd629e9e", port: 2082, wsPath: "/old-node/ws", egress: "direct",
    connectAddress: "104.16.1.2", tunnel: { mode: "fixed", token: "test_TunnelToken_abcdefghijklmnop123456", domain: "node.example.com", protocol: "http2" },
    webhook: { kind: "none", url: "" } };
}
function clientOutbound(node: NodeConfig, via: "direct" | "tunnel" = "direct", assignedDomain?: string): Record<string, any> {
  return (generateClientConfig(node, via, assignedDomain).config.outbounds as Record<string, any>[])[0]!;
}
function shareUrl(node: NodeConfig, via: "direct" | "tunnel" = "direct", assignedDomain?: string): URL {
  const link = generateNodeLinks(node, assignedDomain).find(link => link.via === via)!;
  expect(link.error).toBeUndefined(); expect(link.uri).not.toBeNull();
  return new URL(link.uri!);
}

afterEach(() => { for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

describe("multiple-node configuration", () => {
  test("starts empty and does not create a node or require a tunnel", () => {
    expect(defaultConfig()).toEqual({ schema: 2, nodes: [], webhook: { kind: "none", url: "" } });
    expect(validateConfig(defaultConfig())).toEqual(defaultConfig());
    const node = createDefaultNode("vless");
    expect(node.direct).toBe(true); expect(node.tunnel.mode).toBe("none"); expect(node.address).toBe("");
    expect(validateConfig(testConfig(node)).nodes[0]!.uuid).toBe(node.uuid);
  });
  test.each(NODE_PROTOCOLS)("creates independently authenticated %s nodes", protocol => {
    const first = testNode(protocol), second = createDefaultNode(protocol, [first]);
    expect(first.id).not.toBe(first.uuid); expect(first.id).not.toBe(second.id); expect(first.uuid).not.toBe(second.uuid);
    expect(first.password).not.toBe(second.password); expect(second.port).not.toBe(first.port);
    expect(validateNode(first)).toEqual(first);
    expect(nodeEngine(first)).toBe(protocol === "vless" ? "xray" : "singBox");
  });
  test("accepts several protocols and prevents duplicate internal IDs", () => {
    const vless = testNode("vless"), vmess = testNode("vmess"), ss = testNode("shadowsocks");
    expect(validateConfig({ ...defaultConfig(), nodes: [vless, vmess, ss] }).nodes).toHaveLength(3);
    expect(() => validateConfig({ ...defaultConfig(), nodes: [vless, { ...vmess, id: vless.id }] })).toThrow("ID");
  });
  test("allows a disabled incomplete TLS draft, but refuses to enable or export it", () => {
    const node = createDefaultNode("hysteria2"); node.enabled = false; node.password = "";
    expect(validateConfig(testConfig(node)).nodes[0]!.enabled).toBe(false);
    expect(() => validateNode({ ...node, enabled: true })).toThrow();
    expect(() => validateNode({ ...node, enabled: true }, { allowIncomplete: true })).not.toThrow();
    expect(generateNodeLinks(node)[0]!.uri).toBeNull();
    expect(() => generateClientConfig(node)).toThrow();
  });
  test("rejects malformed credentials even on disabled drafts", () => {
    const node = testNode(); node.enabled = false; node.uuid = "broken";
    expect(() => validateNode(node)).toThrow("UUID");
    const tls = testNode("trojan"); tls.enabled = false; tls.tls.certificatePem = "invalid PEM";
    expect(() => validateNode(tls)).toThrow("X.509");
  });
  test.each([1, 1023, 1024, 65535])("accepts local/public port boundary %i", port => {
    const node = testNode(); node.port = port; node.publicPort = port;
    expect(validateNode(node).port).toBe(port);
  });
  test.each([0, -1, 65536, 2082.5, NaN, Infinity, "2082", null])("rejects invalid ports %s", port => {
    expect(() => validateNode({ ...testNode(), port })).toThrow();
    expect(() => validateNode({ ...testNode(), publicPort: port })).toThrow();
  });
  test("rejects invalid config versions, shapes, and excessive node counts", () => {
    for (const value of [undefined, null, false, 42, "{}", [], {}, { ...defaultConfig(), schema: 1 }, { ...defaultConfig(), nodes: {} },
      { ...defaultConfig(), nodes: Array.from({ length: 33 }, () => ({ ...testNode(), enabled: false })) }]) expect(() => validateConfig(value)).toThrow();
  });
  test("normalizes values without mutating any nested input fields", () => {
    const node = tunnelNode("fixed"); node.uuid = node.uuid.toUpperCase(); node.tunnel.domain = "Node.Example.COM.";
    node.tunnel.connectAddress = "[2606:4700:0:0:0:0:0:1111]";
    const before = structuredClone(node); const normalized = validateNode(node);
    expect(normalized.uuid).toBe(node.uuid.toLowerCase()); expect(normalized.tunnel.domain).toBe("node.example.com");
    expect(normalized.tunnel.connectAddress).toBe("2606:4700::1111"); expect(node).toEqual(before);
  });
  test("preserves leading/trailing password characters", () => {
    const node = testNode("trojan"); node.password = " password :@/# +秘密 ";
    expect(validateNode(node).password).toBe(node.password);
    expect(decodeURIComponent(shareUrl(node).username)).toBe(node.password);
  });
  test("requires credentials for native protocols", () => {
    for (const protocol of ["shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"] as const) {
      const node = testNode(protocol); node.password = ""; expect(() => validateNode(node)).toThrow("密码");
    }
    const socks = testNode("socks"); socks.username = ""; expect(() => validateNode(socks)).toThrow("用户名");
    socks.username = "长".repeat(100); expect(() => validateNode(socks)).toThrow("UTF-8");
  });
  test("validates paths and native transport restrictions", () => {
    const node = testNode(); node.transport.type = "ws";
    for (const path of ["", "nexus-ws", "/with space", "/a?b", "/a#b", "/a\\b", "/a%2Fb", "/中文", "/a//b", "/a/../b", "/a/./b"]) {
      expect(() => validateNode({ ...node, transport: { ...node.transport, path } })).toThrow();
    }
    expect(() => validateNode({ ...testNode("hysteria2"), transport: node.transport })).toThrow("原生");
    expect(() => validateNode({ ...testNode("vmess"), transport: { ...node.transport, type: "xhttp" } })).toThrow("Xray");
  });
  test("treats client addresses separately from binding and permits unknown addresses at startup", () => {
    const node = testNode(); node.listen = "127.0.0.1"; node.address = "";
    expect(validateNode(node).address).toBe("");
    for (const address of ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "https://example.com"]) expect(() => validateNode({ ...node, address })).toThrow();
    expect(() => validateNode({ ...node, listen: "node.example.com" })).toThrow("监听");
  });
  test("allows TCP and UDP on the same number but rejects overlapping sockets", () => {
    const tcp = testNode("vless"), udp = testNode("hysteria2"); udp.port = tcp.port;
    expect(validateConfig({ ...defaultConfig(), nodes: [tcp, udp] }).nodes).toHaveLength(2);
    expect(nodeListenNetworks(udp)).toEqual(["udp"]);
    for (const protocol of ["vless", "vmess", "shadowsocks", "socks"] as const) {
      const other = testNode(protocol); other.port = tcp.port; other.listen = "127.0.0.1";
      expect(() => validateConfig({ ...defaultConfig(), nodes: [tcp, other] })).toThrow("冲突");
      other.enabled = false; expect(() => validateConfig({ ...defaultConfig(), nodes: [tcp, other] })).not.toThrow();
    }
    tcp.listen = "::1"; const same = testNode(); same.port = tcp.port; same.listen = "0:0:0:0:0:0:0:1";
    expect(() => validateConfig({ ...defaultConfig(), nodes: [tcp, same] })).toThrow("冲突");
  });
  test("does not wait for an imaginary fixed SOCKS UDP listener", () => {
    expect(nodeListenNetworks(testNode("socks"))).toEqual(["tcp"]);
    expect(nodeListenNetworks(testNode("shadowsocks"))).toEqual(["tcp", "udp"]);
  });
  test("requires WARP credentials only for enabled nodes selecting WARP", () => {
    const node = testNode(); node.egress = "warp";
    expect(() => validateConfig(testConfig(node))).toThrow("WARP");
    expect(validateConfig({ ...testConfig(node), warp: warpProfile() }).nodes[0]!.egress).toBe("warp");
    node.enabled = false; expect(() => validateConfig(testConfig(node))).not.toThrow();
  });
  test("fingerprints normalized fields, secrets, and topology consistently", () => {
    const config = testConfig(tunnelNode("fixed"));
    const reordered = Object.fromEntries(Object.entries(config).reverse()) as unknown as AppConfig;
    expect(configFingerprint(config)).toBe(configFingerprint(reordered));
    expect(configFingerprint(config)).toBe(configFingerprint(JSON.parse(JSON.stringify(config))));
    for (const change of [(n: NodeConfig) => n.port++, (n: NodeConfig) => n.transport.path = "/other", (n: NodeConfig) => n.tunnel.token += "xyz", (n: NodeConfig) => n.enabled = false]) {
      const copy = structuredClone(config); change(copy.nodes[0]!); expect(configFingerprint(copy)).not.toBe(configFingerprint(config));
    }
  });
});

describe("optional node tunnels", () => {
  test.each(["vless", "vmess"] as const)("supports %s direct, tunnel-only, and both routes", protocol => {
    const node = testNode(protocol); expect(validateNode(node).tunnel.mode).toBe("none");
    node.transport.type = "ws"; node.tunnel.mode = "quick";
    expect(nodeAllowsTunnel(node)).toBe(true); expect(validateNode(node).direct).toBe(true);
    expect(generateNodeLinks(node, "new.trycloudflare.com").map(link => link.via)).toEqual(["direct", "tunnel"]);
    node.direct = false; expect(() => validateNode(node)).toThrow("127.0.0.1");
    node.listen = "::1"; expect(validateNode(node).direct).toBe(false);
    expect(generateNodeLinks(node, "new.trycloudflare.com")).toHaveLength(1);
  });
  test("requires a real endpoint route and compatible WebSocket transport", () => {
    const node = testNode(); node.direct = false;
    expect(() => validateNode(node)).toThrow("至少");
    node.direct = true; node.tunnel.mode = "quick";
    expect(() => validateNode(node)).toThrow("WebSocket");
    const ss = testNode("shadowsocks"); ss.tunnel.mode = "quick";
    expect(() => validateNode(ss)).toThrow("隧道");
    const wsTls = testNode(); wsTls.transport.type = "ws"; wsTls.tunnel.mode = "quick";
    wsTls.tls.mode = "tls"; wsTls.tls.certificatePem = certificatePem; wsTls.tls.keyPem = keyPem;
    expect(() => validateNode(wsTls)).toThrow("本机无 TLS");
  });
  test("validates fixed token/domain and keeps quick mode independent of saved fixed settings", () => {
    const node = tunnelNode("fixed"); expect(validateNode(node)).toEqual(node);
    for (const tunnel of [{ ...node.tunnel, token: "" }, { ...node.tunnel, domain: "" }, { ...node.tunnel, token: "too short" }, { ...node.tunnel, domain: "https://node.example.com" }]) {
      expect(() => validateNode({ ...node, tunnel })).toThrow();
    }
    node.tunnel.mode = "quick";
    expect(shareUrl(node, "tunnel", "fresh.trycloudflare.com").hostname).toBe("fresh.trycloudflare.com");
  });
});

describe("TLS, REALITY and Shadowsocks credentials", () => {
  test("validates X.509 and key matching, including disabled supplied credentials", () => {
    const node = testNode("trojan"); expect(validateNode(node).tls.certificatePem).toBe(certificatePem);
    const otherKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    node.tls.keyPem = otherKey; expect(() => validateNode(node)).toThrow("不匹配");
    node.enabled = false; expect(() => validateNode(node)).toThrow("不匹配");
    node.tls.keyPem = "not a key"; expect(() => validateNode(node)).toThrow("私钥");
  });
  test("refuses an expired certificate for enabled nodes without destroying drafts", () => {
    const node = testNode("hysteria2"), cert = new X509Certificate(certificatePem);
    const clock = spyOn(Date, "now").mockReturnValue(Date.parse(cert.validTo) + 1000);
    try { expect(() => validateNode(node)).toThrow("过期"); node.enabled = false; expect(() => validateNode(node)).not.toThrow(); }
    finally { clock.mockRestore(); }
  });
  test("supports IP certificate names and enforces protocol-specific TLS modes", () => {
    const node = testNode("hysteria2"); node.tls.serverName = "[::1]"; expect(validateNode(node).tls.serverName).toBe("::1");
    node.tls.mode = "none"; expect(() => validateNode(node)).toThrow("需要 TLS");
    const ss = testNode("shadowsocks"); ss.tls = testNode("trojan").tls;
    expect(() => validateNode(ss)).toThrow("TLS");
  });
  test("generates compatible X25519 pairs and rejects mismatched or malformed REALITY settings", () => {
    const node = realityNode(); expect(deriveRealityPublicKey(node.tls.reality.privateKey)).toBe(node.tls.reality.publicKey);
    expect(() => validateNode(node)).not.toThrow();
    const bad = structuredClone(node); bad.tls.reality.publicKey = generateRealityKeyPair().publicKey;
    expect(() => validateNode(bad)).toThrow("不匹配");
    for (const shortId of ["a", "xyz0", "0".repeat(18)]) {
      const copy = structuredClone(node); copy.tls.reality.shortId = shortId; expect(() => validateNode(copy)).toThrow("short ID");
    }
    node.transport.type = "ws"; expect(() => validateNode(node)).toThrow("WebSocket");
    expect(() => deriveRealityPublicKey("a".repeat(43))).toThrow();
  });
  test("requires paired VLESS encryption fields and keeps them out of other protocols", () => {
    const node = testNode(); node.vlessEncryption = "mlkem768x25519plus.native.client-key";
    expect(() => validateNode(node)).toThrow("同时");
    node.vlessDecryption = "mlkem768x25519plus.native.server-key"; expect(() => validateNode(node)).not.toThrow();
    node.protocol = "vmess"; expect(() => validateNode(node)).toThrow("VLESS");
  });
  test("rejects non-operational Vision transports without ENC, including wizard previews", () => {
    const plain = testNode(); plain.flow = "xtls-rprx-vision";
    expect(() => validateNode(plain, { allowIncomplete: true })).toThrow("Vision");
    const secured = realityNode(); secured.flow = "xtls-rprx-vision";
    expect(() => validateNode(secured)).not.toThrow();
    for (const type of ["grpc", "xhttp"] as const) {
      secured.transport.type = type; expect(() => validateNode(secured)).toThrow("Vision");
      secured.vlessEncryption = "mlkem768x25519plus.native.client-key"; secured.vlessDecryption = "mlkem768x25519plus.native.server-key";
      expect(() => validateNode(secured)).not.toThrow();
      secured.vlessEncryption = "none"; secured.vlessDecryption = "none";
    }
  });
  test.each(SHADOWSOCKS_METHODS)("generates correct %s passwords and export credentials", method => {
    const node = testNode("shadowsocks"); node.method = method; node.password = generateShadowsocksPassword(method);
    expect(() => validateNode(node)).not.toThrow();
    expect(node.password).not.toBe(generateShadowsocksPassword(method));
    if (method.startsWith("2022-")) {
      expect(Buffer.from(node.password, "base64")).toHaveLength(method === "2022-blake3-aes-128-gcm" ? 16 : 32);
      node.password = "not-a-2022-key"; expect(() => validateNode(node)).toThrow("Base64");
    }
  });
});

describe("domain, address and WARP validation", () => {
  test("normalizes HTTP Host values without dropping explicit default ports or IPv6 brackets", () => {
    expect(normalizeTransportHost("Node.Example.COM:80")).toBe("node.example.com:80");
    expect(normalizeTransportHost("node.example.com:8443")).toBe("node.example.com:8443");
    expect(normalizeTransportHost("2001:0DB8:0:0:0:0:0:1")).toBe("[2001:db8::1]");
    expect(normalizeTransportHost("[::1]:80")).toBe("[::1]:80");
    for (const host of ["https://example.com", "node.example.com:", "node.example.com:0", "example.com/path", "user@example.com"]) expect(() => normalizeTransportHost(host)).toThrow();
  });
  test("normalizes IDNs and IPv6 addresses without accepting URL or scope suffixes", () => {
    expect(normalizeDomain("Node.Example.COM.")).toBe("node.example.com");
    expect(normalizeDomain("节点.example.com")).toMatch(/^xn--[a-z0-9-]+\.example\.com$/);
    expect(normalizeConnectAddress("104.16.1.2")).toBe("104.16.1.2");
    expect(normalizeConnectAddress("[2606:4700:0:0:0:0:0:1111]")).toBe("2606:4700::1111");
    expect(normalizeConnectAddress("")).toBe("");
    for (const input of ["", "localhost", "https://node.example.com", "node.example.com/path", "node.example.com:443", "104.16.1.2", "user@node.example.com", "*.example.com", "node..example.com", "-node.example.com", "node_.example.com", `${"a".repeat(64)}.example.com`, "node.example.com\n"]) expect(() => normalizeDomain(input)).toThrow();
    for (const input of ["fe80::1%eth0", "[fe80::1%13]"]) expect(() => normalizeConnectAddress(input)).toThrow();
  });
  test("accepts valid WireGuard profiles and rejects corrupted keys, CIDRs, and Reserved values", () => {
    const baseline = warpProfile(); expect(validateWarpProfile(baseline)).toEqual(baseline);
    for (const value of [null, {}, [], { ...baseline, privateKey: "not-a-key" }, { ...baseline, peerPublicKey: Buffer.alloc(31).toString("base64") },
      { ...baseline, addresses: [] }, { ...baseline, addresses: ["172.16.0.2"] }, { ...baseline, addresses: ["172.16.0.2/33"] }, { ...baseline, addresses: ["2606:4700::2/129"] },
      { ...baseline, endpointPort: 0 }, { ...baseline, endpointHost: "https://example.com" }, { ...baseline, reserved: [0, 256, 1] }, { ...baseline, reserved: [0, 1] }, { ...baseline, reserved: [0, 1.5, 2] }]) expect(() => validateWarpProfile(value)).toThrow();
  });
  test("keeps webhook rules consistent when switching notification modes", () => {
    const config = defaultConfig(); config.webhook = { kind: "none", url: "https://example.com/old-secret" };
    expect(validateConfig(config).webhook).toEqual({ kind: "none", url: "" });
    expect(validateConfig({ ...config, webhook: { kind: "generic", url: "https://example.com/hook?key=abc" } }).webhook.url).toBe("https://example.com/hook?key=abc");
    for (const url of ["", "http://example.com", "file:///tmp/hook", "https://user:pass@example.com", "https://example.com/#secret"]) expect(() => validateConfig({ ...config, webhook: { kind: "generic", url } })).toThrow();
  });
});

describe("sharing and standalone client exports", () => {
  test.each(NODE_PROTOCOLS)("exports %s with its own address, public port and credentials", protocol => {
    const node = testNode(protocol); node.publicPort = 12345;
    const item = generateNodeLinks(node)[0]!; expect(item.via).toBe("direct"); expect(item.error).toBeUndefined();
    expect(item.uri === null).toBe(protocol === "naive");
    const result = generateClientConfig(node), outbound = clientOutbound(node);
    if (protocol === "vless") { expect(result.format).toBe("xray"); expect(outbound.settings.vnext[0].port).toBe(12345); expect(outbound.settings.vnext[0].users[0].id).toBe(node.uuid); }
    else { expect(result.format).toBe("sing-box"); expect(outbound.server).toBe(node.address); expect(outbound.server_port).toBe(12345); }
    expect(JSON.stringify(result.config)).not.toContain("PRIVATE KEY");
    expect(JSON.stringify(result.config)).not.toContain(node.tunnel.token || "unexpected-empty-token-marker");
  });
  test("does not fabricate missing direct addresses or unassigned tunnel hostnames", () => {
    const node = testNode(); node.address = "";
    expect(generateNodeLinks(node)[0]!.error).toContain("连接地址"); expect(() => generateClientConfig(node)).toThrow("连接地址");
    const tunnel = tunnelNode(); expect(generateNodeLinks(tunnel)[0]!.error).toContain("尚未分配");
    for (const domain of ["正在分配中", "https://node.example.com", "node.example.com/path"]) expect(generateNodeLinks(tunnel, domain)[0]!.uri).toBeNull();
  });
  test("separates direct address/port from tunnel TLS, SNI, Host, and edge override", () => {
    const node = tunnelNode(); node.direct = true; node.address = "203.0.113.50"; node.publicPort = 8080;
    node.transport.host = "origin.example.com"; node.transport.path = "/nexus/ws-v1._~"; node.tunnel.connectAddress = "2606:4700::1111";
    const direct = shareUrl(node, "direct", "sample.trycloudflare.com"), tunnel = shareUrl(node, "tunnel", "sample.trycloudflare.com");
    expect(direct.hostname).toBe("203.0.113.50"); expect(direct.port).toBe("8080"); expect(direct.searchParams.get("security")).toBe("none");
    expect(direct.searchParams.get("host")).toBe("origin.example.com"); expect(direct.searchParams.has("sni")).toBe(false);
    expect(tunnel.hostname).toBe("[2606:4700::1111]"); expect(tunnel.port).toBe("443");
    expect(tunnel.searchParams.get("sni")).toBe("sample.trycloudflare.com"); expect(tunnel.searchParams.get("host")).toBe("sample.trycloudflare.com");
    expect(tunnel.searchParams.get("path")).toBe(node.transport.path); expect(tunnel.href).not.toContain("%252F");
    const stream = clientOutbound(node, "tunnel", "sample.trycloudflare.com").streamSettings;
    expect(stream.tlsSettings.allowInsecure).toBeUndefined(); expect(stream.tlsSettings.pinnedPeerCertSha256).toBeUndefined(); expect(stream.wsSettings.headers.Host).toBe("sample.trycloudflare.com");
  });
  test("exports VMess UTF-8 names and each transport service/path without losing authentication", () => {
    const node = testNode("vmess"); node.name = "中文 节点"; node.transport.type = "grpc"; node.transport.serviceName = "service/grpc";
    const raw = generateNodeLinks(node)[0]!.uri!;
    const decoded = JSON.parse(Buffer.from(raw.slice("vmess://".length), "base64").toString("utf8"));
    expect(decoded.ps).toContain(node.name); expect(decoded.id).toBe(node.uuid); expect(decoded.aid).toBe("0"); expect(decoded.path).toBe("service/grpc");
    expect(clientOutbound(node).transport.service_name).toBe("service/grpc");
  });
  test("follows SIP002 different userinfo encodings for classic and 2022 Shadowsocks", () => {
    const classic = testNode("shadowsocks"); classic.method = "aes-128-gcm"; classic.password = "复杂 :@/+# password";
    const legacy = shareUrl(classic);
    expect(Buffer.from(legacy.username, "base64url").toString("utf8")).toBe(`${classic.method}:${classic.password}`);
    const modern = testNode("shadowsocks"), modernUrl = shareUrl(modern);
    expect(decodeURIComponent(modernUrl.username)).toBe(modern.method); expect(decodeURIComponent(modernUrl.password)).toBe(modern.password);
  });
  test("exports Hysteria2 obfuscation and TUIC controls, while omitting bandwidth from URI", () => {
    const hy2 = testNode("hysteria2"); hy2.hy2.obfsPassword = "obfs/ +密码"; hy2.tls.insecure = true;
    hy2.hy2.upMbps = 500; hy2.hy2.downMbps = 80;
    const hy2Url = shareUrl(hy2); expect(hy2Url.searchParams.get("obfs-password")).toBe(hy2.hy2.obfsPassword);
    expect(hy2Url.searchParams.get("obfs")).toBe("salamander"); expect(hy2Url.searchParams.get("insecure")).toBe("1");
    expect(hy2Url.searchParams.has("upmbps")).toBe(false); expect(clientOutbound(hy2).obfs.password).toBe(hy2.hy2.obfsPassword);
    expect(clientOutbound(hy2).up_mbps).toBe(80); expect(clientOutbound(hy2).down_mbps).toBe(500);
    const tuic = testNode("tuic"); tuic.tuic.zeroRttHandshake = true; tuic.tuic.congestionControl = "new_reno";
    expect(clientOutbound(tuic).zero_rtt_handshake).toBe(true); expect(shareUrl(tuic).searchParams.get("congestion_control")).toBe("new_reno");
  });
  test("exports only public REALITY material and pairs of client/server ENC stay separate", () => {
    const node = realityNode(); const uri = shareUrl(node), client = clientOutbound(node);
    expect(uri.searchParams.get("pbk")).toBe(node.tls.reality.publicKey);
    expect(client.streamSettings.realitySettings.password).toBe(node.tls.reality.publicKey);
    expect(JSON.stringify(client)).not.toContain(node.tls.reality.privateKey);
    node.tls.mode = "none"; node.vlessEncryption = "mlkem768x25519plus.native.client-key"; node.vlessDecryption = "mlkem768x25519plus.native.server-key";
    expect(shareUrl(node).searchParams.get("encryption")).toBe(node.vlessEncryption);
    expect(JSON.stringify(generateClientConfig(node))).not.toContain(node.vlessDecryption);
  });
  test("uses a certificate pin for current Xray self-signed TLS instead of removed allowInsecure", () => {
    const node = testNode(); node.tls = { ...testNode("trojan").tls, insecure: true };
    const fingerprint = new X509Certificate(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase();
    expect(shareUrl(node).searchParams.get("pcs")).toBe(fingerprint);
    expect(shareUrl(node).searchParams.has("allowInsecure")).toBe(false);
    expect(clientOutbound(node).streamSettings.tlsSettings.pinnedPeerCertSha256).toBe(fingerprint);
    expect(clientOutbound(node).streamSettings.tlsSettings.allowInsecure).toBeUndefined();
  });
  test("uses complete JSON for AnyTLS REALITY and Naive without making unsupported share links", () => {
    const anytls = realityNode("anytls"), anyLink = generateNodeLinks(anytls)[0]!;
    expect(anyLink).toMatchObject({ uri: null, format: "json" }); expect(anyLink.error).toBeUndefined();
    expect(clientOutbound(anytls).tls.reality.public_key).toBe(anytls.tls.reality.publicKey);
    const naive = testNode("naive"); naive.tls.insecure = true;
    const tls = clientOutbound(naive).tls; expect(tls.certificate.join("\n")).toBe(certificatePem.trim());
    expect(tls.insecure).toBeUndefined(); expect(tls.key).toBeUndefined();
    naive.tls.insecure = false; expect(clientOutbound(naive).tls.certificate).toBeUndefined();
  });
  test("never exports a route disabled in the node", () => {
    expect(() => generateClientConfig(testNode(), "tunnel", "example.com")).toThrow("没有开启隧道");
    expect(() => generateClientConfig(tunnelNode(), "direct")).toThrow("没有开启直连");
  });
});

describe("persistent configuration and released-v1 migration", () => {
  test("anchors all files to the entry script, including paths with spaces and Unicode", () => {
    const entry = join(temporaryDirectory(), "Test User 中文 O'Neil", "nexus-edge.ts"), paths = createPaths(entry, join(dirname(entry), "bun runtime", "bun"));
    expect(paths.entry).toBe(entry); expect(paths.root).toBe(dirname(entry));
    for (const filename of [paths.config, paths.runtimeState, paths.log, paths.link, paths.lockDb, paths.tokenFile, paths.singConfig, paths.xrayConfig]) {
      expect(isAbsolute(filename)).toBe(true); expect(dirname(filename)).toBe(paths.data);
    }
  });
  test("creates an empty config once and preserves generated node credentials across reads", () => {
    const paths = createPaths(join(temporaryDirectory(), "nexus-edge.ts")); expect(readConfig(paths)).toEqual(defaultConfig());
    const node = testNode(); writeConfig(paths, testConfig(node)); expect(readConfig(paths).nodes[0]!.uuid).toBe(node.uuid);
  });
  test("archives exact legacy bytes before migrating without changing UUID, token, path, or WARP", () => {
    const paths = createPaths(join(temporaryDirectory(), "nexus-edge.ts")); readConfig(paths);
    const legacy = { ...legacyConfig(), egress: "warp", warp: warpProfile(), webhook: { kind: "generic" as const, url: "https://example.com/hook?key=keep" } };
    const original = JSON.stringify(legacy, null, 3) + "\n"; writeFileSync(paths.config, original);
    const upgraded = readConfig(paths), node = upgraded.nodes[0]!;
    expect(upgraded.schema).toBe(2); expect(node.uuid).toBe(legacy.uuid); expect(node.transport.path).toBe(legacy.wsPath);
    expect(node.listen).toBe("127.0.0.1"); expect(node.direct).toBe(false); expect(node.port).toBe(legacy.port);
    expect(node.tunnel.token).toBe(legacy.tunnel.token); expect(node.tunnel.connectAddress).toBe(legacy.connectAddress);
    expect(upgraded.warp).toEqual(legacy.warp); expect(upgraded.webhook).toEqual(legacy.webhook);
    expect(readFileSync(`${paths.config}.schema1.bak`, "utf8")).toBe(original); expect(readFileSync(`${paths.config}.bak`, "utf8")).toBe(original);
    expect(readConfig(paths)).toEqual(upgraded);
  });
  test("leaves corrupted or unsupported legacy data untouched instead of resetting UUID", () => {
    for (const invalid of ["{broken", "null", '{"schema":999}', JSON.stringify({ ...legacyConfig(), uuid: "broken" })]) {
      const paths = createPaths(join(temporaryDirectory(), "nexus-edge.ts")); readConfig(paths); writeFileSync(paths.config, invalid);
      expect(() => readConfig(paths)).toThrow(); expect(readFileSync(paths.config, "utf8")).toBe(invalid);
    }
    expect(() => migrateLegacyConfig({ ...legacyConfig(), tunnel: null })).toThrow();
  });
  test("rejects invalid writes and never replaces a good backup with corrupted data", () => {
    const paths = createPaths(join(temporaryDirectory(), "nexus-edge.ts")), original = testConfig(); writeConfig(paths, original);
    const before = readFileSync(paths.config, "utf8"), invalid = structuredClone(original); invalid.nodes[0]!.port = 0;
    expect(() => writeConfig(paths, invalid)).toThrow(); expect(readFileSync(paths.config, "utf8")).toBe(before);
    const updated = structuredClone(original); updated.nodes[0]!.port++;
    writeConfig(paths, updated); const backup = readFileSync(`${paths.config}.bak`, "utf8"); expect(JSON.parse(backup)).toEqual(original);
    writeFileSync(paths.config, "{interrupted old file"); updated.nodes[0]!.port++; writeConfig(paths, updated);
    expect(readFileSync(`${paths.config}.bak`, "utf8")).toBe(backup); expect(readConfig(paths).nodes[0]!.uuid).toBe(original.nodes[0]!.uuid);
  });
  test("keeps expired certificates readable and editable while runtime validation still rejects them", () => {
    const paths = createPaths(join(temporaryDirectory(), "nexus-edge.ts"));
    const config = testConfig(testNode("trojan")); writeConfig(paths, config);
    const fingerprint = configFingerprint(config), cert = new X509Certificate(certificatePem);
    const clock = spyOn(Date, "now").mockReturnValue(Date.parse(cert.validTo) + 1000);
    try {
      expect(readConfig(paths)).toEqual(config); expect(configFingerprint(config)).toBe(fingerprint);
      expect(() => validateConfig(config)).toThrow("过期");
      const edited = readConfig(paths); edited.nodes[0]!.name = "等待换证书"; writeConfig(paths, edited);
      expect(readConfig(paths).nodes[0]!.name).toBe("等待换证书");
      edited.nodes[0]!.enabled = false; expect(() => validateConfig(edited)).not.toThrow();
    } finally { clock.mockRestore(); }
  });
});

describe("atomic file replacement", () => {
  test("completely replaces existing content and preserves Unicode", () => {
    const filename = join(temporaryDirectory(), "settings.json");
    atomicWrite(filename, JSON.stringify({ value: "long original contents" }));
    atomicWrite(filename, JSON.stringify({ value: "中文" }));
    expect(JSON.parse(readFileSync(filename, "utf8"))).toEqual({ value: "中文" });
  });

  test("creates a private file when an explicit private mode is requested", () => {
    const filename = join(temporaryDirectory(), "private-state.json");
    atomicWrite(filename, "{}", 0o600);
    expect(readFileSync(filename, "utf8")).toBe("{}");
    if (process.platform !== "win32") {
      expect(statSync(filename).mode & 0o777).toBe(0o600);
    }
  });

  test.skipIf(process.platform === "win32")("does not overwrite a file through a symlink", () => {
    const directory = temporaryDirectory();
    const destination = join(directory, "other-owner.txt");
    const link = join(directory, "settings.json");
    writeFileSync(destination, "must remain unchanged", "utf8");
    symlinkSync(destination, link);
    expect(() => atomicWrite(link, "replacement")).toThrow();
    expect(readFileSync(destination, "utf8")).toBe("must remain unchanged");
  });
});

describe("streamed log lines", () => {
  test("reconstructs a tunnel hostname split across output chunks", () => {
    const lines: string[] = [];
    const buffer = new LineBuffer((line) => lines.push(line));
    buffer.feed(Buffer.from("INF Your quick tunnel is https://quiet-"));
    buffer.feed(Buffer.from("river.trycloud"));
    buffer.feed(Buffer.from("flare.com\nINF Registered tunnel connection\n"));
    buffer.end();
    expect(lines).toEqual([
      "INF Your quick tunnel is https://quiet-river.trycloudflare.com",
      "INF Registered tunnel connection",
    ]);
  });

  test("handles a CRLF delimiter split between chunks and flushes the final line", () => {
    const lines: string[] = [];
    const buffer = new LineBuffer((line) => lines.push(line));
    buffer.feed(Buffer.from("first\r"));
    buffer.feed(Buffer.from("\nsecond\nlast line without newline"));
    expect(lines).toEqual(["first", "second"]);
    buffer.end();
    expect(lines).toEqual(["first", "second", "last line without newline"]);
  });

  test("does not damage a Unicode character divided between byte chunks", () => {
    const lines: string[] = [];
    const buffer = new LineBuffer((line) => lines.push(line));
    const bytes = Buffer.from("节点就绪\n", "utf8");
    for (const byte of bytes) buffer.feed(Buffer.from([byte]));
    buffer.end();
    expect(lines).toEqual(["节点就绪"]);
  });
});

describe("log redaction", () => {
  test("redacts encoded passwords, complete VMess links, PEM lines and both VLESS ENC halves", () => {
    const node = testNode("trojan"); node.password = "secret /+密码:credential";
    const config = testConfig(node), secrets = collectConfigSecrets(config);
    const encoded = encodeURIComponent(node.password), jsonEscaped = JSON.stringify(keyPem).slice(1, -1);
    expect(redact(`${node.password} ${encoded} ${jsonEscaped}`, secrets)).not.toContain(encoded);
    expect(redact(keyPem.split("\n")[1]!, secrets)).toBe("[REDACTED]");
    const vmess = generateNodeLinks(testNode("vmess"))[0]!.uri!; expect(redact(vmess, [])).toBe("vmess://[REDACTED]");
    const enc = testNode(); enc.vlessEncryption = "client-authentication-material"; enc.vlessDecryption = "server-secret-material";
    const encSecrets = collectConfigSecrets(testConfig(enc)); expect(encSecrets).toContain(enc.vlessEncryption); expect(encSecrets).toContain(enc.vlessDecryption);
    expect(redact("none", collectConfigSecrets(defaultConfig()))).toBe("none");
  });
  test("redacts every occurrence of an explicitly supplied secret literally", () => {
    const secret = "token'+[literal].*\\sensitive";
    const output = redact(`before ${secret}, again ${secret}, after`, [secret]);
    expect(output).not.toContain(secret);
    expect(output).toContain("before ");
    expect(output).toContain(", after");
  });

  test("does not alter normal diagnostics when the secret list is empty", () => {
    const message = "INF connection registered; origin=127.0.0.1:2082";
    expect(redact(message, [])).toBe(message);
    expect(redact(message, [""])).toBe(message);
  });

  test("redacts a secret that arrived over multiple log chunks", () => {
    const secret = "nexus-test-secret-abcdefghijklmnopqrstuvwxyz";
    const lines: string[] = [];
    const buffer = new LineBuffer((line) => lines.push(redact(line, [secret])));
    buffer.feed(Buffer.from(`ERR token=${secret.slice(0, 13)}`));
    buffer.feed(Buffer.from(`${secret.slice(13)} rejected\n`));
    buffer.end();
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain(secret);
    expect(lines[0]).toContain("rejected");
  });

  test("masks bearer authorization and node credentials while retaining useful diagnostics", () => {
    const uuid = "2b3916ee-51de-491e-8c5c-9319dd629e9e";
    const secret = "abcdefgh.ijklmnop.qrstuvwxyz";
    const output = redact(`Authorization: Bearer ${secret}; node=vless://${uuid}@node.example.com:443`, []);
    expect(output).not.toContain(secret);
    expect(output).not.toContain(uuid);
    expect(output).toContain("node.example.com:443");
  });

  test("does not leak secret fragments when a single log line exceeds the buffering limit", () => {
    const secret = "nexus-test-secret-abcdefghijklmnopqrstuvwxyz";
    const lines: string[] = [];
    const buffer = new LineBuffer((line) => lines.push(redact(line, [secret])));
    buffer.feed(Buffer.from("x".repeat(16380) + secret));
    buffer.end();
    expect(lines.join("\n").includes(secret.slice(4))).toBe(false);
  });
});

describe("declared platform support", () => {
  test("accepts only advertised platform and architecture combinations", () => {
    expect(() => assertSupportedPlatform("win32", "x64")).not.toThrow();
    expect(() => assertSupportedPlatform("linux", "x64")).not.toThrow();
    expect(() => assertSupportedPlatform("linux", "arm64")).not.toThrow();
    for (const [os, cpu] of [["darwin", "x64"], ["linux", "ia32"], ["win32", "arm64"]] as const) {
      expect(() => assertSupportedPlatform(os, cpu)).toThrow();
    }
  });
});
