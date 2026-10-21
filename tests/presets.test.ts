import { describe, expect, test } from "bun:test";
import { type NodeConfig, type NodeProtocol, NODE_PROTOCOLS, createDefaultNode, deriveRealityPublicKey, generateRealityKeyPair, nodeAllowsTunnel, nodeListenNetworks, validateNode } from "../src/core.ts";
import { SIMPLE_PROTOCOL_LABELS, applySimpleTunnel, createSimpleNode } from "../src/presets.ts";
import { certificatePem, keyPem } from "./fixtures/tls.ts";

function tunnelNode(protocol: "vless" | "vmess" = "vless", mode: "quick" | "fixed" = "quick"): NodeConfig {
  const node = applySimpleTunnel(createSimpleNode(protocol), mode);
  node.tunnel.token = "test_TunnelToken_abcdefghijklmnop123456";
  node.tunnel.domain = "tunnel.example.com";
  return node;
}

describe("simple protocol presets", () => {
  test("exposes every supported protocol without forcing a tunnel", () => {
    expect(Object.keys(SIMPLE_PROTOCOL_LABELS).sort()).toEqual([...NODE_PROTOCOLS].sort());
    for (const protocol of NODE_PROTOCOLS) {
      const node = createSimpleNode(protocol);
      expect(SIMPLE_PROTOCOL_LABELS[protocol].length).toBeGreaterThan(0);
      expect(node.protocol).toBe(protocol);
      expect(node.direct).toBe(true);
      expect(node.listen).toBe("0.0.0.0");
      expect(node.tunnel.mode).toBe("none");
      expect(node.egress).toBe("direct");
      expect(node.address).toBe("");
      expect(node.publicPort).toBe(node.port);
      expect(() => validateNode(node, { allowIncomplete: true })).not.toThrow();
    }
  });

  test("VLESS is ready for TCP REALITY Vision with unique generated keys", () => {
    const node = createSimpleNode("vless");
    const another = createSimpleNode("vless");
    expect(node.transport.type).toBe("tcp");
    expect(node.tls.mode).toBe("reality");
    expect(node.tls.serverName).toBe("apple.com");
    expect(node.tls.reality.handshakeServer).toBe("apple.com");
    expect(node.tls.reality.handshakePort).toBe(443);
    expect(node.tls.reality.shortId).toMatch(/^[0-9a-f]{16}$/);
    expect(deriveRealityPublicKey(node.tls.reality.privateKey)).toBe(node.tls.reality.publicKey);
    expect(node.tls.reality.privateKey).not.toBe(another.tls.reality.privateKey);
    expect(node.tls.reality.shortId).not.toBe(another.tls.reality.shortId);
    expect(node.uuid).not.toBe(another.uuid);
    expect(node.flow).toBe("xtls-rprx-vision");
    expect([node.vlessEncryption, node.vlessDecryption]).toEqual(["none", "none"]);
    expect(() => validateNode(node)).not.toThrow();
  });

  test("VMess uses WS and Shadowsocks generates a valid independent SS2022 key", () => {
    const vmess = createSimpleNode("vmess");
    expect(vmess.transport.type).toBe("ws");
    expect(vmess.transport.path).toMatch(/^\//);
    expect(vmess.vmessSecurity).toBe("auto");
    expect(vmess.tls.mode).toBe("none");
    expect(() => validateNode(vmess)).not.toThrow();
    const ss = createSimpleNode("shadowsocks");
    const another = createSimpleNode("shadowsocks");
    expect(ss.method).toBe("2022-blake3-aes-128-gcm");
    expect(Buffer.from(ss.password, "base64").length).toBe(16);
    expect(ss.password).not.toBe(another.password);
    expect(ss.tls.mode).toBe("none");
    expect(() => validateNode(ss)).not.toThrow();
  });

  test("TLS presets defer certificate generation and choose the protocol ALPN", () => {
    const protocols: NodeProtocol[] = ["trojan", "hysteria2", "tuic", "anytls", "naive"];
    for (const protocol of protocols) {
      const node = createSimpleNode(protocol);
      expect(node.transport.type).toBe("tcp");
      expect(node.tls.mode).toBe("tls");
      expect(node.tls.serverName).toBe("nexus.local");
      expect(node.tls.insecure).toBe(true);
      expect([node.tls.certificatePem, node.tls.keyPem]).toEqual(["", ""]);
      expect(node.tls.alpn).toEqual(protocol === "hysteria2" || protocol === "tuic" ? ["h3"] : protocol === "naive" ? ["h2"] : ["h2", "http/1.1"]);
      expect(() => validateNode(node)).toThrow(/证书/);
      node.tls.certificatePem = certificatePem;
      node.tls.keyPem = keyPem;
      node.tls.serverName = "node.example.com";
      expect(() => validateNode(node)).not.toThrow();
    }
    expect(createSimpleNode("hysteria2").hy2).toEqual({ upMbps: 100, downMbps: 100, obfsPassword: "" });
    expect(createSimpleNode("tuic").tuic).toEqual({ congestionControl: "bbr", zeroRttHandshake: false });
  });

  test("SOCKS has generated authentication without TLS or a UDP startup listener", () => {
    const node = createSimpleNode("socks");
    expect(node.username).not.toBe("");
    expect(node.password.length).toBeGreaterThan(20);
    expect(node.tls.mode).toBe("none");
    expect(nodeListenNetworks(node)).toEqual(["tcp"]);
    expect(() => validateNode(node)).not.toThrow();
  });

  test("reuses core allocation while leaving existing nodes unchanged", () => {
    const existing: NodeConfig[] = [];
    for (const protocol of [...NODE_PROTOCOLS, "vless", "hysteria2"] as NodeProtocol[]) {
      const snapshot = structuredClone(existing);
      const node = createSimpleNode(protocol, existing);
      expect(existing).toEqual(snapshot);
      expect(existing.some(other => other.enabled && other.port === node.port && nodeListenNetworks(other).some(network => nodeListenNetworks(node).includes(network)))).toBe(false);
      existing.push(node);
    }
    expect(new Set(existing.map(node => node.id)).size).toBe(existing.length);
  });
});

describe("explicit simple tunnel changes", () => {
  test("new VLESS tunnel converts the transport and keeps identity, credentials, and dormant advanced fields", () => {
    const node = createSimpleNode("vless");
    node.address = "node.example.com";
    node.publicPort = 9443;
    node.name = "Existing VLESS";
    node.enabled = false;
    node.egress = "warp";
    node.transport.path = "/custom/ws";
    node.transport.host = "ws.example.com:8080";
    node.transport.serviceName = "custom-grpc";
    node.transport.mode = "stream-up";
    node.vlessEncryption = "test-enc-client";
    node.vlessDecryption = "test-enc-server";
    node.tunnel.token = "test_TunnelToken_abcdefghijklmnop123456";
    node.tunnel.domain = "tunnel.example.com";
    node.tunnel.connectAddress = "cdn.example.com";
    node.tunnel.protocol = "http2";
    const snapshot = structuredClone(node);
    const changed = applySimpleTunnel(node, "fixed");
    expect(node).toEqual(snapshot);
    expect(changed).toEqual({ ...snapshot, flow: "",
      transport: { ...snapshot.transport, type: "ws" }, tls: { ...snapshot.tls, mode: "none" }, tunnel: { ...snapshot.tunnel, mode: "fixed" } });
    expect(nodeAllowsTunnel(changed)).toBe(true);
    expect(() => validateNode(changed)).not.toThrow();
    changed.tls.reality.privateKey = "";
    expect(node.tls.reality.privateKey).toBe(snapshot.tls.reality.privateKey);
  });

  test.each(["quick", "fixed"] as const)("same %s mode is a detached no-op for customized nodes", mode => {
    const node = tunnelNode("vless", mode);
    node.direct = true;
    node.listen = "192.0.2.50";
    node.vlessEncryption = "test-enc-client";
    node.vlessDecryption = "test-enc-server";
    node.flow = "xtls-rprx-vision";
    const changed = applySimpleTunnel(node, mode);
    expect(changed).toEqual(node);
    expect(changed).not.toBe(node);
  });

  test("none-to-none does not reset an advanced VLESS setup", () => {
    const node = createDefaultNode("vless");
    node.transport.type = "xhttp";
    node.transport.path = "/advanced";
    node.transport.mode = "stream-one";
    node.tls.mode = "tls";
    node.tls.serverName = "custom.example.com";
    node.tls.certificatePem = certificatePem;
    node.tls.keyPem = keyPem;
    node.vlessEncryption = "test-enc-client";
    node.vlessDecryption = "test-enc-server";
    node.flow = "xtls-rprx-vision";
    expect(applySimpleTunnel(node, "none")).toEqual(node);
  });

  test.each([true, false])("quick/fixed changes preserve direct=%s and the selected listener", direct => {
    const node = tunnelNode();
    node.direct = direct;
    node.listen = direct ? "192.0.2.50" : "::1";
    node.transport.path = "/do-not-replace";
    const fixed = applySimpleTunnel(node, "fixed");
    expect(fixed).toEqual({ ...node, tunnel: { ...node.tunnel, mode: "fixed" } });
    expect(applySimpleTunnel(fixed, "quick")).toEqual(node);
  });

  test("closing a VLESS tunnel restores Reality with its old keys, target, SNI, and ENC", () => {
    const node = tunnelNode();
    node.listen = "::1";
    node.tls.serverName = "sni.example.com";
    node.tls.reality.handshakeServer = "target.example.com";
    node.tls.reality.handshakePort = 8443;
    node.vlessEncryption = "test-enc-client";
    node.vlessDecryption = "test-enc-server";
    const snapshot = structuredClone(node);
    const changed = applySimpleTunnel(node, "none");
    expect(node).toEqual(snapshot);
    expect(changed).toEqual({ ...snapshot, direct: true, listen: "::", flow: "xtls-rprx-vision",
      transport: { ...snapshot.transport, type: "tcp" }, tls: { ...snapshot.tls, mode: "reality" }, tunnel: { ...snapshot.tunnel, mode: "none" } });
    expect(() => validateNode(changed)).not.toThrow();
  });

  test("closing an old VLESS tunnel without Reality metadata creates working defaults", () => {
    const node = createDefaultNode("vless");
    node.transport.type = "ws";
    node.tls.serverName = "old-tls.example.com";
    node.direct = false;
    node.listen = "127.0.0.1";
    node.tunnel.mode = "quick";
    const changed = applySimpleTunnel(node, "none");
    expect(changed.listen).toBe("0.0.0.0");
    expect(changed.uuid).toBe(node.uuid);
    expect(changed.password).toBe(node.password);
    expect(changed.tls.serverName).toBe("apple.com");
    expect(changed.tls.reality.handshakeServer).toBe("apple.com");
    expect(changed.tls.reality.handshakePort).toBe(443);
    expect(deriveRealityPublicKey(changed.tls.reality.privateKey)).toBe(changed.tls.reality.publicKey);
    expect(() => validateNode(changed)).not.toThrow();
  });

  test("a saved Reality private key can restore a missing public key without rotating credentials", () => {
    const node = tunnelNode();
    const pair = generateRealityKeyPair();
    node.tls.reality.privateKey = pair.privateKey;
    node.tls.reality.publicKey = "";
    const changed = applySimpleTunnel(node, "none");
    expect(changed.tls.reality.privateKey).toBe(pair.privateKey);
    expect(changed.tls.reality.publicKey).toBe(pair.publicKey);
    expect(node.tls.reality.publicKey).toBe("");
  });

  test("closing a tunnel preserves a valid empty Reality short ID with the existing key pair", () => {
    const original = createSimpleNode("vless");
    original.tls.reality.shortId = "";
    expect(() => validateNode(original)).not.toThrow();
    const opened = applySimpleTunnel(original, "quick");
    const restored = applySimpleTunnel(opened, "none");
    expect(restored.tls.reality).toEqual(original.tls.reality);
    expect(restored.tls.reality.shortId).toBe("");
    expect(restored.uuid).toBe(original.uuid);
    expect(() => validateNode(restored)).not.toThrow();
  });

  test("VMess gets WS for a new tunnel and keeps WS when the tunnel closes", () => {
    const node = createDefaultNode("vmess");
    node.transport.type = "grpc";
    node.tls.mode = "tls";
    node.tls.serverName = "custom.example.com";
    node.tls.certificatePem = certificatePem;
    node.tls.keyPem = keyPem;
    node.transport.path = "/preserved-path";
    const changed = applySimpleTunnel(node, "quick");
    expect(changed.transport.type).toBe("ws");
    expect(changed.transport.path).toBe("/preserved-path");
    expect(changed.tls.mode).toBe("none");
    expect(changed.tls.certificatePem).toBe(certificatePem);
    expect(changed.uuid).toBe(node.uuid);
    expect(() => validateNode(changed)).not.toThrow();
    const closed = applySimpleTunnel(changed, "none");
    expect(closed.direct).toBe(true);
    expect(closed.listen).toBe("0.0.0.0");
    expect(closed.transport.type).toBe("ws");
    expect(closed.tls.mode).toBe("none");
    expect(closed.uuid).toBe(node.uuid);
    expect(() => validateNode(closed)).not.toThrow();
  });

  test.each(["0.0.0.0", "192.0.2.50", "127.0.0.1", "::", "2001:db8::50", "::1"])("adding a tunnel preserves the existing direct listener %s", listen => {
    const node = createSimpleNode("vless");
    node.listen = listen;
    const changed = applySimpleTunnel(node, "quick");
    expect(changed.listen).toBe(listen);
    expect(changed.direct).toBe(true);
    expect(node.listen).toBe(listen);
  });

  test.each(["0.0.0.0", "192.0.2.50", "::", "2001:db8::50"])("an explicitly tunnel-only draft with %s gets a loopback listener", listen => {
    const node = createSimpleNode("vless");
    node.direct = false;
    node.listen = listen;
    const changed = applySimpleTunnel(node, "quick");
    expect(changed.listen).toBe(listen.includes(":") ? "::1" : "127.0.0.1");
    expect(changed.direct).toBe(false);
    expect(() => validateNode(changed)).not.toThrow();
    expect(node.listen).toBe(listen);
  });

  test.each(["192.0.2.50", "2001:db8::50"])("closing a dual-entry tunnel preserves an intentional specific listener %s", listen => {
    const node = tunnelNode("vmess");
    node.direct = true;
    node.listen = listen;
    expect(applySimpleTunnel(node, "none").listen).toBe(listen);
  });

  test("new WS tunnel supplies a path only when an old TCP draft had none", () => {
    const node = createDefaultNode("vless");
    node.transport.path = "";
    const changed = applySimpleTunnel(node, "quick");
    expect(changed.transport.path).toBe("/nexus-ws");
    expect(() => validateNode(changed)).not.toThrow();
  });

  test("native protocols reject Cloudflare conversion without mutating the node", () => {
    for (const protocol of NODE_PROTOCOLS.filter(protocol => protocol !== "vless" && protocol !== "vmess")) {
      const node = createSimpleNode(protocol);
      const snapshot = structuredClone(node);
      expect(() => applySimpleTunnel(node, "quick")).toThrow(/VLESS \/ VMess/);
      expect(() => applySimpleTunnel(node, "fixed")).toThrow(/VLESS \/ VMess/);
      expect(node).toEqual(snapshot);
      expect(applySimpleTunnel(node, "none")).toEqual(snapshot);
    }
  });
});
