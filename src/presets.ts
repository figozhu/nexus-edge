import { randomBytes as presetRandomBytes } from "node:crypto";
import { isIP as presetIsIP } from "node:net";
import { type NodeConfig, type NodeProtocol, createDefaultNode, deriveRealityPublicKey, generateRealityKeyPair } from "./core.ts";

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
