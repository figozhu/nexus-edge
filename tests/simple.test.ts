import { afterEach, describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { createServer, type Server } from "node:net";
import { type PublicAddressResult } from "../src/address.ts";
import { type AppConfig, type DaemonStatus, type NodeConfig, configFingerprint, defaultConfig, runtimeConfigFingerprint } from "../src/core.ts";
import { panelRuntimeMatches } from "../src/panel.ts";
import { createSimpleNode } from "../src/presets.ts";
import { applyDetectedAddress, directListenerNotice, findAvailableNodePort, normalizeClientAddress } from "../src/simple.ts";

const ipv4 = "1.1.1.1";
const ipv6 = "2606:4700:4700::1111";

function detected(v4: string | null = ipv4, v6: string | null = ipv6, cancelled = false): PublicAddressResult {
  return { ipv4: v4, ipv6: v6, preferredAddress: cancelled ? null : v4 || v6,
    source: { ipv4: v4 ? "test:ipv4" : null, ipv6: v6 ? "test:ipv6" : null }, warnings: [], cancelled,
    checkedAt: "2026-10-21T00:00:00.000Z" };
}

describe("simple connection addresses", () => {
  test("a new draft prefers detected IPv4 and selects the IPv4 wildcard listener", () => {
    const node = createSimpleNode("vless");
    node.listen = "::";
    const before = structuredClone(node);
    const applied = applyDetectedAddress(node, detected(), true);
    expect(applied.node).toEqual({ ...before, address: ipv4, listen: "0.0.0.0" });
    expect(node).toEqual(before);
    expect(applied.notice).toContain("IPv4");
  });

  test("an IPv6-only new draft uses IPv6 for both the connection address and wildcard listener", () => {
    const node = createSimpleNode("vless");
    const before = structuredClone(node);
    const applied = applyDetectedAddress(node, detected(null, ipv6), true);
    expect(applied.node).toEqual({ ...before, address: ipv6, listen: "::" });
    expect(node).toEqual(before);
    expect(applied.notice).toContain("IPv6");
    expect(applied.notice).toContain("客户端所在网络");
  });

  for (const [listen, expected] of [["0.0.0.0", ipv4], ["192.0.2.10", ipv4], ["127.0.0.1", ipv4],
    ["::", ipv6], ["2001:db8::10", ipv6], ["::1", ipv6]] as const) {
    test(`explicit redetection preserves the existing ${listen} listener, mapped port, UUID and SNI`, () => {
      const node = createSimpleNode("vless");
      node.listen = listen;
      node.address = "old.example.com";
      node.port = 12345;
      node.publicPort = 443;
      node.tls.serverName = "reality.example.com";
      node.tls.reality.handshakeServer = "reality.example.com";
      const before = structuredClone(node);
      const applied = applyDetectedAddress(node, detected());
      expect(applied.node).toEqual({ ...before, address: expected });
      expect(node).toEqual(before);
    });
  }

  test("IPv6-only detection does not rewrite an existing IPv4 listener or its current connection address", () => {
    const node = createSimpleNode("vmess");
    node.address = "manual.example.com";
    const applied = applyDetectedAddress(node, detected(null, ipv6));
    expect(applied.node).toEqual(node);
    expect(applied.notice).toContain("当前节点监听 IPv4");
  });

  test("an existing specific IPv6 listener does not adopt an IPv4-only result", () => {
    const node = createSimpleNode("vless");
    node.listen = "2001:db8::10";
    node.address = "manual.example.com";
    expect(applyDetectedAddress(node, detected(ipv4, null)).node).toEqual(node);
    node.listen = "::";
    expect(applyDetectedAddress(node, detected(ipv4, null)).node).toEqual({ ...node, address: ipv4 });
  });

  test("failed or cancelled detection keeps the whole draft, even when cancellation includes partial results", () => {
    const node = createSimpleNode("vless");
    node.address = "manual.example.com";
    node.listen = "::";
    expect(applyDetectedAddress(node, detected(null, null), true).node).toEqual(node);
    const cancelled = applyDetectedAddress(node, detected(ipv4, ipv6, true), true);
    expect(cancelled.node).toEqual(node);
    expect(cancelled.node).not.toBe(node);
    expect(cancelled.notice).toContain("取消");
  });

  test("a manually selected listener on a new draft remains an explicit choice", () => {
    const node = createSimpleNode("vmess");
    node.listen = "192.0.2.10";
    expect(applyDetectedAddress(node, detected(), true).node.listen).toBe(node.listen);
  });

  test("the WARP observation remains visible without replacing the detected address", () => {
    const node = createSimpleNode("vless");
    const result = detected(ipv4, null);
    result.warnings = ["检测结果标记为 WARP 出口，请核对实际服务器地址。"];
    const applied = applyDetectedAddress(node, result, true);
    expect(applied.node.address).toBe(ipv4);
    expect(applied.notice).toContain("WARP");
  });

  test("manual client addresses reject wildcard listeners but accept domains, IPv6 and LAN addresses", () => {
    for (const value of ["", "0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"]) {
      expect(() => normalizeClientAddress(value)).toThrow();
    }
    expect(normalizeClientAddress("Node.Example.COM")).toBe("node.example.com");
    expect(normalizeClientAddress(`[${ipv6}]`)).toBe(ipv6);
    expect(normalizeClientAddress("192.168.10.20")).toBe("192.168.10.20");
    expect(() => normalizeClientAddress("https://node.example.com/path")).toThrow();
    expect(() => normalizeClientAddress("fe80::1%eth0")).toThrow();
  });

  test("listener notices identify IPv6 and loopback mismatches without treating a tunnel-only node as direct", () => {
    const node = createSimpleNode("vless");
    node.address = ipv6;
    expect(directListenerNotice(node)).toContain("本机却只监听 IPv4");
    node.listen = "127.0.0.1";
    expect(directListenerNotice(node)).toContain("只接收本机连接");
    node.listen = "::1";
    expect(directListenerNotice(node)).toContain("只接收本机连接");
    node.address = ipv4;
    node.listen = "2001:db8::10";
    expect(directListenerNotice(node)).toContain("只监听指定 IPv6");
    node.listen = "::";
    expect(directListenerNotice(node)).toBe("");
    node.listen = "127.0.0.1";
    node.address = "localhost";
    expect(directListenerNotice(node)).toBe("");
    node.address = ipv4;
    node.direct = false;
    expect(directListenerNotice(node)).toBe("");
    node.direct = true;
    node.address = "";
    expect(directListenerNotice(node)).toBe("");
  });
});

function runtimeConfig(): AppConfig {
  const node = createSimpleNode("vmess");
  node.address = "node.example.com";
  return { ...defaultConfig(), nodes: [node] };
}

function runtimeStatus(config: AppConfig, includeRuntimeHash = true): DaemonStatus {
  return { instanceId: "simple-test-instance", pid: 1234, startedAt: "2026-10-21T00:00:00.000Z",
    phase: "ready", configHash: configFingerprint(config),
    ...(includeRuntimeHash ? { runtimeConfigHash: runtimeConfigFingerprint(config) } : {}),
    cores: {}, nodes: [], links: [], lastError: null };
}

describe("panel running configuration matching", () => {
  test("an absent daemon never matches, and an old daemon must match the full configuration", () => {
    const config = runtimeConfig();
    const oldStatus = runtimeStatus(config, false);
    expect(panelRuntimeMatches(null, config)).toBe(false);
    expect(panelRuntimeMatches(oldStatus, config)).toBe(true);
    const changed = structuredClone(config);
    changed.nodes[0]!.address = ipv4;
    expect(panelRuntimeMatches(oldStatus, changed)).toBe(false);
    changed.nodes[0]!.address = config.nodes[0]!.address;
    changed.nodes[0]!.publicPort = 443;
    expect(panelRuntimeMatches(oldStatus, changed)).toBe(false);
  });

  test("a new daemon still matches after only the client address and NAT port change", () => {
    const config = runtimeConfig();
    const status = runtimeStatus(config);
    const changed = structuredClone(config);
    changed.nodes[0]!.address = ipv4;
    changed.nodes[0]!.publicPort = 443;
    const before = structuredClone(changed);
    expect(status.configHash).not.toBe(configFingerprint(changed));
    expect(panelRuntimeMatches(status, changed)).toBe(true);
    expect(changed).toEqual(before);
  });

  for (const field of ["uuid", "path"] as const) {
    test(`a changed ${field} is not treated as client metadata for either daemon generation`, () => {
      const config = runtimeConfig();
      const changed = structuredClone(config);
      changed.nodes[0]!.address = ipv4;
      if (field === "uuid") changed.nodes[0]!.uuid = randomUUID();
      else changed.nodes[0]!.transport.path = "/changed-server-path";
      expect(panelRuntimeMatches(runtimeStatus(config), changed)).toBe(false);
      expect(panelRuntimeMatches(runtimeStatus(config, false), changed)).toBe(false);
    });
  }

  test("a present but different runtime hash never falls back to a matching full hash", () => {
    const config = runtimeConfig();
    const status = runtimeStatus(config);
    status.runtimeConfigHash = "0".repeat(64);
    expect(status.configHash).toBe(configFingerprint(config));
    expect(panelRuntimeMatches(status, config)).toBe(false);
  });
});

interface TcpReservation { port: number; server: Server; close: () => Promise<void> }
interface UdpReservation { port: number; socket: Socket; close: () => Promise<void> }
const socketCleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of socketCleanups.splice(0).reverse()) await cleanup(); });

function reserveTcp(port = 0): Promise<TcpReservation> {
  const server = createServer();
  const close = () => new Promise<void>(resolve => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
  });
  socketCleanups.push(close);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("TCP test socket has no IP endpoint"));
      resolve({ port: address.port, server, close });
    });
  });
}

function reserveUdp(port = 0): Promise<UdpReservation> {
  const socket = createSocket("udp4");
  const close = () => new Promise<void>(resolve => { try { socket.close(() => resolve()); } catch { resolve(); } });
  socketCleanups.push(close);
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind({ address: "127.0.0.1", port, exclusive: true }, () => resolve({ port: socket.address().port, socket, close }));
  });
}

async function withRoomToScan<T extends { port: number; close: () => Promise<void> }>(reserve: () => Promise<T>): Promise<T> {
  // Windows can choose ephemeral ports up to 65535. Leave room above the occupied
  // port without assuming that the host's next numeric port is otherwise unused.
  for (let attempt = 0; attempt < 8; attempt++) {
    const reservation = await reserve();
    if (reservation.port <= 65407) return reservation;
    await reservation.close();
  }
  throw new Error("Could not reserve a loopback test port with room to scan");
}

describe("simple port allocation with real loopback listeners", () => {
  test("skips a TCP port owned by another application and leaves that listener running", async () => {
    const occupied = await withRoomToScan(reserveTcp);
    const node = createSimpleNode("vmess");
    node.listen = "127.0.0.1";
    node.port = occupied.port;
    const before = structuredClone(node);
    const selected = await findAvailableNodePort(node, []);
    expect(selected).toBeGreaterThan(occupied.port);
    expect(selected).toBeLessThanOrEqual(occupied.port + 127);
    expect(occupied.server.listening).toBe(true);
    const usable = await reserveTcp(selected);
    expect(usable.port).toBe(selected);
    expect(node).toEqual(before);
  });

  test("skips an occupied UDP port for a native UDP protocol", async () => {
    const occupied = await withRoomToScan(reserveUdp);
    const node = createSimpleNode("hysteria2");
    node.listen = "127.0.0.1";
    node.port = occupied.port;
    const selected = await findAvailableNodePort(node, []);
    expect(selected).toBeGreaterThan(occupied.port);
    expect(selected).toBeLessThanOrEqual(occupied.port + 127);
    expect(occupied.socket.address().port).toBe(occupied.port);
    const usable = await reserveUdp(selected);
    expect(usable.port).toBe(selected);
  });

  test("Shadowsocks rejects an otherwise free TCP port when UDP at that port is occupied", async () => {
    const occupied = await withRoomToScan(reserveUdp);
    const tcpAtSamePort = await reserveTcp(occupied.port);
    await tcpAtSamePort.close();
    const node = createSimpleNode("shadowsocks");
    node.listen = "127.0.0.1";
    node.port = occupied.port;
    const selected = await findAvailableNodePort(node, []);
    expect(selected).toBeGreaterThan(occupied.port);
    const tcp = await reserveTcp(selected);
    const udp = await reserveUdp(selected);
    expect(tcp.port).toBe(udp.port);
    expect(occupied.socket.address().port).toBe(occupied.port);
  });
});
