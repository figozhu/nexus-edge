import { expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import * as cp from "node:child_process";
import * as crypto from "node:crypto";
import { createPaths, createDefaultNode, defaultConfig, writeConfig, appArguments, getFirewallSettings, type NodeConfig } from "../src/core.ts";
import { getDaemonStatus, stopDaemonGracefully } from "../src/daemon.ts";
import { readTrafficReport, trafficDatabasePath } from "../src/traffic-store.ts";
import { NETWORK_RELEASES } from "../src/network.ts";
import { collectCoreTraffic, trafficRpc } from "../src/traffic-core.ts";

const binaries = { singBox: process.env.NEXUS_EDGE_SINGBOX_TEST_BINARY, xray: process.env.NEXUS_EDGE_XRAY_TEST_BINARY };
const enabled = process.env.NEXUS_EDGE_TEST_TRAFFIC === "1" && binaries.singBox && binaries.xray;
async function freePort(excluded: Set<number>): Promise<number> {
  for (;;) {
    const server = net.createServer(); await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const port = (server.address() as net.AddressInfo).port; await new Promise<void>(resolve => server.close(() => resolve()));
    if (!excluded.has(port)) { excluded.add(port); return port; }
  }
}
async function localRoundtrip(node: NodeConfig, target: number, size: number): Promise<net.Socket> {
  // Xray deliberately excludes 127.0.0.1 from its online map. A second loopback
  // address exercises real source attribution without using a network interface.
  const socket = net.createConnection({ host: "127.0.0.1", port: node.port, localAddress: node.protocol === "vless" ? "127.0.0.2" : "127.0.0.1" });
  let pending = Buffer.alloc(0), waiting: (() => void) | undefined, failure: Error | undefined;
  socket.on("data", (chunk: Buffer) => { pending = Buffer.concat([pending, chunk]); waiting?.(); });
  socket.on("error", error => { failure = error; waiting?.(); });
  const read = async (length: number) => {
    const deadline = Date.now() + 5000;
    while (pending.length < length) {
      if (failure || Date.now() > deadline) throw failure ?? new Error("Isolated proxy roundtrip timed out");
      await new Promise<void>(resolve => { const timer = setTimeout(resolve, 50); waiting = () => { clearTimeout(timer); resolve(); }; });
    }
    const result = pending.subarray(0, length); pending = pending.subarray(length); return result;
  };
  try {
    if (node.protocol === "socks") {
      socket.write(Buffer.from([5, 1, 2])); expect([...await read(2)]).toEqual([5, 2]);
      const username = Buffer.from(node.username), password = Buffer.from(node.password);
      socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password])); expect([...await read(2)]).toEqual([1, 0]);
      socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, target >> 8, target & 255]));
      const header = await read(4); expect(header[1]).toBe(0); await read(header[3] === 4 ? 18 : 6);
    } else {
      socket.write(Buffer.concat([Buffer.from([0]), Buffer.from(node.uuid.replaceAll("-", ""), "hex"), Buffer.from([0, 1, target >> 8, target & 255, 1, 127, 0, 0, 1])]));
    }
    const payload = crypto.randomBytes(size); socket.write(payload);
    if (node.protocol === "vless") expect([...await read(2)]).toEqual([0, 0]);
    expect(await read(size)).toEqual(payload);
    return socket;
  } catch (error) { socket.destroy(); throw error; }
}

(enabled ? test : test.skip)("real normal worker collects two Xray ports and sing-box, persists history and flushes on graceful stop/restart", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-traffic-worker-"));
  const original = path.resolve(process.env.NEXUS_EDGE_TRAFFIC_TEST_ENTRY ?? "nexus-edge.ts");
  const script = original.endsWith(".ts"), entry = path.join(root, script ? "nexus-edge.ts" : process.platform === "win32" ? "nexus-edge.exe" : "nexus-edge");
  fs.copyFileSync(original, entry); if (!script && process.platform !== "win32") fs.chmodSync(entry, 0o755);
  const paths = createPaths(entry, script ? process.execPath : entry), sockets: net.Socket[] = [], echoSockets = new Set<net.Socket>();
  const echo = net.createServer(socket => { echoSockets.add(socket); socket.on("close", () => echoSockets.delete(socket)); socket.pipe(socket); });
  let worker: cp.ChildProcess | undefined, closed: Promise<void> | undefined, output = "";
  const start = async () => {
    worker = cp.spawn(paths.runtime, appArguments(paths, ["--worker"]), { cwd: root, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    worker.stdout!.on("data", data => { output = (output + data).slice(-6000); }); worker.stderr!.on("data", data => { output = (output + data).slice(-6000); });
    closed = new Promise<void>(resolve => worker!.once("close", () => resolve()));
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) { if (worker.exitCode !== null) throw new Error("Fixture worker exited: " + output); if ((await getDaemonStatus(paths))?.phase === "ready") return; await Bun.sleep(100); }
    throw new Error("Fixture worker did not become ready: " + output);
  };
  try {
    const config = defaultConfig(), used = new Set<number>();
    config.firewall = { ...getFirewallSettings(config), mode: "manual" };
    for (const [protocol, name] of [["vless", "synthetic port A"], ["vless", "synthetic port B"], ["socks", "synthetic sing-box"]] as const) {
      const node = createDefaultNode(protocol); node.name = name; node.listen = "127.0.0.1"; node.address = "127.0.0.1"; node.port = await freePort(used); node.publicPort = node.port; config.nodes.push(node);
    }
    writeConfig(paths, config); const originalConfig = fs.readFileSync(paths.config);
    for (const engine of ["xray", "singBox"] as const) {
      const source = binaries[engine]!, asset = NETWORK_RELEASES[engine].assets[`${process.platform}-${process.arch}`]!;
      expect(crypto.createHash("sha256").update(fs.readFileSync(source)).digest("hex")).toBe(asset.files[asset.executable]!);
      fs.cpSync(path.dirname(source), path.join(paths.bin, `${engine}-${NETWORK_RELEASES[engine].version}-${process.platform}-${process.arch}`), { recursive: true });
    }
    await new Promise<void>(resolve => echo.listen(0, "127.0.0.1", resolve)); const target = (echo.address() as net.AddressInfo).port;
    await start();
    for (let i = 0; i < config.nodes.length; i++) sockets.push(await localRoundtrip(config.nodes[i]!, target, (i + 1) * 16384));
    const deadline = Date.now() + 15000;
    let report = readTrafficReport(paths);
    while (Date.now() < deadline && report.nodes.filter(n => n.up > 0 && n.down > 0).length < 3) { await Bun.sleep(100); report = readTrafficReport(paths); }
    expect(report.nodes).toHaveLength(3);
    for (let i = 0; i < config.nodes.length; i++) {
      const row = report.nodes.find(n => n.nodeId === config.nodes[i]!.id); expect(row.port).toBe(config.nodes[i]!.port); expect(row.up).toBeGreaterThan(0); expect(row.down).toBeGreaterThan(0);
    }
    expect(report.peers.some(p => p.engine === "xray" && p.ip === "127.0.0.2" && p.quality === "presence")).toBe(true);
    expect(report.peers.some(p => p.engine === "singBox" && p.ip === "127.0.0.1" && p.up >= 49152)).toBe(true);
    for (const socket of sockets.splice(0)) socket.destroy();
    const drainDeadline = Date.now() + 3000;
    while (echoSockets.size && Date.now() < drainDeadline) await Bun.sleep(25);
    const run = fs.readdirSync(paths.data).find(name => name.startsWith("run-"))!;
    const generated = JSON.parse(fs.readFileSync(path.join(paths.data, run, "xray.json"), "utf8"));
    const api = generated.inbounds.find((inbound: any) => inbound.tag === "nexus-traffic");
    const endpoint = { port: api.port, secret: api.settings.accounts[0].pass };
    await expect(trafficRpc({ ...endpoint, secret: "0".repeat(64) }, "/xray.app.stats.command.StatsService/QueryStats")).rejects.toThrow("认证失败");
    const direct = await collectCoreTraffic("xray", endpoint, config.nodes.slice(0, 2));
    for (let i = 0; i < direct.nodes.length; i++) expect(direct.nodes[i]).toMatchObject({ up: (i + 1) * 16384, down: (i + 1) * 16384 });
    await stopDaemonGracefully(paths); await closed;
    expect(fs.readFileSync(paths.config)).toEqual(originalConfig);
    const settled = readTrafficReport(paths);
    for (let i = 0; i < config.nodes.length; i++) {
      const row = settled.nodes.find(n => n.nodeId === config.nodes[i]!.id);
      expect(row.up).toBeGreaterThanOrEqual((i + 1) * 16384); expect(row.down).toBeGreaterThanOrEqual((i + 1) * 16384);
    }
    expect(settled.status.every(s => s.state === "stopped")).toBe(true);
    const before = settled.cores.find(c => c.engine === "xray").up;
    await start(); sockets.push(await localRoundtrip(config.nodes[0]!, target, 8192));
    for (const socket of sockets.splice(0)) socket.destroy();
    await Bun.sleep(100);
    await stopDaemonGracefully(paths); await closed;
    const after = readTrafficReport(paths); expect(after.cores.find(c => c.engine === "xray").up).toBeGreaterThanOrEqual(before + 8192);
    expect(after.events.filter(e => e.code === "generation").length).toBeGreaterThanOrEqual(4);
    expect(fs.readFileSync(paths.config)).toEqual(originalConfig);
    expect(fs.existsSync(paths.runtimeState)).toBe(false);
    // A statistics storage failure must neither replace the file nor prevent
    // normal proxy service from starting and stopping through the real entry.
    fs.writeFileSync(trafficDatabasePath(paths), "synthetic damaged statistics");
    await start(); sockets.push(await localRoundtrip(config.nodes[0]!, target, 1024));
    for (const socket of sockets.splice(0)) socket.destroy();
    await stopDaemonGracefully(paths); await closed;
    expect(fs.readFileSync(trafficDatabasePath(paths), "utf8")).toBe("synthetic damaged statistics");
    expect(fs.readFileSync(paths.config)).toEqual(originalConfig);
  } finally {
    for (const socket of sockets) socket.destroy();
    if (worker && worker.exitCode === null) { try { await stopDaemonGracefully(paths); } catch { worker.kill("SIGTERM"); } await closed; }
    for (const socket of echoSockets) socket.destroy(); if (echo.listening) await new Promise<void>(resolve => echo.close(() => resolve()));
    fs.rmSync(root, { recursive: true, force: true });
  }
}, 60000);
