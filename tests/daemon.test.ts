import { afterEach, describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, connect } from "node:net";
import { createSocket } from "node:dgram";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
  type AppConfig, type AppPaths, type DaemonStatus, type RuntimeRecord,
  type NodeConfig, type NodeProtocol, type NodeRuntimeStatus,
  atomicWrite, configFingerprint, createPaths, createDefaultNode, defaultConfig, writeConfig,
} from "../src/core.ts";
import {
  InstanceBusyError, acquireDaemonLock, getDaemonStatus, readRuntimeRecord,
  startDetachedDaemon, stopDaemonGracefully,
} from "../src/daemon.ts";
import { certificatePem, keyPem } from "./fixtures/tls.ts";

const ENTRY = join(import.meta.dir, "fixtures", "daemon-entry.ts");
interface MockEvent { role: string; kind: string; pid: number; args: string[]; at: number }
interface Environment {
  root: string; paths: AppPaths; config: AppConfig; workers: ChildProcess[]; errors: string;
}
interface NodeOptions {
  protocol?: NodeProtocol; tunnel?: NodeConfig["tunnel"]["mode"];
  direct?: boolean; enabled?: boolean; address?: string; listen?: string;
}
const environments: Environment[] = [];
const extraChildren: ChildProcess[] = [];

async function until<T>(read: () => T | Promise<T>, accepted: (value: T) => boolean, timeoutMs = 6000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let value: T;
  do {
    value = await read();
    if (accepted(value)) return value;
    await Bun.sleep(25);
  } while (Date.now() < deadline);
  throw new Error("Timed out waiting for test condition; last value=" + JSON.stringify(value!));
}

async function freePort(host = "127.0.0.1"): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("No test listener address"));
      server.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}

async function addNode(env: Environment, options: NodeOptions = {}): Promise<NodeConfig> {
  const node = createDefaultNode(options.protocol ?? "vless", env.config.nodes);
  node.listen = options.listen ?? "127.0.0.1";
  do { node.port = await freePort(node.listen); }
  while (env.config.nodes.some(existing => existing.port === node.port));
  node.publicPort = node.port;
  node.address = options.address ?? "127.0.0.1";
  node.enabled = options.enabled ?? true;
  node.tunnel.mode = options.tunnel ?? "none";
  node.direct = options.direct ?? node.tunnel.mode === "none";
  if (node.tunnel.mode !== "none") node.transport.type = "ws";
  if (node.tunnel.mode === "fixed") {
    node.tunnel.token = "test_TunnelToken_abcdefghijklmnop123456";
    node.tunnel.domain = "node.example.com";
  }
  if (node.tls.mode === "tls") {
    node.tls.certificatePem = certificatePem;
    node.tls.keyPem = keyPem;
    node.tls.serverName = "node.example.com";
    node.tls.insecure = true;
  }
  env.config.nodes.push(node);
  writeConfig(env.paths, env.config);
  return node;
}

async function environment(options: NodeOptions = {}): Promise<Environment> {
  const root = mkdtempSync(join(tmpdir(), "nexus-edge-daemon-test-"));
  const paths = { ...createPaths(join(root, "nexus-edge.ts"), process.execPath), entry: ENTRY };
  const env: Environment = { root, paths, config: defaultConfig(), workers: [], errors: "" };
  environments.push(env);
  await addNode(env, options);
  return env;
}

function startWorker(env: Environment): ChildProcess {
  const child = spawn(process.execPath, [ENTRY, "--fixture-worker", env.root], {
    cwd: env.root, shell: false, windowsHide: true, stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr?.on("data", chunk => { env.errors = (env.errors + chunk.toString()).slice(-16000); });
  env.workers.push(child);
  return child;
}

test("firewall diagnostics use the installation scope and remain separate from local listener readiness", async () => {
  const env = await environment({ protocol: "shadowsocks" });
  writeFileSync(join(env.root, "firewall-fixture.json"), "{}");
  startWorker(env);
  const status = await until(() => getDaemonStatus(env.paths), current => current?.phase === "ready");
  expect(status!.firewall).toEqual({ status: "blocked", backend: "windows", detail: "Synthetic blocked firewall", warnings: ["Synthetic policy warning"] });
  const observed = JSON.parse(readFileSync(join(env.root, "firewall-observed.jsonl"), "utf8"));
  expect(observed).toEqual({ root: env.paths.root, data: env.paths.data });
  expect(status!.nodes[0]!.listenerReady).toBe(true);
  expect(readFileSync(env.paths.log, "utf8")).toContain("Synthetic policy warning");
});

test("an unexpected firewall backend failure is logged while the local core still becomes ready", async () => {
  const env = await environment({ protocol: "shadowsocks" });
  writeFileSync(join(env.root, "firewall-fixture.json"), JSON.stringify({ throw: true }));
  startWorker(env);
  const status = await until(() => getDaemonStatus(env.paths), current => current?.phase === "ready");
  expect(status!.firewall?.status).toBe("error");
  expect(status!.firewall?.detail).toContain("Synthetic firewall exception");
  expect(status!.nodes[0]!.listenerReady).toBe(true);
});

function events(env: Environment): MockEvent[] {
  const filename = join(env.root, "events.jsonl");
  if (!existsSync(filename)) return [];
  return readFileSync(filename, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
}

function nodeState(status: DaemonStatus, node: NodeConfig): NodeRuntimeStatus {
  return status.nodes.find(value => value.id === node.id)!;
}

function nodeFile(env: Environment, node: NodeConfig, kind: "ready" | "domain" | "no-listen" | "no-udp" | "ready-delay"): string {
  return join(env.root, kind + "-" + node.id + (kind === "ready" ? ".status" : kind === "domain" ? ".txt" : ""));
}

function crash(env: Environment, role: string): void {
  writeFileSync(join(env.root, "crash-" + role.replaceAll(":", "_")), "1");
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

async function status(env: Environment, phase: DaemonStatus["phase"] = "ready"): Promise<DaemonStatus> {
  try {
    return await until(() => getDaemonStatus(env.paths, 500), value => value?.phase === phase) as DaemonStatus;
  } catch (error) { throw new Error(String(error) + "\nFixture stderr: " + env.errors); }
}

async function exited(child: ChildProcess, timeoutMs = 9000): Promise<void> {
  await until(() => child.exitCode !== null || child.signalCode !== null, Boolean, timeoutMs);
}

async function localPost(port: number, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, path: "/stop", method: "POST", headers, agent: false }, response => {
      response.resume();
      response.once("end", () => resolve(response.statusCode!));
    });
    req.once("error", reject);
    req.setTimeout(1000, () => req.destroy(new Error("Test control timeout")));
    req.end();
  });
}

afterEach(async () => {
  for (const env of environments.splice(0)) {
    try { await stopDaemonGracefully(env.paths, 5000); } catch { /* Owned process handles are the fallback. */ }
    for (const child of env.workers) {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    }
    for (const child of env.workers) {
      try { await exited(child); }
      catch { child.kill("SIGKILL"); await exited(child).catch(() => {}); }
    }
    const mockPids = [...new Set(events(env).map(event => event.pid))];
    await until(() => mockPids.every(pid => !alive(pid)), Boolean, 9000);
    rmSync(env.root, { recursive: true, force: true });
  }
  for (const child of extraChildren.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    await exited(child).catch(() => { child.kill("SIGKILL"); });
  }
});

describe("local multi-node daemon acceptance", () => {
  test("runs VLESS, VMess and Shadowsocks together without any tunnel process", async () => {
    const env = await environment();
    await addNode(env, { protocol: "vmess" });
    const ss = await addNode(env, { protocol: "shadowsocks" });
    startWorker(env);
    const ready = await status(env);
    expect(ready.cores.xray?.state).toBe("running");
    expect(ready.cores.singBox?.state).toBe("running");
    expect(ready.nodes).toHaveLength(3);
    expect(ready.nodes.every(node => node.directReady && !node.tunnelReady && node.tunnelState === "disabled")).toBe(true);
    expect(nodeState(ready, ss).listenerCheck).toBe("tcp+udp");
    expect(ready.links.map(link => link.uri?.split(":")[0]).sort()).toEqual(["ss", "vless", "vmess"]);
    expect(readFileSync(env.paths.link, "utf8").trim().split("\n")).toHaveLength(3);
    expect(events(env).filter(event => event.kind === "start").map(event => event.role).sort()).toEqual(["singBox", "xray"]);
    expect(readdirSync(env.paths.bin)).toHaveLength(0);
  }, 12000);

  test("keeps a listening node ready when its public address is empty without inventing a URI", async () => {
    const env = await environment({ address: "" });
    startWorker(env);
    const ready = await status(env);
    expect(ready.nodes[0]!.listenerReady).toBe(true);
    expect(ready.nodes[0]!.directReady).toBe(true);
    expect(ready.links).toHaveLength(1);
    expect(ready.links[0]!.uri).toBeNull();
    expect(ready.links[0]!.error).toBeTruthy();
    expect(existsSync(env.paths.link)).toBe(false);
    expect(events(env).filter(event => event.kind === "start")).toHaveLength(1);
  }, 12000);

  test("does not allocate a second core or tunnel for a disabled node", async () => {
    const env = await environment();
    const disabled = await addNode(env, { protocol: "vmess", tunnel: "quick", enabled: false });
    disabled.port = env.config.nodes[0]!.port;
    writeConfig(env.paths, env.config);
    startWorker(env);
    const ready = await status(env);
    expect(nodeState(ready, disabled).phase).toBe("disabled");
    expect(nodeState(ready, disabled).tunnelState).toBe("disabled");
    expect(ready.cores.singBox).toBeUndefined();
    expect(ready.links).toHaveLength(1);
    expect(events(env).filter(event => event.kind === "start").map(event => event.role)).toEqual(["xray"]);
  }, 12000);

  test("reports UDP listener evidence separately and does not require a TCP port for Hysteria2", async () => {
    const env = await environment({ protocol: "hysteria2" });
    startWorker(env);
    const ready = await status(env);
    expect(ready.nodes[0]!.listenerCheck).toBe("udp");
    expect(ready.nodes[0]!.detail).toContain("UDP 端口占用");
    expect(ready.nodes[0]!.detail).toContain("尚未验证");
    expect(readFileSync(env.paths.log, "utf8")).not.toContain(keyPem.split("\n")[1]!);
    expect(ready.links[0]!.uri).toMatch(/^(hysteria2|hy2):\/\//);
    const tcpConnects = await new Promise<boolean>(resolve => {
      const socket = connect({ host: "127.0.0.1", port: env.config.nodes[0]!.port });
      socket.once("connect", () => { socket.destroy(); resolve(true); });
      socket.once("error", () => resolve(false));
    });
    expect(tcpConnects).toBe(false);
    expect(ready.cores.xray).toBeUndefined();
  }, 12000);

  test("requires both TCP and UDP listeners for a Shadowsocks node", async () => {
    const env = await environment({ protocol: "shadowsocks" });
    const node = env.config.nodes[0]!;
    writeFileSync(nodeFile(env, node, "no-udp"), "1");
    startWorker(env);
    await until(() => getDaemonStatus(env.paths), value => value?.cores.singBox?.state === "running");
    await Bun.sleep(250);
    const pending = (await getDaemonStatus(env.paths))!;
    expect(pending.nodes[0]!.listenerReady).toBe(false);
    expect(pending.phase).not.toBe("ready");
    expect(pending.links).toHaveLength(0);
    rmSync(nodeFile(env, node, "no-udp"));
    crash(env, "singBox");
    expect((await status(env)).nodes[0]!.listenerReady).toBe(true);
  }, 12000);

  test("exposes a ready JSON-only node as an exportable route without fabricating a share URI", async () => {
    const env = await environment({ protocol: "naive" });
    startWorker(env);
    const ready = await status(env);
    expect(ready.links).toHaveLength(1);
    expect(ready.links[0]!.format).toBe("json");
    expect(ready.links[0]!.uri).toBeNull();
    expect(ready.links[0]!.error).toBeUndefined();
    expect(existsSync(env.paths.link)).toBe(false);
  }, 12000);

  test("requires healthy origin and tunnel plus a complete Quick Tunnel hostname before export", async () => {
    const env = await environment({ tunnel: "quick" });
    const node = env.config.nodes[0]!;
    writeFileSync(nodeFile(env, node, "ready"), "503");
    startWorker(env);
    await until(() => events(env).filter(event => event.kind === "start").length, count => count === 2);
    await Bun.sleep(200);
    const pending = (await getDaemonStatus(env.paths))!;
    expect(pending.phase).not.toBe("ready");
    expect(pending.links).toHaveLength(0);
    expect(existsSync(env.paths.link)).toBe(false);
    writeFileSync(nodeFile(env, node, "ready"), "200");
    const ready = await status(env);
    const current = nodeState(ready, node);
    expect(current.domain).toBe("quiet-river.trycloudflare.com");
    expect(current.tunnelReady).toBe(true);
    expect(current.directReady).toBe(false);
    expect(ready.cores.xray?.state).toBe("running");
    expect(readFileSync(env.paths.link, "utf8").trim()).toBe(current.links[0]!.uri!);
    expect(new URL(current.links[0]!.uri!).searchParams.get("sni")).toBe(current.domain!);
  }, 12000);

  test("does not claim a fixed tunnel is ready only because its domain is configured and redacts node credentials", async () => {
    const env = await environment({ tunnel: "fixed" });
    const node = env.config.nodes[0]!;
    writeFileSync(nodeFile(env, node, "ready"), "503");
    startWorker(env);
    await until(() => getDaemonStatus(env.paths), value => value?.nodes[0]?.tunnelState === "running");
    await Bun.sleep(250);
    const pending = (await getDaemonStatus(env.paths))!;
    expect(pending.nodes[0]!.domain).toBe("node.example.com");
    expect(pending.phase).not.toBe("ready");
    expect(pending.links).toHaveLength(0);
    expect(existsSync(env.paths.link)).toBe(false);
    writeFileSync(nodeFile(env, node, "ready"), "200");
    expect((await status(env)).links[0]!.uri).toContain("@node.example.com:443");
    const log = readFileSync(env.paths.log, "utf8");
    expect(log).not.toContain(node.tunnel.token);
    expect(log).not.toContain(node.uuid);
    expect(log).not.toContain(node.password);
    expect(log).toContain("[REDACTED]");
  }, 12000);

  test("keeps a live but non-listening origin out of ready state", async () => {
    const env = await environment({ tunnel: "fixed" });
    writeFileSync(nodeFile(env, env.config.nodes[0]!, "no-listen"), "1");
    startWorker(env);
    await until(() => getDaemonStatus(env.paths), value => value?.nodes[0]?.tunnelState === "running" && value?.cores.xray?.state === "running");
    await Bun.sleep(200);
    const pending = (await getDaemonStatus(env.paths))!;
    expect(pending.nodes[0]!.listenerReady).toBe(false);
    expect(pending.nodes[0]!.tunnelReady).toBe(false);
    expect(pending.phase).not.toBe("ready");
    expect(pending.links).toHaveLength(0);
    expect(existsSync(env.paths.link)).toBe(false);
  }, 12000);

  test("keeps direct and other node routes available when one of two independent tunnels fails", async () => {
    const env = await environment({ tunnel: "quick", direct: true });
    const first = env.config.nodes[0]!;
    const second = await addNode(env, { protocol: "vmess", tunnel: "quick" });
    const third = await addNode(env, { protocol: "shadowsocks" });
    writeFileSync(nodeFile(env, first, "domain"), "first-river.trycloudflare.com");
    writeFileSync(nodeFile(env, second, "domain"), "second-river.trycloudflare.com");
    startWorker(env);
    const ready = await status(env);
    expect(ready.links).toHaveLength(4);
    const tunnelEvents = events(env).filter(event => event.kind === "start" && event.role.startsWith("cloudflared:"));
    const metrics = tunnelEvents.map(event => event.args[event.args.indexOf("--metrics") + 1]!);
    expect(tunnelEvents).toHaveLength(2);
    expect(new Set(metrics).size).toBe(2);
    expect(metrics.every(value => value.startsWith("127.0.0.1:"))).toBe(true);
    writeFileSync(nodeFile(env, first, "ready"), "503");
    const degraded = await until(() => getDaemonStatus(env.paths), value => value?.phase === "degraded" && nodeState(value, first).tunnelReady === false);
    expect(nodeState(degraded!, first).directReady).toBe(true);
    expect(nodeState(degraded!, first).links.map(link => link.via)).toEqual(["direct"]);
    expect(nodeState(degraded!, second).tunnelReady).toBe(true);
    expect(nodeState(degraded!, third).directReady).toBe(true);
    expect(degraded!.links).toHaveLength(3);
    expect(readFileSync(env.paths.link, "utf8")).not.toContain("first-river");
    const secondLink = nodeState(degraded!, second).links[0]!.uri!;
    expect(readFileSync(env.paths.link, "utf8")).toContain(secondLink);
    expect(JSON.parse(Buffer.from(secondLink.slice("vmess://".length), "base64").toString("utf8")).add).toBe("second-river.trycloudflare.com");
    writeFileSync(nodeFile(env, first, "ready"), "200");
    expect((await status(env)).links).toHaveLength(4);
  }, 14000);

  test("invalidates a failed tunnel route then restores it after health recovers", async () => {
    const env = await environment({ tunnel: "quick" });
    const node = env.config.nodes[0]!;
    startWorker(env);
    await status(env);
    writeFileSync(nodeFile(env, node, "ready"), "503");
    await until(() => getDaemonStatus(env.paths), value => value !== null && value.links.length === 0);
    expect(existsSync(env.paths.link)).toBe(false);
    writeFileSync(nodeFile(env, node, "ready"), "200");
    expect((await status(env)).links).toHaveLength(1);
  }, 12000);

  test("recovers a crashed tunnel with a new hostname without restarting other tunnels", async () => {
    const env = await environment({ tunnel: "quick" });
    const node = env.config.nodes[0]!;
    const other = await addNode(env, { tunnel: "fixed" });
    startWorker(env);
    await status(env);
    writeFileSync(nodeFile(env, node, "domain"), "new-river.trycloudflare.com");
    crash(env, "cloudflared:" + node.id);
    const recovered = await until(() => getDaemonStatus(env.paths), value => value?.phase === "ready" && nodeState(value, node).domain === "new-river.trycloudflare.com");
    expect(nodeState(recovered!, node).tunnelRestarts).toBeGreaterThanOrEqual(1);
    expect(nodeState(recovered!, other).tunnelRestarts).toBe(0);
    expect(readFileSync(env.paths.link, "utf8")).not.toContain("quiet-river");
    expect(readFileSync(env.paths.link, "utf8")).toContain("new-river");
  }, 14000);

  test("keeps sing-box nodes ready after an Xray crash and does not revive stale direct links during a tunnel probe", async () => {
    const env = await environment({ tunnel: "quick", direct: true });
    const xray = env.config.nodes[0]!;
    const sing = await addNode(env, { protocol: "vmess" });
    startWorker(env);
    await status(env);
    writeFileSync(nodeFile(env, xray, "ready-delay"), "350");
    await Bun.sleep(100);
    writeFileSync(nodeFile(env, xray, "no-listen"), "1");
    crash(env, "xray");
    await until(() => events(env).filter(event => event.kind === "start" && event.role === "xray").length, count => count >= 2);
    await Bun.sleep(550);
    const degraded = (await getDaemonStatus(env.paths))!;
    expect(degraded.phase).toBe("degraded");
    expect(nodeState(degraded, xray).listenerReady).toBe(false);
    expect(nodeState(degraded, xray).links).toHaveLength(0);
    expect(nodeState(degraded, sing).directReady).toBe(true);
    expect(degraded.links.map(link => link.nodeId)).toEqual([sing.id]);
    expect(degraded.cores.singBox?.restarts).toBe(0);
    rmSync(nodeFile(env, xray, "no-listen"));
    rmSync(nodeFile(env, xray, "ready-delay"));
    crash(env, "xray");
    expect((await status(env)).links).toHaveLength(3);
  }, 16000);

  test("keeps the running snapshot and generated config path stable after a saved edit", async () => {
    const env = await environment({ tunnel: "quick" });
    const node = env.config.nodes[0]!;
    startWorker(env);
    const first = await status(env);
    const updated = structuredClone(env.config);
    updated.nodes[0]!.transport.path = "/saved-but-not-restarted";
    writeConfig(env.paths, updated);
    crash(env, "xray");
    const recovered = await until(() => getDaemonStatus(env.paths), value => value?.phase === "ready" && (value.cores.xray?.restarts ?? 0) >= 1);
    expect(recovered!.configHash).toBe(first.configHash);
    expect(recovered!.configHash).not.toBe(configFingerprint(updated));
    expect(new URL(recovered!.links[0]!.uri!).searchParams.get("path")).toBe(node.transport.path);
    const configPaths = events(env).filter(event => event.role === "xray" && event.kind === "start")
      .map(event => event.args[event.args.indexOf("-config") + 1]);
    expect(new Set(configPaths).size).toBe(1);
    expect(configPaths[0]).toContain("run-" + first.instanceId);
  }, 12000);

  test("rejects unauthenticated, wrong-instance and browser-origin control requests", async () => {
    const env = await environment();
    startWorker(env);
    const ready = await status(env);
    const record = readRuntimeRecord(env.paths)!;
    const correctHeaders = { Authorization: "Bearer " + record.controlToken, "X-Nexus-Instance": record.instanceId };
    const candidates: Record<string, string>[] = [
      {},
      { ...correctHeaders, Authorization: "Bearer " + "0".repeat(64) },
      { ...correctHeaders, "X-Nexus-Instance": randomUUID() },
      { ...correctHeaders, Origin: "https://untrusted.example" },
    ];
    for (const headers of candidates) expect(await localPost(record.controlPort, headers)).toBe(403);
    expect((await getDaemonStatus(env.paths))!.instanceId).toBe(ready.instanceId);
  }, 12000);

  test("keeps identity and authenticated stop available when exported URIs exceed the IPC budget", async () => {
    const env = await environment();
    for (let index = 1; index < 12; index++) await addNode(env);
    // Synthetic ENC text exercises model length bounds and URL escaping. The
    // mock is not an Xray handshake or validation of these fictitious keys.
    for (const node of env.config.nodes) {
      node.vlessEncryption = "+/=".repeat(5000);
      node.vlessDecryption = "synthetic-test-only-decryption";
    }
    writeConfig(env.paths, env.config);
    const worker = startWorker(env);
    const ready = await status(env);
    expect(ready.nodes).toHaveLength(12);
    expect(ready.nodes.every(node => node.directReady)).toBe(true);
    expect(ready.links).toHaveLength(12);
    expect(ready.links.every(link => link.uri === null && link.error?.includes("链接较长"))).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(ready))).toBeLessThan(1024 * 1024);
    expect(readFileSync(env.paths.link, "utf8").trim().split("\n")).toHaveLength(12);
    expect(readFileSync(env.paths.link, "utf8").length).toBeGreaterThan(500000);
    await stopDaemonGracefully(env.paths, 6000);
    await exited(worker);
    expect(await getDaemonStatus(env.paths)).toBeNull();
  }, 14000);

  test("allows one worker per data directory and leaves the first instance intact", async () => {
    const env = await environment({ tunnel: "quick" });
    startWorker(env);
    const first = await status(env);
    expect(() => acquireDaemonLock(env.paths)).toThrow(InstanceBusyError);
    const duplicate = startWorker(env);
    await exited(duplicate, 3000);
    expect(duplicate.exitCode).not.toBe(0);
    expect((await getDaemonStatus(env.paths))!.instanceId).toBe(first.instanceId);
    expect(events(env).filter(event => event.kind === "start")).toHaveLength(2);
  }, 12000);

  test("stops every owned core and tunnel through authenticated IPC and removes the current export", async () => {
    const env = await environment({ tunnel: "quick", direct: true });
    await addNode(env, { protocol: "vmess", tunnel: "fixed" });
    await addNode(env, { protocol: "shadowsocks" });
    const worker = startWorker(env);
    await status(env);
    const corePids = events(env).filter(event => event.kind === "start").map(event => event.pid);
    expect(corePids).toHaveLength(4);
    await stopDaemonGracefully(env.paths, 6000);
    await exited(worker);
    expect(await getDaemonStatus(env.paths)).toBeNull();
    expect(existsSync(env.paths.runtimeState)).toBe(false);
    expect(existsSync(env.paths.link)).toBe(false);
    expect(corePids.every(pid => !alive(pid))).toBe(true);
    const unlock = acquireDaemonLock(env.paths); unlock();
  }, 14000);

  for (const network of ["tcp", "udp"] as const) {
    test("rejects an occupied " + network.toUpperCase() + " listener before spawning any core", async () => {
      const env = await environment({ protocol: network === "udp" ? "hysteria2" : "vless" });
      const port = env.config.nodes[0]!.port;
      const blocker = network === "tcp" ? createServer() : createSocket("udp4");
      if (network === "tcp") {
        await new Promise<void>(resolve => (blocker as ReturnType<typeof createServer>).listen(port, "127.0.0.1", resolve));
      } else {
        await new Promise<void>(resolve => (blocker as ReturnType<typeof createSocket>).bind(port, "127.0.0.1", resolve));
      }
      try {
        const worker = startWorker(env);
        await exited(worker, 3000);
        expect(worker.exitCode).not.toBe(0);
        expect(events(env)).toHaveLength(0);
        expect(existsSync(env.paths.runtimeState)).toBe(false);
        expect(env.errors).toContain(network.toUpperCase() + " 端口");
        const unlock = acquireDaemonLock(env.paths); unlock();
      } finally { blocker.close(); }
    }, 12000);
  }

  test("rejects an empty enabled set without downloading or starting a core", async () => {
    const env = await environment();
    env.config.nodes = [];
    writeConfig(env.paths, env.config);
    const worker = startWorker(env);
    await exited(worker, 3000);
    expect(worker.exitCode).not.toBe(0);
    expect(env.errors).toContain("没有已启用的节点");
    expect(events(env)).toHaveLength(0);
    expect(readdirSync(env.paths.bin)).toHaveLength(0);
    const unlock = acquireDaemonLock(env.paths); unlock();
  }, 12000);

  test("ignores a stale PID record instead of killing an unrelated process", async () => {
    const env = await environment();
    const sleeper = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", windowsHide: true });
    extraChildren.push(sleeper);
    await new Promise<void>((resolve, reject) => { sleeper.once("spawn", () => resolve()); sleeper.once("error", reject); });
    const stale: RuntimeRecord = {
      schema: 1, pid: sleeper.pid!, instanceId: randomUUID(), startedAt: new Date().toISOString(),
      controlPort: await freePort(), controlToken: randomBytes(32).toString("hex"), configHash: configFingerprint(env.config),
    };
    atomicWrite(env.paths.runtimeState, JSON.stringify(stale));
    expect(await getDaemonStatus(env.paths)).toBeNull();
    await stopDaemonGracefully(env.paths, 1000);
    expect(alive(sleeper.pid!)).toBe(true);
  }, 12000);

  test("recognizes and gracefully stops a v1 worker without requiring v2 nodes or cores fields", async () => {
    const env = await environment();
    const release = acquireDaemonLock(env.paths);
    const record: RuntimeRecord = {
      schema: 1, pid: process.pid, instanceId: randomUUID(), startedAt: new Date().toISOString(),
      controlPort: 0, controlToken: randomBytes(32).toString("hex"), configHash: "a".repeat(64),
    };
    let stopped = false;
    const oldStatus = {
      instanceId: record.instanceId, pid: record.pid, startedAt: record.startedAt,
      configHash: record.configHash, phase: "ready", singBox: "running", cloudflared: "running",
      domain: "old.trycloudflare.com", link: "vless://old-test-link", tunnelReady: true,
      restarts: { singBox: 0, cloudflared: 0 }, lastError: null,
    };
    const server = Bun.serve({
      hostname: "127.0.0.1", port: 0,
      fetch(req) {
        if (req.headers.get("Authorization") !== "Bearer " + record.controlToken || req.headers.get("X-Nexus-Instance") !== record.instanceId) return new Response("Forbidden", { status: 403 });
        if (new URL(req.url).pathname === "/stop" && req.method === "POST") {
          stopped = true;
          setTimeout(() => { release(); void server.stop(true); }, 25);
          return Response.json({ accepted: true });
        }
        return Response.json(oldStatus);
      },
    });
    record.controlPort = server.port!;
    atomicWrite(env.paths.runtimeState, JSON.stringify(record));
    try {
      const result = await getDaemonStatus(env.paths);
      expect(result?.instanceId).toBe(record.instanceId);
      expect(result?.configHash).toBe(record.configHash);
      expect(result?.runtimeConfigHash).toBeUndefined();
      expect(result?.nodes).toBeUndefined();
      await stopDaemonGracefully(env.paths, 2000);
      expect(stopped).toBe(true);
    } finally { release(); await server.stop(true); }
  }, 6000);

  for (const recordState of ["missing", "corrupt"] as const) {
    test("does not report a stopped daemon while the lock is held and its record is " + recordState, async () => {
      const env = await environment();
      if (recordState === "corrupt") writeFileSync(env.paths.runtimeState, "{incomplete runtime record");
      const release = acquireDaemonLock(env.paths);
      try { await expect(stopDaemonGracefully(env.paths, 1000)).rejects.toThrow(InstanceBusyError); }
      finally { release(); }
    });
  }

  test("cleans up all cores after supervisor SIGKILL and permits a fresh worker", async () => {
    const env = await environment({ tunnel: "quick" });
    await addNode(env, { protocol: "shadowsocks" });
    const worker = startWorker(env);
    const first = await status(env);
    const corePids = events(env).filter(event => event.kind === "start").map(event => event.pid);
    worker.kill("SIGKILL");
    await exited(worker);
    await until(() => corePids.every(pid => !alive(pid)), Boolean, 9000);
    expect(await getDaemonStatus(env.paths)).toBeNull();
    startWorker(env);
    expect((await status(env)).instanceId).not.toBe(first.instanceId);
  }, 18000);

  test("starts a detached worker using its real entrypoint and working directory", async () => {
    const env = await environment();
    await startDetachedDaemon(env.paths);
    const ready = await status(env);
    expect(ready.pid).not.toBe(process.pid);
    await stopDaemonGracefully(env.paths, 6000);
    expect(await getDaemonStatus(env.paths)).toBeNull();
  }, 14000);

  test("keeps loopback readiness and authenticated IPC away from inherited environment proxies", async () => {
    const env = await environment({ tunnel: "quick" });
    const proxyRequests: { url: string; authorized: boolean }[] = [];
    const decoy = Bun.serve({
      hostname: "127.0.0.1", port: 0,
      fetch(request) {
        proxyRequests.push({ url: request.url, authorized: request.headers.has("Authorization") });
        return new Response("Synthetic proxy must not receive local control", { status: 502 });
      },
    });
    const proxyKeys = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];
    const bypassKeys = ["NO_PROXY", "no_proxy"];
    const originals = new Map([...proxyKeys, ...bypassKeys].map(key => [key, process.env[key]]));
    try {
      for (const key of proxyKeys) process.env[key] = "http://127.0.0.1:" + decoy.port;
      for (const key of bypassKeys) process.env[key] = "";
      const worker = startWorker(env);
      const ready = await status(env);
      expect(ready.nodes[0]!.tunnelReady).toBe(true);
      expect(proxyRequests).toHaveLength(0);
      // Positive control: ordinary Bun fetch really uses this decoy proxy,
      // including localhost with empty NO_PROXY. No credential is sent.
      const probe = await fetch("http://127.0.0.1:" + env.config.nodes[0]!.port + "/proxy-environment-canary", { signal: AbortSignal.timeout(1500) });
      await probe.body?.cancel();
      expect(probe.status).toBe(502);
      expect(proxyRequests).toHaveLength(1);
      expect(proxyRequests[0]!.url).toContain("/proxy-environment-canary");
      expect(proxyRequests[0]!.authorized).toBe(false);
      proxyRequests.length = 0;
      expect((await getDaemonStatus(env.paths))!.instanceId).toBe(ready.instanceId);
      await stopDaemonGracefully(env.paths, 6000);
      await exited(worker);
      expect(await getDaemonStatus(env.paths)).toBeNull();
      expect(proxyRequests).toHaveLength(0);
    } finally {
      for (const [key, value] of originals) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
      await decoy.stop(true);
    }
  }, 14000);
});
