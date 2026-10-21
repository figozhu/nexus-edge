import { afterEach, describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AppConfig, type AppPaths, type DaemonStatus,
  configFingerprint, createDefaultNode, createPaths, defaultConfig,
  runtimeConfigFingerprint, writeConfig,
} from "../src/core.ts";
import { getDaemonStatus, stopDaemonGracefully } from "../src/daemon.ts";

function configWithTunnel(): AppConfig {
  const node = createDefaultNode("vless");
  node.transport.type = "ws";
  node.tunnel.mode = "quick";
  node.direct = true;
  return { ...defaultConfig(), nodes: [node] };
}

describe("runtime configuration identity", () => {
  test("ignores only direct client address and public port without weakening the full fingerprint or mutating the input", () => {
    const original = configWithTunnel();
    const changed = structuredClone(original);
    changed.nodes[0]!.address = "198.51.100.23";
    changed.nodes[0]!.publicPort = 45678;
    const copy = structuredClone(changed);
    expect(configFingerprint(changed)).not.toBe(configFingerprint(original));
    expect(runtimeConfigFingerprint(changed)).toBe(runtimeConfigFingerprint(original));
    expect(changed).toEqual(copy);
    changed.nodes[0]!.address = "";
    changed.nodes[0]!.publicPort = 443;
    expect(runtimeConfigFingerprint(changed)).toBe(runtimeConfigFingerprint(original));
  });

  const changes: [string, (config: AppConfig) => void][] = [
    ["UUID", config => { config.nodes[0]!.uuid = randomUUID(); }],
    ["transport path", config => { config.nodes[0]!.transport.path = "/different-server-path"; }],
    ["listener address", config => { config.nodes[0]!.listen = "127.0.0.1"; }],
    ["listener port", config => { config.nodes[0]!.port++; }],
    ["TLS settings", config => { config.nodes[0]!.tls.serverName = "node.example.com"; }],
    ["tunnel transport", config => { config.nodes[0]!.tunnel.protocol = "http2"; }],
    ["tunnel credentials", config => { config.nodes[0]!.tunnel.token = "synthetic_token_123456789"; }],
    ["node name", config => { config.nodes[0]!.name = "Explicitly renamed node"; }],
    ["enabled state", config => { config.nodes[0]!.enabled = false; }],
    ["shared notification settings", config => { config.webhook = { kind: "generic", url: "https://notify.example.com/test" }; }],
  ];
  for (const [name, mutate] of changes) {
    test("retains " + name + " in the runtime fingerprint", () => {
      const original = configWithTunnel();
      const changed = structuredClone(original);
      mutate(changed);
      changed.nodes[0]!.address = "203.0.113.41";
      expect(runtimeConfigFingerprint(changed)).not.toBe(runtimeConfigFingerprint(original));
    });
  }

  test("covers other and disabled nodes instead of approving a metadata refresh from one matching node", () => {
    const original = configWithTunnel();
    const disabled = createDefaultNode("vmess", original.nodes);
    disabled.enabled = false;
    original.nodes.push(disabled);
    const changed = structuredClone(original);
    changed.nodes[0]!.address = "203.0.113.41";
    changed.nodes[1]!.transport.path = "/edited-other-node";
    expect(runtimeConfigFingerprint(changed)).not.toBe(runtimeConfigFingerprint(original));
  });

  test("still validates excluded metadata before accepting the configuration", () => {
    const config = configWithTunnel();
    config.nodes[0]!.address = "0.0.0.0";
    expect(() => runtimeConfigFingerprint(config)).toThrow("连接地址");
  });
});

interface MockEvent { role: string; kind: string; pid: number }
interface TestWorker {
  root: string; paths: AppPaths; config: AppConfig; worker: ChildProcess; stderr: string;
}
const activeWorkers: TestWorker[] = [];

async function until<T>(read: () => T | Promise<T>, accepted: (value: T) => boolean, timeout = 6000): Promise<T> {
  const deadline = Date.now() + timeout;
  let value: T;
  do {
    value = await read();
    if (accepted(value)) return value;
    await Bun.sleep(25);
  } while (Date.now() < deadline);
  throw new Error("Timed out waiting for runtime metadata: " + JSON.stringify(value!));
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("No local test address"));
      server.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}

async function startTestWorker(withDisabledNode = false, configure?: (config: AppConfig) => void): Promise<TestWorker> {
  const root = mkdtempSync(join(tmpdir(), "nexus-runtime-metadata-"));
  const entry = join(import.meta.dir, "fixtures", "daemon-entry.ts");
  const paths = { ...createPaths(join(root, "nexus-edge.ts"), process.execPath), entry };
  const config = configWithTunnel();
  const node = config.nodes[0]!;
  node.listen = "127.0.0.1";
  node.port = await freePort();
  node.publicPort = node.port;
  if (withDisabledNode) {
    const disabled = createDefaultNode("vmess", config.nodes);
    disabled.enabled = false;
    config.nodes.push(disabled);
  }
  configure?.(config);
  writeConfig(paths, config);
  const worker = spawn(process.execPath, [entry, "--fixture-worker", root], {
    cwd: root, shell: false, windowsHide: true, stdio: ["ignore", "ignore", "pipe"],
  });
  const env: TestWorker = { root, paths, config, worker, stderr: "" };
  worker.stderr?.on("data", chunk => { env.stderr = (env.stderr + chunk.toString()).slice(-12000); });
  activeWorkers.push(env);
  return env;
}

function mockEvents(env: TestWorker): MockEvent[] {
  const path = join(env.root, "events.jsonl");
  return existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) : [];
}

function capturedNotices(env: TestWorker): { domain: string; link: string }[] {
  const path = join(env.root, "notices.jsonl");
  return existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) : [];
}

function directUri(status: DaemonStatus | null): string | null {
  return status?.nodes[0]?.links.find(link => link.via === "direct")?.uri ?? null;
}

async function ready(env: TestWorker): Promise<DaemonStatus> {
  try {
    return await until(() => getDaemonStatus(env.paths), value => value?.phase === "ready") as DaemonStatus;
  } catch (error) { throw new Error(String(error) + "\nFixture stderr: " + env.stderr); }
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

afterEach(async () => {
  for (const env of activeWorkers.splice(0)) {
    try { await stopDaemonGracefully(env.paths, 5000); } catch { /* Only our ChildProcess handle is used below. */ }
    if (env.worker.exitCode === null && env.worker.signalCode === null) env.worker.kill("SIGTERM");
    await until(() => env.worker.exitCode !== null || env.worker.signalCode !== null, Boolean, 9000);
    const pids = [...new Set(mockEvents(env).map(event => event.pid))];
    await until(() => pids.every(pid => !processAlive(pid)), Boolean, 9000);
    rmSync(env.root, { recursive: true, force: true });
  }
});

describe("live client endpoint metadata", () => {
  test("keeps original ready notifications but metadata edits do not resend them, while a new Quick hostname still does", async () => {
    const env = await startTestWorker(false, config => {
      config.webhook = { kind: "generic", url: "https://nexus-edge-webhook.test/fixture" };
      config.nodes[0]!.address = "198.51.100.20";
    });
    const first = await ready(env);
    const originalNotices = await until(() => capturedNotices(env), notices => notices.length === 2);
    expect(originalNotices.map(notice => notice.domain).sort()).toEqual(["198.51.100.20", first.nodes[0]!.domain!].sort());
    const updated = structuredClone(env.config);
    for (const [address, publicPort] of [["198.51.100.21", env.config.nodes[0]!.port], ["198.51.100.21", 45680], ["", 45680], ["203.0.113.21", 45681]] as const) {
      updated.nodes[0]!.address = address;
      updated.nodes[0]!.publicPort = publicPort;
      writeConfig(env.paths, updated);
      await until(() => getDaemonStatus(env.paths), status => address ? directUri(status)?.includes(`@${address}:${publicPort}`) === true : directUri(status) === null);
      await Bun.sleep(125);
      expect(capturedNotices(env)).toEqual(originalNotices);
    }
    const nodeId = env.config.nodes[0]!.id;
    const nextDomain = "another-river.trycloudflare.com";
    writeFileSync(join(env.root, "domain-" + nodeId + ".txt"), nextDomain);
    writeFileSync(join(env.root, "crash-cloudflared_" + nodeId), "1");
    await until(() => getDaemonStatus(env.paths), status => status?.phase === "ready" && status.nodes[0]?.domain === nextDomain && status.nodes[0].tunnelRestarts >= 1);
    const changedNotices = await until(() => capturedNotices(env), notices => notices.length === 3);
    expect(changedNotices[2]!.domain).toBe(nextDomain);
    expect(changedNotices[2]!.link).toContain(nextDomain);
    expect((await getDaemonStatus(env.paths))?.cores.xray?.restarts).toBe(0);
  }, 12000);

  test("filling a missing public address after readiness silently refreshes exports without a deferred direct notification", async () => {
    const env = await startTestWorker(false, config => {
      config.webhook = { kind: "generic", url: "https://nexus-edge-webhook.test/fixture" };
    });
    const first = await ready(env);
    const originalNotices = await until(() => capturedNotices(env), notices => notices.length === 1);
    expect(originalNotices[0]!.domain).toBe(first.nodes[0]!.domain!);
    const updated = structuredClone(env.config);
    updated.nodes[0]!.address = "198.51.100.22";
    writeConfig(env.paths, updated);
    const refreshed = await until(() => getDaemonStatus(env.paths), status => directUri(status)?.includes("@198.51.100.22:") === true);
    expect(readFileSync(env.paths.link, "utf8")).toContain(directUri(refreshed)!);
    writeFileSync(join(env.root, "crash-xray"), "1");
    await until(() => getDaemonStatus(env.paths), status => status?.phase === "ready" && (status.cores.xray?.restarts ?? 0) >= 1);
    await Bun.sleep(125);
    expect(capturedNotices(env)).toEqual(originalNotices);
  }, 12000);

  test("refreshes direct links and the export file without restarting a core or invalidating its Quick hostname", async () => {
    const env = await startTestWorker();
    const first = await ready(env);
    const firstTunnel = first.nodes[0]!.links.find(link => link.via === "tunnel")!.uri;
    expect(directUri(first)).toBeNull();
    expect(first.runtimeConfigHash).toBe(runtimeConfigFingerprint(env.config));
    const updated = structuredClone(env.config);
    updated.nodes[0]!.address = "198.51.100.23";
    updated.nodes[0]!.publicPort = 45678;
    writeConfig(env.paths, updated);
    const refreshed = await until(() => getDaemonStatus(env.paths), value => directUri(value)?.includes("@198.51.100.23:45678") === true) as DaemonStatus;
    expect(refreshed.instanceId).toBe(first.instanceId);
    expect(refreshed.configHash).toBe(first.configHash);
    expect(refreshed.runtimeConfigHash).toBe(first.runtimeConfigHash);
    expect(refreshed.runtimeConfigHash).toBe(runtimeConfigFingerprint(updated));
    expect(refreshed.nodes[0]!.domain).toBe(first.nodes[0]!.domain);
    expect(refreshed.nodes[0]!.tunnelReady).toBe(true);
    expect(refreshed.nodes[0]!.links.find(link => link.via === "tunnel")!.uri).toBe(firstTunnel);
    expect(refreshed.cores.xray!.restarts).toBe(0);
    expect(refreshed.nodes[0]!.tunnelRestarts).toBe(0);
    expect(mockEvents(env).filter(event => event.kind === "start")).toHaveLength(2);
    expect(readFileSync(env.paths.link, "utf8")).toContain(directUri(refreshed)!);
    expect(readFileSync(env.paths.link, "utf8")).toContain(firstTunnel!);
  }, 12000);

  test("rejects metadata from a different complete runtime identity and keeps frozen credentials across core retries", async () => {
    const env = await startTestWorker(true);
    const first = await ready(env);
    const accepted = structuredClone(env.config);
    accepted.nodes[0]!.address = "198.51.100.24";
    accepted.nodes[0]!.publicPort = 45679;
    writeConfig(env.paths, accepted);
    const before = await until(() => getDaemonStatus(env.paths), value => directUri(value)?.includes("@198.51.100.24:45679") === true) as DaemonStatus;
    const oldUri = directUri(before)!;
    const unrelatedEdit = structuredClone(accepted);
    unrelatedEdit.nodes[0]!.address = "203.0.113.24";
    unrelatedEdit.nodes[1]!.transport.path = "/different-disabled-node";
    writeConfig(env.paths, unrelatedEdit);
    await Bun.sleep(250);
    expect(directUri(await getDaemonStatus(env.paths))).toBe(oldUri);

    const changedServer = structuredClone(accepted);
    changedServer.nodes[0]!.uuid = randomUUID();
    changedServer.nodes[0]!.transport.path = "/not-running";
    changedServer.nodes[0]!.address = "203.0.113.25";
    writeConfig(env.paths, changedServer);
    writeFileSync(join(env.root, "crash-xray"), "1");
    const retried = await until(() => getDaemonStatus(env.paths), value => value?.phase === "ready" && (value.cores.xray?.restarts ?? 0) >= 1) as DaemonStatus;
    expect(retried.runtimeConfigHash).toBe(first.runtimeConfigHash);
    expect(directUri(retried)).toBe(oldUri);
    expect(readFileSync(env.paths.link, "utf8")).not.toContain(changedServer.nodes[0]!.uuid);
    expect(new URL(directUri(retried)!).searchParams.get("path")).toBe(env.config.nodes[0]!.transport.path);

    const restored = structuredClone(accepted);
    restored.nodes[0]!.address = "203.0.113.26";
    writeConfig(env.paths, restored);
    const refreshed = await until(() => getDaemonStatus(env.paths), value => directUri(value)?.includes("@203.0.113.26:45679") === true) as DaemonStatus;
    expect(refreshed.nodes[0]!.domain).toBe(first.nodes[0]!.domain);
    expect(refreshed.nodes[0]!.tunnelRestarts).toBe(0);
  }, 12000);

  test("does not reset configuration or lose accepted links when the saved file is invalid or missing", async () => {
    const env = await startTestWorker();
    await ready(env);
    const accepted = structuredClone(env.config);
    accepted.nodes[0]!.address = "198.51.100.27";
    writeConfig(env.paths, accepted);
    const before = await until(() => getDaemonStatus(env.paths), value => directUri(value)?.includes("@198.51.100.27:") === true) as DaemonStatus;
    const oldUri = directUri(before)!;
    writeFileSync(env.paths.config, "{partial edit");
    await Bun.sleep(200);
    expect(directUri(await getDaemonStatus(env.paths))).toBe(oldUri);
    expect(readFileSync(env.paths.config, "utf8")).toBe("{partial edit");
    rmSync(env.paths.config);
    await Bun.sleep(200);
    const after = await getDaemonStatus(env.paths);
    expect(after?.phase).toBe("ready");
    expect(directUri(after)).toBe(oldUri);
    expect(existsSync(env.paths.config)).toBe(false);
    expect(mockEvents(env).filter(event => event.kind === "start")).toHaveLength(2);
  }, 12000);
});
