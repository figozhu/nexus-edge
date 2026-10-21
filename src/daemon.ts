import * as daemonFs from "node:fs";
import * as daemonPath from "node:path";
import * as daemonCp from "node:child_process";
import * as daemonCrypto from "node:crypto";
import * as daemonNet from "node:net";
import * as daemonHttp from "node:http";
import * as daemonDgram from "node:dgram";
import * as daemonSqlite from "bun:sqlite";
import { type AppConfig, type AppPaths, type RuntimeRecord, type DaemonStatus, type NodeConfig, type NodeRuntimeStatus, type CoreName, type CoreRuntimeStatus, type CoreProcessState, atomicWrite, ensureDataDir, readConfig, validateConfig, configFingerprint, runtimeConfigFingerprint, collectConfigSecrets, generateNodeLinks, nodeEngine, nodeListenNetworks, normalizeDomain, LineBuffer, redact, errorMessage, delay } from "./core.ts";
import { ensureBinaries, preflightCores, buildCloudflaredArgs, readCoreSelection, initializeCoreSelection, coreReleaseFingerprint, type Binaries } from "./network.ts";
import { syncFirewallBackground } from "./firewall-control.ts";
import { type FirewallResult } from "./firewall.ts";

export class InstanceBusyError extends Error {
  constructor() { super("同一数据目录已有守护进程占用。请从管理面板停止它；不要删除锁文件或根据旧 PID 杀进程。"); }
}

/** SQLite's OS-backed lock is released after a crash; no stale PID can grant ownership. */
export function acquireDaemonLock(paths: AppPaths): () => void {
  ensureDataDir(paths);
  const db = new daemonSqlite.Database(paths.lockDb, { create: true });
  try { db.exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;"); }
  catch (e) { db.close(); if (/busy|locked/i.test(errorMessage(e))) throw new InstanceBusyError(); throw e; }
  if (process.platform !== "win32") daemonFs.chmodSync(paths.lockDb, 0o600);
  let released = false;
  return () => { if (!released) { released = true; try { db.exec("ROLLBACK;"); } finally { db.close(); } } };
}

export function readRuntimeRecord(paths: AppPaths): RuntimeRecord | null {
  let text: string;
  try { text = daemonFs.readFileSync(paths.runtimeState, "utf8"); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === "ENOENT") return null; throw e; }
  try {
    const r = JSON.parse(text) as RuntimeRecord;
    if (r.schema !== 1 || typeof r.instanceId !== "string" || !/^[0-9a-f-]{36}$/.test(r.instanceId) || !Number.isInteger(r.pid) || r.pid < 1 || !Number.isInteger(r.controlPort) || r.controlPort < 1 || r.controlPort > 65535 || !/^[0-9a-f]{64}$/.test(r.controlToken) || !/^[0-9a-f]{64}$/.test(r.configHash) || typeof r.startedAt !== "string") return null;
    return r;
  } catch { return null; }
}

// Node's direct HTTP client ignores HTTP_PROXY. Loopback control credentials must
// never be sent through a proxy inherited from the user's terminal environment.
async function daemonLocalRequest(port: number, path: string, timeoutMs: number, headers: Record<string, string> = {}, method = "GET"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = daemonHttp.request({ hostname: "127.0.0.1", port, path, method, headers, agent: false }, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => {
        body += chunk;
        if (Buffer.byteLength(body) > 1024 * 1024) request.destroy(new Error("本地控制响应超过大小限制。"));
      });
      response.once("error", reject);
      response.once("end", () => resolve({ status: response.statusCode ?? 0, body }));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("本地控制请求超时。")));
    request.once("error", reject);
    request.end();
  });
}

export async function getDaemonStatus(paths: AppPaths, timeoutMs = 1200): Promise<DaemonStatus | null> {
  const runtime = readRuntimeRecord(paths);
  if (!runtime) return null;
  try {
    const response = await daemonLocalRequest(runtime.controlPort, "/status", timeoutMs, { Authorization: `Bearer ${runtime.controlToken}`, "X-Nexus-Instance": runtime.instanceId });
    if (response.status !== 200) return null;
    const result = JSON.parse(response.body) as DaemonStatus;
    return result.instanceId === runtime.instanceId && result.pid === runtime.pid ? result : null;
  } catch { return null; }
}

export async function stopDaemonGracefully(paths: AppPaths, timeoutMs = 16000): Promise<void> {
  const runtime = readRuntimeRecord(paths);
  if (!runtime) {
    // Startup/preflight owns the lock before publishing its control endpoint.
    const release = acquireDaemonLock(paths); release();
    return;
  }
  const status = await getDaemonStatus(paths);
  if (!status) {
    // A dead process releases this lock. Never use the PID record as a kill target.
    const release = acquireDaemonLock(paths); release();
    return;
  }
  const response = await daemonLocalRequest(runtime.controlPort, "/stop", 3000, { Authorization: `Bearer ${runtime.controlToken}`, "X-Nexus-Instance": runtime.instanceId }, "POST");
  if (response.status !== 200) throw new Error(`守护进程拒绝停止请求（HTTP ${response.status}）。`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const latest = await getDaemonStatus(paths, 500);
    if (!latest || latest.instanceId !== runtime.instanceId) {
      try { const release = acquireDaemonLock(paths); release(); return; }
      catch (e) { if (!(e instanceof InstanceBusyError)) throw e; }
    }
    await delay(150);
  }
  throw new Error("等待停止超时，未强杀任何 PID。请查看日志或通过系统任务/服务管理器检查当前实例。");
}

export async function startDetachedDaemon(paths: AppPaths): Promise<void> {
  if (await getDaemonStatus(paths)) throw new Error("后台实例已经运行，请选择重启。");
  ensureDataDir(paths);
  const release = acquireDaemonLock(paths); release();
  const fd = daemonFs.openSync(paths.log, "a", 0o600);
  try {
    await new Promise<void>((resolve, reject) => {
      const child = daemonCp.spawn(paths.runtime, [paths.entry, "--worker"], {
        cwd: paths.root, shell: false, detached: true, windowsHide: true,
        stdio: ["ignore", fd, fd],
      });
      child.once("error", reject);
      child.once("spawn", () => { child.unref(); resolve(); });
    });
  } finally { daemonFs.closeSync(fd); }
}

export async function waitForReady(paths: AppPaths, timeoutMs = 45000, progress?: (status: DaemonStatus | null) => void): Promise<DaemonStatus | null> {
  const deadline = Date.now() + timeoutMs;
  let latest: DaemonStatus | null = null;
  while (Date.now() < deadline) {
    latest = await getDaemonStatus(paths);
    progress?.(latest);
    if (latest?.phase === "ready") return latest;
    await delay(750);
  }
  return latest;
}

export class RotatingLogger {
  private file: string;
  private secrets: string[];
  private size: number;
  constructor(file: string, secrets: string[]) {
    this.file = file; this.secrets = secrets;
    this.size = daemonFs.existsSync(file) ? daemonFs.statSync(file).size : 0;
  }
  write(message: string): void {
    const safe = redact(message, this.secrets).slice(0, 18000);
    const line = `[${new Date().toISOString()}] ${safe}\n`;
    if (this.size + Buffer.byteLength(line) > 2 * 1024 * 1024) {
      for (let n = 2; n >= 1; n--) {
        const source = n === 1 ? this.file : `${this.file}.${n - 1}`;
        const target = `${this.file}.${n}`;
        if (daemonFs.existsSync(target)) daemonFs.unlinkSync(target);
        if (daemonFs.existsSync(source)) daemonFs.renameSync(source, target);
      }
      this.size = 0;
    }
    daemonFs.appendFileSync(this.file, line, { mode: 0o600 });
    this.size += Buffer.byteLength(line);
  }
}

export function tailLog(paths: AppPaths, count = 25): string {
  if (!daemonFs.existsSync(paths.log)) return "暂无运行日志。";
  const fd = daemonFs.openSync(paths.log, "r");
  try {
    const size = daemonFs.fstatSync(fd).size;
    const buffer = Buffer.alloc(Math.min(size, 64 * 1024));
    daemonFs.readSync(fd, buffer, 0, buffer.length, Math.max(0, size - buffer.length));
    return buffer.toString("utf8").trimEnd().split("\n").slice(-count).join("\n");
  } finally { daemonFs.closeSync(fd); }
}

function daemonSameSecret(actual: string | null, expected: string): boolean {
  const a = Buffer.from(actual ?? ""); const b = Buffer.from(expected);
  return a.length === b.length && daemonCrypto.timingSafeEqual(a, b);
}

function daemonSerializeStatus(status: DaemonStatus): string {
  const text = JSON.stringify(status);
  if (Buffer.byteLength(text) <= 1024 * 1024) return text;
  // Long VLESS ENC values may make links larger than the local IPC budget.
  // Keep readiness and identity available so the user can still stop/restart.
  // The complete URIs stay in the export file; the panel can regenerate them.
  const conciseLink = (link: DaemonStatus["links"][number]) => link.uri
    ? { ...link, uri: null, error: "链接较长，请从节点导出菜单生成；完整 URI 仍保存在节点链接文件中。" }
    : link;
  return JSON.stringify({
    ...status,
    nodes: status.nodes.map(node => ({ ...node, links: node.links.map(conciseLink) })),
    links: status.links.map(conciseLink),
  });
}

export async function assertLocalPortAvailable(port: number, host = "127.0.0.1", network: "tcp" | "udp" = "tcp"): Promise<void> {
  if (network === "udp") {
    await new Promise<void>((resolve, reject) => {
      const socket = daemonDgram.createSocket({ type: daemonNet.isIP(host) === 6 ? "udp6" : "udp4", reuseAddr: false });
      socket.once("error", error => {
        try { socket.close(); } catch { /* A bind failure may leave no socket handle. */ }
        reject(new Error(`本机 UDP 端口 ${host}:${port} 无法使用：${errorMessage(error)}`));
      });
      socket.bind({ address: host, port, exclusive: true }, () => socket.close(() => resolve()));
    });
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const server = daemonNet.createServer();
    server.once("error", error => reject(new Error(`本机 TCP 端口 ${host}:${port} 无法使用：${errorMessage(error)}`)));
    server.listen({ host, port, exclusive: true }, () => server.close(error => error ? reject(error) : resolve()));
  });
}

async function daemonFreePort(excluded: Set<number>): Promise<number> {
  for (let attempt = 0; attempt < 64; attempt++) {
    const port = await new Promise<number>((resolve, reject) => {
      const server = daemonNet.createServer();
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
        const address = server.address();
        const value = typeof address === "object" && address ? address.port : 0;
        server.close(error => error ? reject(error) : resolve(value));
      });
    });
    if (port && !excluded.has(port)) { excluded.add(port); return port; }
  }
  throw new Error("无法分配不冲突的本机隧道指标端口。");
}

function daemonProbeAddress(listen: string): string {
  return listen === "0.0.0.0" ? "127.0.0.1" : listen === "::" ? "::1" : listen;
}

async function daemonProbeTcp(port: number, listen: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = daemonNet.connect({ host: daemonProbeAddress(listen), port });
    let done = false;
    const finish = (ok: boolean) => { if (!done) { done = true; socket.destroy(); resolve(ok); } };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(700, () => finish(false));
  });
}

/** A bound UDP port is a listener check, not a protocol handshake or proof of reachability. */
async function daemonProbeUdp(port: number, listen: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = daemonDgram.createSocket({ type: daemonNet.isIP(listen) === 6 ? "udp6" : "udp4", reuseAddr: false });
    let done = false;
    const timer = setTimeout(() => finish(false), 700);
    const finish = (inUse: boolean) => {
      if (done) return;
      done = true; clearTimeout(timer);
      try { socket.close(() => resolve(inUse)); } catch { resolve(inUse); }
    };
    socket.once("error", error => finish((error as NodeJS.ErrnoException).code === "EADDRINUSE"));
    socket.bind({ address: listen, port, exclusive: true }, () => finish(false));
  });
}

async function daemonSettleWithin(promises: Promise<void>[], milliseconds: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.allSettled(promises),
      new Promise<void>(resolve => { timer = setTimeout(resolve, milliseconds); }),
    ]);
  } finally { if (timer) clearTimeout(timer); }
}

export function buildWebhookPayload(kind: AppConfig["webhook"]["kind"], domain: string, link: string): unknown {
  const content = `NexusEdge 节点通路已就绪\n地址：${domain}\n${link}`;
  switch (kind) {
    case "feishu": return { msg_type: "text", content: { text: content } };
    case "wecom": case "dingtalk": return { msgtype: "text", text: { content } };
    case "bark": return { title: "NexusEdge 节点就绪", body: content };
    default: return { event: "nexus-edge.ready", domain, link, text: content };
  }
}

async function daemonNotify(config: AppConfig, domain: string, link: string, logger: RotatingLogger): Promise<void> {
  if (config.webhook.kind === "none") return;
  try {
    const response = await fetch(config.webhook.url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildWebhookPayload(config.webhook.kind, domain, link)),
      redirect: "error", signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (config.webhook.kind !== "generic") {
      const body = await response.json() as { code?: number; errcode?: number };
      const good = config.webhook.kind === "bark" ? body.code === 200 : config.webhook.kind === "feishu" ? body.code === 0 : body.errcode === 0;
      if (!good) throw new Error("接收方返回非成功业务状态；检查该机器人的认证/签名要求。");
    } else { await response.body?.cancel(); }
    logger.write("[webhook] 已发送当前节点通知。");
  } catch (e) { logger.write(`[webhook] 通知失败，后台继续运行：${errorMessage(e)}`); }
}

export interface DaemonCoreCommand { executable: string; args: string[] }
export interface DaemonOptions {
  /** Dependency injection for local tests only. The interactive program never sets these. */
  cores?: Partial<Record<CoreName, DaemonCoreCommand>>;
  tunnels?: Record<string, DaemonCoreCommand>;
  skipPreflight?: boolean;
  healthIntervalMs?: number;
  backoffBaseMs?: number;
  firewall?: (paths: AppPaths, config: AppConfig) => Promise<FirewallResult | null>;
}

interface DaemonJob {
  key: string;
  engine?: CoreName;
  nodeId?: string;
  command: DaemonCoreCommand;
  args: string[];
  state: CoreRuntimeStatus;
}

export async function runDaemonWorker(paths: AppPaths, options: DaemonOptions = {}): Promise<void> {
  const releaseLock = acquireDaemonLock(paths);
  const instanceId = daemonCrypto.randomUUID();
  const startedAt = new Date().toISOString();
  const runDirectory = daemonPath.join(paths.data, `run-${instanceId}`);
  const abort = new AbortController();
  let server: ReturnType<typeof Bun.serve> | undefined;
  let logger: RotatingLogger | undefined;
  let stopRequested = false;
  const children = new Set<daemonCp.ChildProcess>();
  const loops: Promise<void>[] = [];
  let fatalError: unknown;
  let requestStop: () => void = () => {};
  const stopPromise = new Promise<void>(resolve => { requestStop = () => { if (!stopRequested) { stopRequested = true; abort.abort(); resolve(); } }; });
  const signalStop = () => requestStop();
  process.on("SIGINT", signalStop);
  process.on("SIGTERM", signalStop);
  try {
    // A normalized immutable snapshot is used for all retries in this worker.
    const config = readConfig(paths);
    const runtimeHash = runtimeConfigFingerprint(config);
    const enabled = config.nodes.filter(node => node.enabled);
    if (!enabled.length) throw new Error("没有已启用的节点。请先在面板创建或启用至少一个节点。");
    logger = new RotatingLogger(paths.log, collectConfigSecrets(config));
    logger.write(`NexusEdge worker 启动，PID=${process.pid}，instance=${instanceId}，节点数=${enabled.length}`);
    daemonFs.mkdirSync(runDirectory, { mode: 0o700 });
    const runningPaths: AppPaths = {
      ...paths, data: runDirectory, singConfig: daemonPath.join(runDirectory, "sing-box.json"),
      xrayConfig: daemonPath.join(runDirectory, "xray.json"), tokenFile: daemonPath.join(runDirectory, "tunnel-token.txt"),
    };
    for (const node of enabled) for (const network of nodeListenNetworks(node)) await assertLocalPortAvailable(node.port, node.listen, network);
    const engines = [...new Set(enabled.map(nodeEngine))];
    const tunneled = enabled.filter(node => node.tunnel.mode !== "none");
    const injectedAll = engines.every(engine => options.cores?.[engine]) && tunneled.every(node => options.tunnels?.[node.id]);
    // A real first start records the default selection, so later script updates
    // cannot silently replace a user's chosen core set. Fully injected tests
    // do not install or claim ownership of real core binaries.
    const releases = (injectedAll && options.skipPreflight ? readCoreSelection(paths) : initializeCoreSelection(paths)).active;
    const releaseHash = coreReleaseFingerprint(releases);
    let binaries: Binaries = {};
    if (!options.skipPreflight) binaries = await preflightCores(runningPaths, config, { releases });
    else if (!injectedAll) binaries = await ensureBinaries(paths, config, message => logger!.write(message), releases);
    if (abort.signal.aborted) return;
    let firewall: DaemonStatus["firewall"];
    if (options.firewall || !(injectedAll && options.skipPreflight)) {
      try {
        const result = await (options.firewall ?? syncFirewallBackground)(paths, config);
        if (result) firewall = { status: result.status, backend: result.backend, detail: result.detail, warnings: result.warnings };
      } catch (error) {
        firewall = { status: "error", backend: "none", detail: `防火墙同步未完成：${errorMessage(error)}`, warnings: [] };
      }
      if (firewall) {
        logger.write(`[firewall] ${firewall.status} / ${firewall.backend}：${firewall.detail}`);
        for (const warning of firewall.warnings) logger.write(`[firewall] ${warning}`);
      }
    }
    if (abort.signal.aborted) return;
    const runtime: RuntimeRecord = {
      schema: 1, instanceId, pid: process.pid, startedAt,
      controlPort: 0, controlToken: daemonCrypto.randomBytes(32).toString("hex"), configHash: configFingerprint(config),
    };
    const status: DaemonStatus = {
      instanceId, pid: process.pid, startedAt, configHash: runtime.configHash, runtimeConfigHash: runtimeHash, coreReleaseHash: releaseHash,
      phase: "starting", cores: {}, nodes: config.nodes.map(node => ({
        id: node.id, name: node.name, protocol: node.protocol, engine: nodeEngine(node), enabled: node.enabled,
        phase: node.enabled ? "starting" : "disabled", listenerReady: false,
        listenerCheck: nodeListenNetworks(node).join("+") as NodeRuntimeStatus["listenerCheck"],
        directReady: false, tunnelReady: false, tunnelMode: node.tunnel.mode,
        tunnelState: node.enabled && node.tunnel.mode !== "none" ? "starting" : "disabled", tunnelRestarts: 0,
        domain: node.tunnel.mode === "fixed" ? node.tunnel.domain : null,
        links: [], lastError: null, detail: node.enabled ? "等待本地核心监听。" : "节点已禁用，未启动监听或隧道。",
      })), links: [], lastError: null, ...(firewall ? { firewall } : {}),
    };
    const nodeStates = new Map(status.nodes.map(node => [node.id, node]));
    const nodeConfigs = new Map(config.nodes.map(node => [node.id, node]));
    let clientMetadata = new Map(config.nodes.map(node => [node.id, { address: node.address, publicPort: node.publicPort }] as const));
    let lastMetadataText: string | undefined;
    const refreshClientMetadata = () => {
      try {
        // Read-only: a missing or partially edited file must not create defaults
        // or migrate configuration underneath the running worker.
        const text = daemonFs.readFileSync(paths.config, "utf8");
        if (text === lastMetadataText) return;
        lastMetadataText = text;
        const candidate = validateConfig(JSON.parse(text), { allowExpiredCertificate: true });
        if (runtimeConfigFingerprint(candidate) !== runtimeHash) return;
        // Replace only this overlay. Credentials, listeners, core retry arguments
        // and Quick Tunnel identity always keep using the immutable snapshot.
        clientMetadata = new Map(candidate.nodes.map(node => [node.id, { address: node.address, publicPort: node.publicPort }] as const));
      } catch { /* Keep the last accepted metadata while a saved edit is invalid or unreadable. */ }
    };
    const jobs: DaemonJob[] = [];
    const tunnelJobs = new Map<string, DaemonJob>();
    const metricsPorts = new Map<string, number>();
    const listenerCounts = new Map<string, number>();
    const tunnelCounts = new Map<string, number>();
    const initialState = (): CoreRuntimeStatus => ({ state: "starting", restarts: 0, lastError: null });
    for (const engine of engines) {
      const command = options.cores?.[engine] ?? (binaries[engine] ? { executable: binaries[engine]!, args: [] } : undefined);
      if (!command) throw new Error(`未获取节点所需的 ${engine} 核心。`);
      const state = initialState(); status.cores[engine] = state;
      jobs.push({ key: engine, engine, command, args: engine === "singBox" ? ["run", "-c", runningPaths.singConfig] : ["run", "-config", runningPaths.xrayConfig], state });
    }
    server = Bun.serve({
      hostname: "127.0.0.1", port: 0, maxRequestBodySize: 1024,
      fetch(request) {
        const url = new URL(request.url);
        if (request.headers.has("Origin") || !daemonSameSecret(request.headers.get("Authorization"), `Bearer ${runtime.controlToken}`) || !daemonSameSecret(request.headers.get("X-Nexus-Instance"), instanceId)) return new Response("Forbidden", { status: 403 });
        const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
        if (url.pathname === "/status" && request.method === "GET") return new Response(daemonSerializeStatus(status), { headers });
        if (url.pathname === "/stop" && request.method === "POST") {
          status.phase = "stopping";
          for (const node of status.nodes) if (node.enabled) { node.phase = "stopping"; node.links = []; }
          status.links = [];
          setTimeout(requestStop, 25);
          return new Response('{"accepted":true}', { headers });
        }
        return new Response("Not found", { status: 404 });
      },
    });
    runtime.controlPort = server.port!;
    const reservedPorts = new Set([...enabled.map(node => node.port), runtime.controlPort]);
    // No tunnel means no cloudflared job, metrics listener or /ready request.
    for (const node of tunneled) {
      const command = options.tunnels?.[node.id] ?? (binaries.cloudflared ? { executable: binaries.cloudflared, args: [] } : undefined);
      if (!command) throw new Error(`未获取节点 ${node.name} 所需的 cloudflared。`);
      const metricsPort = await daemonFreePort(reservedPorts); metricsPorts.set(node.id, metricsPort);
      const job: DaemonJob = { key: `cloudflared:${node.id}`, nodeId: node.id, command, args: buildCloudflaredArgs(node, runningPaths, metricsPort), state: initialState() };
      jobs.push(job); tunnelJobs.set(node.id, job);
    }
    atomicWrite(paths.runtimeState, JSON.stringify(runtime, null, 2) + "\n");
    daemonFs.rmSync(paths.link, { force: true });
    let publishedLinks = "";
    const publishLinks = () => {
      status.links = status.nodes.flatMap(node => node.enabled ? node.links : []);
      const text = status.links.filter(link => link.uri).map(link => link.uri!).join("\n");
      if (text === publishedLinks) return;
      publishedLinks = text;
      if (text) atomicWrite(paths.link, text + "\n");
      else daemonFs.rmSync(paths.link, { force: true });
    };
    const invalidateJob = (job: DaemonJob) => {
      const nextPhase = abort.signal.aborted || status.phase === "stopping" ? "stopping" : "degraded";
      for (const node of status.nodes) {
        if (!node.enabled) continue;
        if (job.engine && node.engine === job.engine) {
          node.listenerReady = false; node.directReady = false; node.tunnelReady = false; node.links = [];
          listenerCounts.set(node.id, 0); tunnelCounts.set(node.id, 0);
          node.phase = nextPhase;
        } else if (job.nodeId === node.id) {
          node.tunnelReady = false; node.links = node.links.filter(link => link.via === "direct");
          tunnelCounts.set(node.id, 0); node.phase = nextPhase;
        }
      }
      status.phase = nextPhase;
      publishLinks();
    };
    const setJobState = (job: DaemonJob, state: CoreProcessState) => {
      job.state.state = state;
      if (job.nodeId) {
        const node = nodeStates.get(job.nodeId)!;
        node.tunnelState = state; node.tunnelRestarts = job.state.restarts;
      }
    };
    const supervise = async (job: DaemonJob) => {
      let consecutiveFailures = 0;
      while (!abort.signal.aborted) {
        setJobState(job, "starting");
        if (job.nodeId && nodeConfigs.get(job.nodeId)!.tunnel.mode === "quick") nodeStates.get(job.nodeId)!.domain = null;
        const spawnTime = Date.now();
        logger!.write(`[${job.key}] 启动核心。`);
        const child = daemonCp.spawn(paths.runtime, [paths.entry, "--core-host", job.command.executable, ...job.command.args, ...job.args], {
          cwd: runDirectory, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
        });
        children.add(child);
        const consume = (line: string) => {
          logger!.write(`[${job.key}] ${line}`);
          if (job.nodeId && nodeConfigs.get(job.nodeId)!.tunnel.mode === "quick") {
            const match = line.match(/https:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com)(?=[\s/"'|]|$)/i);
            if (match) nodeStates.get(job.nodeId)!.domain = normalizeDomain(match[1]!);
          }
        };
        const stdout = new LineBuffer(consume); const stderr = new LineBuffer(consume);
        child.stdout!.on("data", chunk => stdout.feed(chunk));
        child.stderr!.on("data", chunk => stderr.feed(chunk));
        const outcome = await new Promise<string>(resolve => {
          child.once("spawn", () => setJobState(job, "running"));
          child.once("error", error => resolve(`spawn 失败：${errorMessage(error)}`));
          child.once("close", (code, signal) => resolve(`退出码=${code ?? "null"}，signal=${signal ?? "none"}`));
        });
        stdout.end(); stderr.end(); children.delete(child);
        setJobState(job, "stopped"); invalidateJob(job);
        if (abort.signal.aborted) break;
        job.state.restarts++;
        consecutiveFailures = Date.now() - spawnTime > 60000 ? 1 : consecutiveFailures + 1;
        const backoff = Math.min(30000, (options.backoffBaseMs ?? 1000) * 2 ** Math.min(5, consecutiveFailures - 1));
        job.state.lastError = `${job.key} ${outcome}；${Math.ceil(backoff / 1000)} 秒后重试。`;
        setJobState(job, "backoff"); logger!.write(job.state.lastError);
        await delay(backoff, abort.signal);
      }
    };

    const lastNotices = new Map<string, string>();
    // A helper also prevents TypeScript from assuming a mutable phase cannot
    // change across an await when /stop is handled by another callback.
    const monitorStopped = () => abort.signal.aborted || status.phase === "stopping";
    const monitorNode = async (node: NodeConfig) => {
      const state = nodeStates.get(node.id)!;
      const core = status.cores[nodeEngine(node)]!;
      const generation = core.restarts;
      let listening = false;
      if (core.state === "running") {
        const probes = await Promise.all(nodeListenNetworks(node).map(network => network === "tcp" ? daemonProbeTcp(node.port, node.listen) : daemonProbeUdp(node.port, node.listen)));
        listening = probes.every(Boolean) && core.state === "running" && core.restarts === generation;
      }
      if (monitorStopped()) return;
      listenerCounts.set(node.id, listening ? (listenerCounts.get(node.id) ?? 0) + 1 : 0);
      state.listenerReady = (listenerCounts.get(node.id) ?? 0) >= 2;
      state.directReady = node.direct && state.listenerReady;
      const tunnel = tunnelJobs.get(node.id);
      let tunnelHealthy = false;
      if (tunnel?.state.state === "running" && state.listenerReady && state.domain) {
        const tunnelGeneration = tunnel.state.restarts;
        try {
          const response = await daemonLocalRequest(metricsPorts.get(node.id)!, "/ready", 900);
          tunnelHealthy = response.status === 200 && tunnel.state.state === "running" && tunnel.state.restarts === tunnelGeneration && core.state === "running" && core.restarts === generation;
        } catch { /* Another node's healthy routes remain usable while this one retries. */ }
      }
      if (monitorStopped()) return;
      // A core may exit while its tunnel /ready request is in flight. Never
      // resurrect that generation's direct links after the exit handler cleared them.
      if (core.state !== "running" || core.restarts !== generation) {
        listenerCounts.set(node.id, 0); state.listenerReady = false; state.directReady = false;
        tunnelHealthy = false;
      }
      tunnelCounts.set(node.id, tunnelHealthy ? (tunnelCounts.get(node.id) ?? 0) + 1 : 0);
      state.tunnelReady = Boolean(tunnel) && (tunnelCounts.get(node.id) ?? 0) >= 2;
      const allReady = state.listenerReady && (!node.direct || state.directReady) && (!tunnel || state.tunnelReady);
      state.phase = allReady ? "ready" : state.directReady || state.tunnelReady || core.restarts > 0 || (tunnel?.state.restarts ?? 0) > 0 || Date.now() - Date.parse(startedAt) > 20000 ? "degraded" : "starting";
      const exportNode = { ...node, ...clientMetadata.get(node.id) };
      state.links = generateNodeLinks(exportNode, state.domain ?? undefined).filter(link => link.via === "direct" ? state.directReady : state.tunnelReady);
      state.lastError = allReady ? null : !state.listenerReady ? core.lastError ?? "本地核心监听尚未就绪。" : tunnel?.state.lastError ?? "Cloudflare 隧道尚未连接，或尚未取得临时域名。";
      state.detail = state.listenerReady
        ? `${state.listenerCheck.includes("udp") ? "已确认核心持续运行和 UDP 端口占用" + (state.listenerCheck === "tcp+udp" ? "、TCP 监听" : "") : "已确认本地 TCP 监听"}；尚未验证公网可达性或客户端协议握手。`
        : "等待所需的本地监听；进程存在本身不代表节点已就绪。";
      const exportErrors = state.links.flatMap(link => link.error ? [link.error] : []);
      if (exportErrors.length) state.detail += ` ${exportErrors.join(" ")}`;
      if (state.tunnelReady && tunnel) tunnel.state.lastError = null;
      for (const link of state.links) {
        const noticeId = `${node.id}:${link.via}`;
        // A direct path becoming ready is one event for this running config.
        // Remember it even if its public address is still missing: later client
        // metadata edits update exports without sending additional notifications.
        // Quick Tunnel hostname changes retain their original notification event.
        const noticeKey = `${runtime.configHash}:${link.via === "direct" ? "direct-ready" : link.uri}`;
        if (lastNotices.get(noticeId) === noticeKey) continue;
        if (link.via === "tunnel" && (!link.uri || link.error)) continue;
        lastNotices.set(noticeId, noticeKey);
        if (link.uri && !link.error) {
          void daemonNotify(config, link.via === "tunnel" ? state.domain! : exportNode.address, link.uri, logger!);
        }
      }
    };
    const monitor = async () => {
      while (!abort.signal.aborted) {
        refreshClientMetadata();
        await Promise.all(enabled.map(monitorNode));
        if (abort.signal.aborted || status.phase === "stopping") break;
        const active = status.nodes.filter(node => node.enabled);
        status.phase = active.every(node => node.phase === "ready") ? "ready" : active.some(node => node.phase === "degraded" || node.directReady || node.tunnelReady) ? "degraded" : "starting";
        status.lastError = active.find(node => node.phase !== "ready" && node.lastError)?.lastError ?? null;
        for (const engine of engines) if (active.filter(node => node.engine === engine).every(node => node.listenerReady)) status.cores[engine]!.lastError = null;
        publishLinks();
        await delay(options.healthIntervalMs ?? 1000, abort.signal);
      }
    };
    for (const promise of [...jobs.map(supervise), monitor()]) loops.push(promise.catch(error => { fatalError = error; logger!.write(`守护异常：${errorMessage(error)}`); requestStop(); }));
    await stopPromise;
    status.phase = "stopping"; status.links = [];
    for (const node of status.nodes) if (node.enabled) { node.phase = "stopping"; node.links = []; }
    publishLinks();
    logger.write("正在关闭所有本实例的核心、隧道与控制通道。");
  } finally {
    try {
      requestStop();
      // EOF on each host's stdin is its liveness signal. Hosts own and await their cores.
      for (const child of children) { try { child.stdin?.end(); } catch { /* Already exited. */ } }
      await daemonSettleWithin(loops, 12000);
      if (children.size) {
        for (const child of children) child.kill("SIGTERM");
        await daemonSettleWithin(loops, 3000);
      }
      if (server) await server.stop(true);
      const record = readRuntimeRecord(paths);
      if (record?.instanceId === instanceId) {
        daemonFs.rmSync(paths.runtimeState, { force: true });
        daemonFs.rmSync(paths.link, { force: true });
      }
      daemonFs.rmSync(runDirectory, { recursive: true, force: true });
      process.removeListener("SIGINT", signalStop);
      process.removeListener("SIGTERM", signalStop);
      logger?.write("后台实例已停止。");
    } finally { releaseLock(); }
  }
  if (fatalError) throw fatalError;
}

/**
 * A tiny core host keeps an open pipe to the supervisor. Even SIGKILL of the
 * supervisor closes that pipe, so the host terminates the core it owns.
 * This also avoids reliance on PID files when stopping a Windows child.
 */
export async function runCoreHost(executable: string, args: string[]): Promise<number> {
  if (!executable || !daemonPath.isAbsolute(executable)) throw new Error("core-host 需要绝对可执行文件路径。");
  const child = daemonCp.spawn(executable, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let stopping = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const cleanup = () => {
    if (stopping) return;
    stopping = true;
    child.kill("SIGTERM");
    killTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }, 6000);
    killTimer.unref();
  };
  const outputError = () => cleanup();
  process.stdout.on("error", outputError); process.stderr.on("error", outputError);
  process.stdin.on("end", cleanup); process.stdin.on("close", cleanup); process.stdin.on("error", cleanup);
  process.on("SIGINT", cleanup); process.on("SIGTERM", cleanup);
  process.stdin.resume();
  child.stdout!.pipe(process.stdout, { end: false });
  child.stderr!.pipe(process.stderr, { end: false });
  const code = await new Promise<number>(resolve => {
    child.once("error", e => { try { process.stderr.write(`core spawn: ${errorMessage(e)}\n`); } catch {} resolve(1); });
    child.once("close", value => resolve(stopping ? 0 : (value ?? 1)));
  });
  if (killTimer) clearTimeout(killTimer);
  process.stdin.pause();
  process.stdin.removeListener("end", cleanup); process.stdin.removeListener("close", cleanup); process.stdin.removeListener("error", cleanup);
  process.removeListener("SIGINT", cleanup); process.removeListener("SIGTERM", cleanup);
  process.stdout.removeListener("error", outputError); process.stderr.removeListener("error", outputError);
  return code;
}
