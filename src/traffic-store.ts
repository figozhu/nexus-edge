import * as trafficStoreFs from "node:fs";
import * as trafficStorePath from "node:path";
import * as trafficSqlite from "bun:sqlite";
import { type AppPaths, type CoreName, type NodeConfig, ensureDataDir } from "./core.ts";
import { type TrafficSnapshot } from "./traffic-core.ts";

export const TRAFFIC_INTERVAL_MS = 10_000;
export const TRAFFIC_BUCKET_MS = 300_000;
export const TRAFFIC_RETENTION_MS = 30 * 86400_000;
export const TRAFFIC_RANGES = { "1h": 3600_000, "24h": 86400_000, "7d": 7 * 86400_000, "30d": TRAFFIC_RETENTION_MS } as const;
export type TrafficRange = keyof typeof TRAFFIC_RANGES;
type TrafficDimension = { key: string; kind: "core" | "node" | "peer"; engine: CoreName; nodeId: string; name: string; port: number; protocol: string; ip: string; quality: string };
type TrafficBaseline = { generation: string; at: number; up: number; down: number; nodes: Map<string, { up: number; down: number }>; connections: Map<string, { up: number; down: number; seen: number }> };
export interface TrafficReport {
  now: number; from: number; oldest: number | null; range: TrafficRange; bucketMs: number; retentionDays: number;
  cores: any[]; nodes: any[]; peers: any[]; series: any[]; status: any[]; events: any[]; limited: boolean;
}

export function trafficDatabasePath(paths: AppPaths): string { return trafficStorePath.join(paths.data, "traffic.sqlite"); }
function trafficCheckDatabase(paths: AppPaths): void {
  if (trafficStoreFs.existsSync(paths.data) && trafficStoreFs.lstatSync(paths.data).isSymbolicLink()) throw new Error("统计数据目录不能是符号链接。");
  for (const suffix of ["", "-wal", "-shm"]) {
    const filename = trafficDatabasePath(paths) + suffix;
    try { const stat = trafficStoreFs.lstatSync(filename); if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("统计数据库不能是链接或特殊文件。"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
}
function trafficSafeCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("统计计数不在安全范围内。");
  return value;
}
function trafficNodeDimension(engine: CoreName, node: NodeConfig): TrafficDimension {
  return { key: `${engine}:${node.id}:${node.port}`, kind: "node", engine, nodeId: node.id, name: node.name, port: node.port, protocol: node.protocol, ip: "", quality: engine === "xray" ? "counter" : "observed" };
}

/** Single worker writes; read-only panels never reset counters. SQLite commits a sample and its rollups atomically. */
export class TrafficStore {
  private db: trafficSqlite.Database;
  private baselines = new Map<CoreName, TrafficBaseline>();
  private lastPrune = 0;
  constructor(paths: AppPaths) {
    ensureDataDir(paths); trafficCheckDatabase(paths);
    this.db = new trafficSqlite.Database(trafficDatabasePath(paths), { create: true });
    try {
      const version = (this.db.query("PRAGMA user_version").get() as { user_version: number }).user_version;
      if (version !== 0 && version !== 1) throw new Error("统计数据库版本不兼容，原文件保持不变。");
      if (version === 0 && this.db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1").get()) throw new Error("统计数据库格式不兼容，原文件保持不变。");
      this.db.exec("PRAGMA busy_timeout=1500; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;");
      this.db.exec(`CREATE TABLE IF NOT EXISTS dimensions (key TEXT PRIMARY KEY, kind TEXT NOT NULL, engine TEXT NOT NULL, nodeId TEXT NOT NULL, name TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL, ip TEXT NOT NULL, quality TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS buckets (bucket INTEGER NOT NULL, key TEXT NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY(bucket,key));
        CREATE TABLE IF NOT EXISTS status (engine TEXT PRIMARY KEY, generation TEXT NOT NULL, lastSeen INTEGER NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL, peersAvailable INTEGER NOT NULL, upRate REAL, downRate REAL);
        CREATE TABLE IF NOT EXISTS events (at INTEGER NOT NULL, engine TEXT NOT NULL, code TEXT NOT NULL);
        PRAGMA user_version=1;`);
      if (process.platform !== "win32") for (const suffix of ["", "-wal", "-shm"]) if (trafficStoreFs.existsSync(trafficDatabasePath(paths) + suffix)) trafficStoreFs.chmodSync(trafficDatabasePath(paths) + suffix, 0o600);
    } catch (error) { this.db.close(); throw error; }
  }
  close(): void { this.db.close(); }
  stopped(): void { this.db.query("UPDATE status SET state='stopped',upRate=NULL,downRate=NULL").run(); }
  unavailable(engine: CoreName, generation: string, now = Date.now()): void {
    const old = this.db.query("SELECT state FROM status WHERE engine=?").get(engine) as { state: string } | null;
    this.db.transaction(() => {
      if (old?.state !== "unavailable") this.db.query("INSERT INTO events VALUES (?,?,?)").run(now, engine, "unavailable");
      this.db.query("INSERT INTO status VALUES (?,?,0,'unavailable',?,0,NULL,NULL) ON CONFLICT(engine) DO UPDATE SET state='unavailable',detail=excluded.detail,upRate=NULL,downRate=NULL")
        .run(engine, generation, "统计接口暂不可用或不受此核心版本支持；历史记录保留，节点运行不受影响。");
    })();
  }
  apply(engine: CoreName, generation: string, nodes: NodeConfig[], sample: TrafficSnapshot, now = Date.now()): void {
    trafficSafeCount(now); trafficSafeCount(sample.up); trafficSafeCount(sample.down);
    const old = this.baselines.get(engine);
    const same = old?.generation === generation;
    const reset = Boolean(same && engine === "singBox" && (sample.up < old.up || sample.down < old.down));
    const previous = same && !reset ? old : undefined;
    // Work on a copy; failures must not advance any baseline or lose a later retry's bytes.
    const next: TrafficBaseline = { generation, at: now, up: sample.up, down: sample.down, nodes: new Map(previous?.nodes), connections: new Map(previous?.connections) };
    const nodeMap = new Map(nodes.map(n => [n.id, trafficNodeDimension(engine, n)]));
    const bucket = Math.floor(now / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS;
    let up = engine === "xray" ? 0 : sample.up - (previous?.up ?? 0), down = engine === "xray" ? 0 : sample.down - (previous?.down ?? 0), nodeReset = false;
    const increments: { dimension: TrafficDimension; up: number; down: number; seen: number }[] = [];
    let limited = false;
    const add = (dimension: TrafficDimension, up: number, down: number, seen = now) => increments.push({ dimension, up: trafficSafeCount(up), down: trafficSafeCount(down), seen });
    for (const counter of sample.nodes) {
      const dimension = nodeMap.get(counter.id); if (!dimension) continue;
      trafficSafeCount(counter.up); trafficSafeCount(counter.down);
      const baseline = previous?.nodes.get(counter.id);
      const du = counter.up - (baseline && baseline.up <= counter.up ? baseline.up : 0), dd = counter.down - (baseline && baseline.down <= counter.down ? baseline.down : 0);
      if (baseline && (baseline.up > counter.up || baseline.down > counter.down)) nodeReset = true;
      add(dimension, du, dd);
      if (engine === "xray") { up = trafficSafeCount(up + du); down = trafficSafeCount(down + dd); }
      next.nodes.set(counter.id, { up: counter.up, down: counter.down });
    }
    add({ key: `core:${engine}`, kind: "core", engine, nodeId: "", name: engine === "xray" ? "Xray" : "sing-box", port: 0, protocol: "", ip: "", quality: "counter" }, up, down);
    for (const c of sample.connections) {
      const dimension = nodeMap.get(c.nodeId); if (!dimension) continue;
      trafficSafeCount(c.up); trafficSafeCount(c.down);
      const baseline = next.connections.get(c.id);
      if (!baseline && next.connections.size >= 50000) { limited = true; continue; }
      // A connection's cumulative counters must never decrease within a core generation.
      if (baseline && (c.up < baseline.up || c.down < baseline.down)) { limited = true; continue; }
      const du = c.up - (baseline?.up ?? 0), dd = c.down - (baseline?.down ?? 0);
      // The API replays its closed-session cache. A replay is not new activity.
      if (!c.closed || du || dd) {
        const seen = c.closed && c.closedAt ? Math.min(trafficSafeCount(c.closedAt), now) : now;
        add(dimension, du, dd, seen);
        if (c.ip) add({ ...dimension, key: `${dimension.key}:${c.ip}`, kind: "peer", ip: c.ip }, du, dd, seen);
      }
      next.connections.set(c.id, { up: c.up, down: c.down, seen: now });
    }
    for (const p of sample.peers) {
      const dimension = nodeMap.get(p.nodeId);
      if (dimension && p.seenAt <= now + 60000 && p.seenAt >= now - TRAFFIC_RETENTION_MS) add({ ...dimension, key: `${dimension.key}:${p.ip}`, kind: "peer", ip: p.ip, quality: "presence" }, 0, 0, p.seenAt);
    }
    for (const [id, c] of next.connections) if (now - c.seen > 3600_000) next.connections.delete(id);
    const elapsed = previous ? now - previous.at : 0;
    const rateKnown = elapsed > 0 && elapsed <= TRAFFIC_INTERVAL_MS * 3;
    this.db.transaction(() => {
      const maintenance = now - this.lastPrune > 3600_000;
      if (maintenance) {
        this.db.query("DELETE FROM buckets WHERE bucket<?").run(now - TRAFFIC_RETENTION_MS);
        this.db.query("DELETE FROM events WHERE at<?").run(now - TRAFFIC_RETENTION_MS);
        this.db.query("DELETE FROM events WHERE rowid NOT IN (SELECT rowid FROM events ORDER BY at DESC LIMIT 1000)").run();
      }
      const count = (this.db.query("SELECT COUNT(*) n FROM buckets").get() as { n: number }).n;
      const excess = count + increments.length - 200000;
      if (excess > 0) {
        this.db.query("DELETE FROM buckets WHERE rowid IN (SELECT rowid FROM buckets ORDER BY bucket LIMIT ?)").run(excess);
        this.db.query("INSERT INTO events VALUES (?,?,?)").run(now, engine, "retention-limit");
      }
      if (maintenance || excess > 0) this.db.query("DELETE FROM dimensions WHERE key NOT IN (SELECT key FROM buckets)").run();
      const putDimension = this.db.query("INSERT INTO dimensions VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET name=excluded.name");
      for (const d of nodeMap.values()) putDimension.run(d.key, d.kind, d.engine, d.nodeId, d.name, d.port, d.protocol, d.ip, d.quality);
      for (const { dimension: d, up, down, seen } of increments) {
        putDimension.run(d.key, d.kind, d.engine, d.nodeId, d.name, d.port, d.protocol, d.ip, d.quality);
        this.db.query("INSERT INTO buckets VALUES (?,?,?,?,?) ON CONFLICT(bucket,key) DO UPDATE SET up=up+excluded.up,down=down+excluded.down,seen=MAX(seen,excluded.seen)").run(d.quality === "presence" ? Math.floor(seen / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS : bucket, d.key, up, down, seen);
      }
      if (!same) this.db.query("INSERT INTO events VALUES (?,?,?)").run(now, engine, "generation");
      if (reset || nodeReset) this.db.query("INSERT INTO events VALUES (?,?,?)").run(now, engine, "reset");
      if (elapsed > TRAFFIC_INTERVAL_MS * 3 || elapsed < 0) this.db.query("INSERT INTO events VALUES (?,?,?)").run(now, engine, "gap");
      const detail = limited ? "连接归属达到容量限制；核心累计量仍采集，节点/来源明细可能遗漏。" : engine === "singBox" ? "核心累计量；节点/来源为已观察连接的下限，采集间隔内超过 1000 个短连接可能遗漏归属。" : "按节点账号累计计数；来源 IP 仅提供近期出现线索，不提供按 IP 的字节数。";
      this.db.query("INSERT OR REPLACE INTO status VALUES (?,?,?,'collecting',?,?,?,?)").run(engine, generation, now, detail, sample.peersAvailable ? 1 : 0, rateKnown ? up * 1000 / elapsed : null, rateKnown ? down * 1000 / elapsed : null);
    })();
    this.baselines.set(engine, next);
    if (now - this.lastPrune > 3600_000) this.lastPrune = now;
  }
}

/** Reads aggregate history without opening config.json or creating a database on first view. */
export function readTrafficReport(paths: AppPaths, range: TrafficRange = "24h", now = Date.now()): TrafficReport {
  if (!Object.hasOwn(TRAFFIC_RANGES, range)) throw new Error("无效的统计时间范围。");
  const from = Math.floor((now - TRAFFIC_RANGES[range]) / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS;
  const report: TrafficReport = { now, from, oldest: null, range, bucketMs: TRAFFIC_BUCKET_MS, retentionDays: 30, cores: [], nodes: [], peers: [], series: [], status: [], events: [], limited: false };
  if (!trafficStoreFs.existsSync(trafficDatabasePath(paths))) return report;
  trafficCheckDatabase(paths);
  const db = new trafficSqlite.Database(trafficDatabasePath(paths), { readonly: true });
  try {
    db.exec("PRAGMA busy_timeout=1500; PRAGMA query_only=ON;");
    if ((db.query("PRAGMA user_version").get() as { user_version: number }).user_version !== 1) throw new Error("统计数据库版本不兼容。");
    db.transaction(() => {
      report.oldest = (db.query("SELECT MIN(bucket) oldest FROM buckets").get() as { oldest: number | null }).oldest;
      for (const kind of ["core", "node", "peer"] as const) {
        const rows = db.query(`SELECT d.*,SUM(b.up) up,SUM(b.down) down,MAX(b.seen) lastSeen FROM buckets b JOIN dimensions d ON d.key=b.key WHERE b.bucket>=? AND b.bucket<=? AND d.kind=? GROUP BY d.key ORDER BY SUM(b.up)+SUM(b.down) DESC,lastSeen DESC LIMIT 501`).all(from, now, kind);
        report[kind === "core" ? "cores" : kind === "node" ? "nodes" : "peers"] = rows.slice(0, 500);
        if (rows.length > 500) report.limited = true;
      }
      const step = range === "1h" ? TRAFFIC_BUCKET_MS : range === "24h" ? 3600_000 : 86400_000;
      report.series = db.query(`SELECT (b.bucket / ?) * ? bucket,d.engine,SUM(b.up) up,SUM(b.down) down FROM buckets b JOIN dimensions d ON d.key=b.key WHERE b.bucket>=? AND b.bucket<=? AND d.kind='core' GROUP BY 1,d.engine ORDER BY 1`).all(step, step, from, now);
      report.status = db.query("SELECT * FROM status").all().map((row: any) => ({ ...row, state: row.state === "collecting" && (now - row.lastSeen > 30000 || row.lastSeen > now + 60000) ? "stale" : row.state }));
      report.events = db.query("SELECT at,engine,code FROM events WHERE at>=? ORDER BY at DESC LIMIT 50").all(from);
    })();
    return report;
  } finally { db.close(); }
}
