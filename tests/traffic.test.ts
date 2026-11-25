import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, symlinkSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPaths, createDefaultNode, defaultConfig, type AppPaths } from "../src/core.ts";
import { buildSingBoxConfig, buildXrayConfig } from "../src/network.ts";
import { parseXrayTraffic, parseSingTraffic, trafficReadProto, withTrafficInstrumentation, type TrafficSnapshot } from "../src/traffic-core.ts";
import { TrafficStore, readTrafficReport, trafficDatabasePath, TRAFFIC_BUCKET_MS, TRAFFIC_RETENTION_MS } from "../src/traffic-store.ts";
import { startTrafficDashboard, trafficDashboardJs } from "../src/traffic-web.ts";
import { Database } from "bun:sqlite";

const roots: string[] = [], stores: TrafficStore[] = [], dashboards: ReturnType<typeof startTrafficDashboard>[] = [];
afterEach(async () => { for (const dashboard of dashboards.splice(0)) await dashboard.close(); for (const store of stores.splice(0)) store.close(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function environment(): { paths: AppPaths; store: TrafficStore } {
  const root = mkdtempSync(join(tmpdir(), "nexus-traffic-test-")); roots.push(root);
  const paths = createPaths(join(root, "app.ts")), store = new TrafficStore(paths); stores.push(store); return { paths, store };
}
const now = 1800000000000;
function frame(up: number, down: number, id: string): TrafficSnapshot { return { up, down, nodes: [{ id, up, down }], connections: [], peers: [], peersAvailable: true }; }
function varint(n: bigint): Buffer { const bytes: number[] = []; do { bytes.push(Number(n & 127n) | (n > 127n ? 128 : 0)); n >>= 7n; } while (n); return Buffer.from(bytes); }
function field(id: number, value: string | number | Buffer | bigint): Buffer {
  if (typeof value === "number" || typeof value === "bigint") return Buffer.concat([varint(BigInt(id * 8)), varint(BigInt(value))]);
  const bytes = typeof value === "string" ? Buffer.from(value) : value;
  return Buffer.concat([varint(BigInt(id * 8 + 2)), varint(BigInt(bytes.length)), bytes]);
}
function stat(id: string, direction: string, value: number | bigint): Buffer { return field(1, Buffer.concat([field(1, `user>>>nexus:${id}>>>traffic>>>${direction}`), field(2, value)])); }

test("instrumentation is loopback-only and never changes stored credentials or original generated config", () => {
  const config = defaultConfig(); config.nodes = [createDefaultNode("vless"), createDefaultNode("socks")];
  const before = JSON.stringify(config), endpoint = { port: 34567, secret: "a".repeat(64) };
  const xray = buildXrayConfig(config) as any, sing = buildSingBoxConfig(config) as any;
  const instrumented = withTrafficInstrumentation(xray, "xray", endpoint) as any;
  expect(instrumented.api).toEqual({ tag: "nexus-traffic-api", services: ["StatsService"] });
  expect(instrumented.inbounds.at(-1)).toMatchObject({ listen: "127.0.0.1", port: 34567, protocol: "socks", settings: { auth: "password" } });
  expect(instrumented.routing.rules[0]).toMatchObject({ inboundTag: ["nexus-traffic"], outboundTag: "nexus-traffic-api" });
  expect(instrumented.inbounds[0].settings.clients[0].email).toBe(`nexus:${config.nodes[0]!.id}`);
  expect(xray.api).toBeUndefined(); expect(sing.services).toBeUndefined();
  const api = (withTrafficInstrumentation(sing, "singBox", endpoint) as any).services[0];
  expect(api.listen).toBe("127.0.0.1"); expect(api.secret).toBe(endpoint.secret); expect(api.dashboard).toBeUndefined();
  expect(JSON.stringify(config)).toBe(before);
  expect(() => withTrafficInstrumentation(xray, "xray", { ...endpoint, port: 0 })).toThrow();
});
test("Xray parser separates known nodes and directions, ignores unrelated counts, rejects duplicate/overflow", () => {
  const bytes = Buffer.concat([stat("443", "uplink", 327300000000), stat("443", "downlink", 400), stat("8943", "downlink", 800), stat("unknown", "uplink", 999)]);
  const parsed = parseXrayTraffic(bytes, ["443", "8943"]);
  expect(parsed.up).toBe(327300000000); expect(parsed.down).toBe(1200); expect(parsed.nodes[1]!.down).toBe(800);
  expect(() => parseXrayTraffic(Buffer.concat([stat("443", "uplink", 1), stat("443", "uplink", 2)]), ["443"])).toThrow("重复");
  expect(() => parseXrayTraffic(stat("443", "uplink", 2n ** 63n), ["443"])).toThrow("安全");
});
test("bounded protobuf reader rejects truncation, malformed wire types and huge messages", () => {
  for (const bytes of [Buffer.from([10, 8, 1]), Buffer.from([0]), Buffer.from([15]), Buffer.alloc(11, 128), Buffer.alloc(8 * 1024 * 1024 + 1)]) expect(() => trafficReadProto(bytes)).toThrow();
});
test("sing-box snapshot keeps only managed node counters and IP, strips destinations, domains and users", () => {
  const connection = Buffer.concat([field(1, "a".repeat(8) + "-" + "a".repeat(27)), field(2, "node:1"), field(6, "[::1]:1234"), field(7, "secret-destination:443"), field(8, "secret.example"), field(10, "secret-user"), field(13, now), field(16, 100), field(17, 200)]);
  const data = Buffer.concat([field(2, 1), field(1, field(3, connection))]);
  const result = parseSingTraffic(Buffer.concat([field(5, 1), field(8, 100), field(9, 200)]), data, ["1"]);
  expect(result.connections[0]).toMatchObject({ ip: "::1", nodeId: "1", up: 100, down: 200, closed: true });
  expect(JSON.stringify(result)).not.toContain("secret");
  expect(() => parseSingTraffic(Buffer.alloc(0), data, ["1"])).toThrow("快照");
});
test("empty dashboard reads do not create configuration or database", () => {
  const root = mkdtempSync(join(tmpdir(), "nexus-traffic-empty-")); roots.push(root); const paths = createPaths(join(root, "app.ts"));
  expect(readTrafficReport(paths).oldest).toBeNull(); expect(existsSync(paths.data)).toBe(false);
  expect(() => readTrafficReport(paths, "__proto__" as any)).toThrow();
});
test("cumulative samples count deltas once, keep 443/8943 separate, and survive database reopen", () => {
  const { paths, store } = environment(), a = createDefaultNode("vless"), b = createDefaultNode("vless"); a.port = 443; b.port = 8943;
  const first = { ...frame(100, 200, a.id), nodes: [{ id: a.id, up: 60, down: 150 }, { id: b.id, up: 40, down: 50 }] };
  store.apply("xray", "one", [a, b], first, now); store.apply("xray", "one", [a, b], first, now + 10000);
  const second = { ...frame(150, 250, a.id), nodes: [{ id: a.id, up: 110, down: 200 }, { id: b.id, up: 40, down: 50 }] };
  store.apply("xray", "one", [a, b], second, now + 20000);
  const result = readTrafficReport(paths, "24h", now + 20000);
  expect(result.cores[0]).toMatchObject({ up: 150, down: 250 });
  expect(result.nodes.find(n => n.port === 8943)).toMatchObject({ up: 40, down: 50 });
  expect(result.status[0].upRate).toBe(5);
  expect(existsSync(paths.config)).toBe(false);
  store.close(); stores.splice(stores.indexOf(store), 1);
  const reopened = new TrafficStore(paths); stores.push(reopened);
  expect(readTrafficReport(paths, "24h", now + 20000).cores).toEqual(result.cores);
});
test("restart or counter reset adds only the new cycle, does not subtract historical bytes", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(1000, 2000, node.id), now);
  store.apply("xray", "two", [node], frame(30, 40, node.id), now + 10000);
  store.apply("xray", "two", [node], frame(5, 6, node.id), now + 20000);
  const result = readTrafficReport(paths, "24h", now + 20000);
  expect(result.cores[0]).toMatchObject({ up: 1035, down: 2046 }); expect(result.events.some(e => e.code === "reset")).toBe(true);
});
test("resetting one Xray inbound never recounts or hides traffic on the other inbound", () => {
  const { paths, store } = environment(), a = createDefaultNode("vless"), b = createDefaultNode("vless");
  store.apply("xray", "one", [a, b], { ...frame(3000, 0, a.id), nodes: [{ id: a.id, up: 1000, down: 0 }, { id: b.id, up: 2000, down: 0 }] }, now);
  store.apply("xray", "one", [a, b], { ...frame(3020, 0, a.id), nodes: [{ id: a.id, up: 10, down: 0 }, { id: b.id, up: 3010, down: 0 }] }, now + 10000);
  const result = readTrafficReport(paths, "24h", now + 10000); expect(result.cores[0].up).toBe(4020); expect(result.events.some(e => e.code === "reset")).toBe(true);
});
test("API outage preserves baselines and history, recovery marks catch-up instead of inventing rates", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(100, 200, node.id), now);
  store.unavailable("xray", "one", now + 10000); store.unavailable("xray", "one", now + 20000);
  expect(readTrafficReport(paths, "24h", now + 20000).status[0].state).toBe("unavailable");
  store.apply("xray", "one", [node], frame(400, 600, node.id), now + 120000);
  const result = readTrafficReport(paths, "24h", now + 120000);
  expect(result.cores[0]).toMatchObject({ up: 400, down: 600 }); expect(result.status[0].upRate).toBeNull();
  expect(result.events.filter(e => e.code === "unavailable")).toHaveLength(1); expect(result.events.some(e => e.code === "gap")).toBe(true);
  expect(readTrafficReport(paths, "24h", now + 160000).status[0].state).toBe("stale");
});
test("port changes retain their historical port labels", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless"); node.port = 443;
  store.apply("xray", "one", [node], frame(100, 200, node.id), now);
  const changed = { ...node, port: 8943 };
  store.apply("xray", "two", [changed], frame(30, 40, node.id), now + 10000);
  expect(readTrafficReport(paths, "24h", now + 10000).nodes.map(n => n.port).sort()).toEqual([443, 8943].sort());
});
test("sing-box closed-connection replay is deduplicated and unobserved core bytes stay unattributed", () => {
  const { paths, store } = environment(), node = createDefaultNode("socks");
  const first: TrafficSnapshot = { ...frame(1000, 2000, node.id), nodes: [], connections: [{ id: "connection", nodeId: node.id, ip: "192.0.2.1", up: 200, down: 300, closed: true }] };
  store.apply("singBox", "one", [node], first, now); store.apply("singBox", "one", [node], first, now + 10000);
  const result = readTrafficReport(paths, "24h", now + 10000);
  expect(result.cores[0]).toMatchObject({ up: 1000, down: 2000 }); expect(result.nodes[0]).toMatchObject({ up: 200, down: 300, quality: "observed" });
  expect(result.peers[0]).toMatchObject({ ip: "192.0.2.1", up: 200, down: 300, lastSeen: now });
});
test("Xray IP presence is assigned to actual seen time and never claims per-IP byte counts", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  const sample = frame(500, 600, node.id); sample.peers = [{ nodeId: node.id, ip: "192.0.2.1", seenAt: now - 2 * 86400_000 }];
  store.apply("xray", "one", [node], sample, now);
  expect(readTrafficReport(paths, "24h", now).peers).toHaveLength(0);
  expect(readTrafficReport(paths, "7d", now).peers[0]).toMatchObject({ quality: "presence", up: 0, down: 0 });
});
test("failed samples do not advance baselines or corrupt totals", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(100, 200, node.id), now);
  expect(() => store.apply("xray", "one", [node], frame(Number.NaN, 1000, node.id), now + 10000)).toThrow();
  store.apply("xray", "one", [node], frame(300, 400, node.id), now + 20000);
  expect(readTrafficReport(paths, "24h", now + 20000).cores[0]).toMatchObject({ up: 300, down: 400 });
});
test("SQLite write failure rolls back rollups and preserves the next retry's delta", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(100, 200, node.id), now);
  const db = new Database(trafficDatabasePath(paths));
  db.exec("CREATE TRIGGER reject_sample BEFORE INSERT ON buckets BEGIN SELECT RAISE(FAIL, 'synthetic write failure'); END");
  expect(() => store.apply("xray", "one", [node], frame(300, 400, node.id), now + 10000)).toThrow();
  expect(readTrafficReport(paths, "24h", now + 10000).cores[0].up).toBe(100);
  db.exec("DROP TRIGGER reject_sample"); db.close();
  store.apply("xray", "one", [node], frame(300, 400, node.id), now + 20000);
  expect(readTrafficReport(paths, "24h", now + 20000).cores[0]).toMatchObject({ up: 300, down: 400 });
});
test("retention removes expired history and incompatible/corrupt databases are not replaced", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(100, 200, node.id), now - TRAFFIC_RETENTION_MS - 2 * TRAFFIC_BUCKET_MS);
  store.apply("xray", "two", [node], frame(30, 40, node.id), now);
  expect(readTrafficReport(paths, "30d", now).cores[0]).toMatchObject({ up: 30, down: 40 });
  store.close(); stores.splice(stores.indexOf(store), 1);
  const db = new Database(trafficDatabasePath(paths)); db.exec("PRAGMA user_version=99"); db.close();
  const before = readFileSync(trafficDatabasePath(paths)); expect(() => new TrafficStore(paths)).toThrow("不兼容"); expect(readFileSync(trafficDatabasePath(paths))).toEqual(before);
  writeFileSync(trafficDatabasePath(paths), "damaged"); expect(() => readTrafficReport(paths)).toThrow(); expect(readFileSync(trafficDatabasePath(paths), "utf8")).toBe("damaged");
});
test("unversioned foreign SQLite data is rejected without changing the file", () => {
  const { paths, store } = environment(); store.close(); stores.splice(stores.indexOf(store), 1);
  rmSync(trafficDatabasePath(paths));
  const db = new Database(trafficDatabasePath(paths)); db.exec("CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated VALUES ('preserve')"); db.close();
  const before = readFileSync(trafficDatabasePath(paths));
  expect(() => new TrafficStore(paths)).toThrow("不兼容"); expect(readFileSync(trafficDatabasePath(paths))).toEqual(before);
});
test("capacity pressure prunes older buckets before accepting a new atomic sample", () => {
  const { paths, store } = environment(), node = createDefaultNode("vless");
  store.apply("xray", "one", [node], frame(100, 200, node.id), now);
  const db = new Database(trafficDatabasePath(paths));
  const key = db.query("SELECT key FROM dimensions WHERE kind='node'").get() as { key: string };
  db.query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<200000) INSERT OR IGNORE INTO buckets SELECT ?-i,?,0,0,? FROM n").run(now, key.key, now);
  store.apply("xray", "one", [node], frame(300, 400, node.id), now + TRAFFIC_BUCKET_MS);
  expect((db.query("SELECT COUNT(*) n FROM buckets").get() as { n: number }).n).toBeLessThanOrEqual(200000); db.close();
  expect(readTrafficReport(paths, "24h", now + TRAFFIC_BUCKET_MS).events.some(e => e.code === "retention-limit")).toBe(true);
});
(process.platform === "win32" ? test.skip : test)("database files are private and symbolic-link substitution is refused", () => {
  const { paths, store } = environment(); expect(statSync(trafficDatabasePath(paths)).mode & 0o777).toBe(0o600);
  store.close(); stores.splice(stores.indexOf(store), 1); rmSync(trafficDatabasePath(paths));
  const target = join(paths.root, "external"); writeFileSync(target, "preserve"); symlinkSync(target, trafficDatabasePath(paths));
  expect(() => new TrafficStore(paths)).toThrow("链接"); expect(readFileSync(target, "utf8")).toBe("preserve");
});
test("dashboard enforces per-session authorization, Host/Origin, methods, routes and read-only ranges", async () => {
  const { paths, store } = environment(), node = createDefaultNode("vless"); node.name = '<img src=x onerror="alert(1)">';
  store.apply("xray", "one", [node], frame(123, 456, node.id));
  const dashboard = startTrafficDashboard(paths); dashboards.push(dashboard);
  const url = new URL(dashboard.url), base = url.origin, headers = { Authorization: `Bearer ${url.hash.slice(1)}` };
  const page = await fetch(base); expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  const html = await page.text(); expect(html).toContain("流量分析"); expect(html).not.toContain(url.hash.slice(1)); expect(html).not.toContain(node.name);
  expect((await fetch(base + "/api/report")).status).toBe(403);
  expect((await fetch(base + "/api/report", { headers: { ...headers, Origin: "https://evil.invalid" } })).status).toBe(403);
  expect((await fetch(base + "/api/report", { headers: { ...headers, Host: "evil.invalid" } })).status).toBe(403);
  expect((await fetch(base + "/api/report", { method: "POST", headers })).status).toBe(405);
  expect((await fetch(base + "/api/report?range=constructor", { headers })).status).toBe(400);
  expect((await fetch(base + "/config.json", { headers })).status).toBe(404);
  const response = await fetch(base + "/api/report?range=24h", { headers }); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
  const data = await response.json() as any; expect(data.report.cores[0].up).toBe(123); expect(JSON.stringify(data)).not.toContain(node.password); expect(JSON.stringify(data)).not.toContain(node.uuid);
  expect(trafficDashboardJs).not.toMatch(/innerHTML|document\.write|eval\(/);
  await dashboard.close(); await expect(fetch(base)).rejects.toThrow();
});
test("dashboard lifetime expires without leaving a listener", async () => {
  const { paths } = environment(), dashboard = startTrafficDashboard(paths, { lifetimeMs: 20 }); dashboards.push(dashboard);
  await Bun.sleep(40); await expect(fetch(new URL(dashboard.url).origin)).rejects.toThrow();
});
