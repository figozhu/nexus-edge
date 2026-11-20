/** Terminal fixture: only synthetic temporary config; forbid network/process activity. */
import * as fixtureFs from "node:fs";
import * as fixturePath from "node:path";
import * as fixtureCrypto from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { createPaths, defaultConfig, createDefaultNode, ensureDataDir, writeConfig } from "../../src/core.ts";
import { runBackupPanel } from "../../src/backup-panel.ts";
import { UserCancelledError, UiExitRequestedError } from "../../src/ui.ts";

if (!fixturePath.basename(process.cwd()).startsWith("nexus-ui-pty-")) throw new Error("Temporary PTY directory required");
const paths = createPaths(fixturePath.join(process.cwd(), "nexus-edge.ts"));
ensureDataDir(paths);
const standalone = process.env.NEXUS_EDGE_PTY_STANDALONE === "1" ? await import("../../nexus-edge.ts") : undefined;
standalone?.ensureDataDir(paths);
const run = standalone?.runBackupPanel ?? runBackupPanel;
const Cancelled = standalone?.UserCancelledError ?? UserCancelledError;
const Exited = standalone?.UiExitRequestedError ?? UiExitRequestedError;
const require = createRequire(import.meta.url);
let forbidden = 0;
const deny = (): never => { forbidden++; throw new Error("Forbidden external activity"); };
globalThis.fetch = (async () => deny()) as unknown as typeof fetch;
for (const [name, methods] of [
  ["node:http", ["request", "get"]], ["node:https", ["request", "get"]],
  ["node:child_process", ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
] as const) for (const method of methods) require(name)[method] = deny;
require("node:net").Socket.prototype.connect = deny;
require("node:net").Server.prototype.listen = deny;
require("node:dgram").createSocket = deny;
Object.assign(Bun, { spawn: deny, spawnSync: deny, connect: deny, listen: deny, serve: deny });
syncBuiltinESMExports();
const node = createDefaultNode("shadowsocks"); node.address = "198.51.100.28";
writeConfig(paths, { ...defaultConfig(), nodes: [node] });
const scenario = process.argv[2];
function trace(event: string) {
  const bytes = fixtureFs.readFileSync(paths.config);
  const config = JSON.parse(bytes.toString());
  process.stdout.write(`\r\n__NEXUS_PTY__${JSON.stringify({ event, raw: Boolean(process.stdin.isRaw), stdinTTY: process.stdin.isTTY, stdoutTTY: process.stdout.isTTY, hash: fixtureCrypto.createHash("sha256").update(bytes).digest("hex"), enabled: config.nodes[0].enabled, address: config.nodes[0].address, forbidden })}\r\n`);
}
trace("start");
for (let round = 0; round < (scenario === "mismatch" || scenario === "running" ? 1 : 2); round++) {
  try { await run(paths, { running: async () => scenario === "running" }); trace(round === 0 ? "exported" : "imported"); }
  catch (error) {
    if (error instanceof Cancelled) trace("cancelled");
    else if (error instanceof Exited) trace("exited");
    else { console.log((error as Error).message); trace("failed"); }
  }
}
if (forbidden || fixtureFs.existsSync(paths.runtimeState) || fixtureFs.existsSync(paths.log) || fixtureFs.readdirSync(paths.bin).length) throw new Error("Unexpected external side effect");
trace("done");
