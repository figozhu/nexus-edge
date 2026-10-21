/** Real node-editor PTY fixture: writes only its temporary config, never starts cores. */
import * as panelFixturePath from "node:path";
import * as panelFixtureCrypto from "node:crypto";
import * as panelFixtureFs from "node:fs";
import { createPaths, createDefaultNode, defaultConfig, readConfig, writeConfig } from "../../src/core.ts";
import { configureNode } from "../../src/panel.ts";
import { UserCancelledError } from "../../src/ui.ts";

globalThis.fetch = (async () => { throw new Error("The panel PTY fixture must never access the network."); }) as unknown as typeof fetch;
const paths = createPaths(panelFixturePath.join(process.cwd(), "nexus-edge.ts"));
function trace(event: string, value: Record<string, unknown> = {}): void {
  process.stdout.write(`\r\n__NEXUS_PTY__${JSON.stringify({ event, ...value, raw: Boolean(process.stdin.isRaw) })}\r\n`);
}
function snapshot(event: string): void {
  const config = readConfig(paths);
  trace(event, { nodes: config.nodes.map(node => ({
    id: node.id, name: node.name, protocol: node.protocol, uuid: node.uuid,
    passwordHash: panelFixtureCrypto.createHash("sha256").update(node.password).digest("hex"),
    address: node.address, port: node.port, publicPort: node.publicPort, listen: node.listen,
    direct: node.direct, method: node.method, transport: node.transport, tlsMode: node.tls.mode,
    serverName: node.tls.serverName, realityPublicKey: node.tls.reality.publicKey, flow: node.flow,
    tunnel: { ...node.tunnel, token: undefined, hasToken: Boolean(node.tunnel.token) },
  })) });
}

const scenario = process.argv[2];
if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("This fixture requires a real PTY.");
trace("start", { stdinTTY: process.stdin.isTTY, stdoutTTY: process.stdout.isTTY });
switch (scenario) {
  case "multi-direct":
    for (let i = 0; i < 3; i++) { await configureNode(paths); snapshot(`saved-${i + 1}`); }
    break;
  case "tunnel-modes": {
    const config = defaultConfig();
    const node = createDefaultNode("vmess");
    node.transport.type = "ws";
    node.address = "direct.example.test";
    node.listen = "0.0.0.0";
    config.nodes.push(node);
    writeConfig(paths, config);
    snapshot("seed");
    for (let i = 0; i < 3; i++) {
      await configureNode(paths, readConfig(paths).nodes[0]!);
      snapshot(`saved-${i + 1}`);
    }
    break;
  }
  case "reality":
    await configureNode(paths); snapshot("saved");
    break;
  case "cancel": {
    writeConfig(paths, defaultConfig());
    const before = panelFixtureFs.readFileSync(paths.config, "utf8");
    let cancelled = false;
    try { await configureNode(paths); }
    catch (error) { if (!(error instanceof UserCancelledError)) throw error; cancelled = true; }
    if (!cancelled || before !== panelFixtureFs.readFileSync(paths.config, "utf8")) throw new Error("Cancelled editor changed persistent configuration.");
    snapshot("cancelled");
    break;
  }
  default: throw new Error(`Unknown scenario ${scenario}`);
}
if (panelFixtureFs.existsSync(paths.bin) && panelFixtureFs.readdirSync(paths.bin).length) throw new Error("The editor unexpectedly downloaded a core.");
if (panelFixtureFs.existsSync(paths.runtimeState)) throw new Error("The editor unexpectedly started a daemon.");
trace("done");
