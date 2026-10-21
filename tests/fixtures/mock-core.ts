// Synthetic local listeners only: no real proxy, Internet request or tunnel.
import { appendFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { createSocket, type Socket } from "node:dgram";
import { createServer, isIP, type Server } from "node:net";
import { nodeListenNetworks, type NodeConfig } from "../../src/core.ts";

const role = process.argv[2]!;
const root = process.argv[3]!;
const nodes = JSON.parse(readFileSync(process.argv[4]!, "utf8")) as NodeConfig[];
const args = process.argv.slice(5);
const servers: Server[] = [];
const sockets: Socket[] = [];
let metrics: ReturnType<typeof Bun.serve> | undefined;
let finishing = false;

function event(kind: string): void {
  appendFileSync(join(root, "events.jsonl"), JSON.stringify({ role, kind, pid: process.pid, args, at: Date.now() }) + "\n");
}

function finish(code: number, kind: string): void {
  if (finishing) return;
  finishing = true;
  event(kind);
  for (const server of servers) server.close();
  for (const socket of sockets) socket.close();
  void metrics?.stop(true);
  process.exit(code);
}

process.on("SIGTERM", () => finish(0, "stop"));
process.on("SIGINT", () => finish(0, "stop"));
event("start");
for (const node of nodes) {
  // These are generated fixture credentials, never real user secrets.
  console.error("fake credentials uuid=" + node.uuid + " password=" + node.password + " token=" + node.tunnel.token);
  if (node.tls.keyPem) console.error(node.tls.keyPem);
}

if (role === "xray" || role === "singBox") {
  for (const node of nodes) {
    if (existsSync(join(root, "no-listen-" + node.id))) continue;
    for (const network of nodeListenNetworks(node)) {
      if (existsSync(join(root, "no-" + network + "-" + node.id))) continue;
      if (network === "tcp") {
        const server = createServer(socket => socket.end("synthetic local listener\n"));
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen({ host: node.listen, port: node.port, exclusive: true }, resolve);
        });
        servers.push(server);
      } else {
        const socket = createSocket({ type: isIP(node.listen) === 6 ? "udp6" : "udp4", reuseAddr: false });
        await new Promise<void>((resolve, reject) => {
          socket.once("error", reject);
          socket.bind({ address: node.listen, port: node.port, exclusive: true }, resolve);
        });
        sockets.push(socket);
      }
    }
  }
} else if (role.startsWith("cloudflared:")) {
  const node = nodes[0]!;
  const metricIndex = args.indexOf("--metrics");
  const address = args[metricIndex + 1];
  if (metricIndex < 0 || !address) throw new Error("Mock cloudflared did not receive --metrics");
  const metricsPort = Number(address.slice(address.lastIndexOf(":") + 1));
  metrics = Bun.serve({
    hostname: "127.0.0.1", port: metricsPort,
    async fetch(request) {
      if (new URL(request.url).pathname !== "/ready") return new Response("not found", { status: 404 });
      const delayPath = join(root, "ready-delay-" + node.id);
      if (existsSync(delayPath)) await Bun.sleep(Number(readFileSync(delayPath, "utf8")));
      const statusPath = join(root, "ready-" + node.id + ".status");
      const status = existsSync(statusPath) ? Number(readFileSync(statusPath, "utf8")) : 200;
      return new Response(status === 200 ? "ready" : "not ready", { status });
    },
  });
  if (args.includes("--url")) {
    const domainPath = join(root, "domain-" + node.id + ".txt");
    const domain = existsSync(domainPath) ? readFileSync(domainPath, "utf8").trim() : "quiet-river.trycloudflare.com";
    // Divide both the domain and multibyte UTF-8 text across writes.
    const bytes = Buffer.from("临时隧道 https://" + domain + "\n");
    const boundaries = [1, 7, 23, bytes.length - 6, bytes.length];
    let previous = 0;
    boundaries.forEach((end, index) => {
      const begin = previous;
      previous = end;
      setTimeout(() => process.stderr.write(bytes.subarray(begin, end)), 8 * index);
    });
  }
} else {
  throw new Error("Unknown mock role: " + role);
}

setInterval(() => {
  // Colons are invalid in Windows filenames.
  const trigger = join(root, "crash-" + role.replaceAll(":", "_"));
  if (existsSync(trigger)) {
    unlinkSync(trigger);
    finish(17, "crash");
  }
}, 30);
