// Test-only entrypoint. It never downloads a binary, creates a real tunnel,
// registers WARP, sends a webhook, or installs a system service.
import { join } from "node:path";
import { appendFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { createPaths, readConfig, nodeEngine, type CoreName } from "../../src/core.ts";
import { runCoreHost, runDaemonWorker, type DaemonCoreCommand } from "../../src/daemon.ts";

const mode = process.argv[2];

try {
  if (mode === "--core-host") {
    process.exitCode = await runCoreHost(process.argv[3]!, process.argv.slice(4));
  } else if (mode === "--fixture-worker" || mode === "--worker") {
    const root = process.argv[3] || process.cwd();
    const paths = {
      ...createPaths(join(root, "nexus-edge.ts"), process.execPath),
      entry: import.meta.path,
    };
    const config = readConfig(paths);
    // Capture only the synthetic test receiver. Never send a real webhook from
    // this fixture, including when a test accidentally supplies another URL.
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url !== "https://nexus-edge-webhook.test/fixture" || init?.method !== "POST") throw new Error("Unexpected outbound request from daemon fixture");
      appendFileSync(join(root, "notices.jsonl"), String(init.body) + "\n", { mode: 0o600 });
      return Response.json({ code: 0 });
    }) as typeof fetch;
    const mock = join(import.meta.dir, "mock-core.ts");
    const snapshots = mkdtempSync(join(root, "mock-snapshot-"));
    const nodes = config.nodes.filter(node => node.enabled);
    const cores: Partial<Record<CoreName, DaemonCoreCommand>> = {};
    const tunnels: Record<string, DaemonCoreCommand> = {};
    for (const engine of new Set(nodes.map(nodeEngine))) {
      const snapshot = join(snapshots, engine + ".json");
      writeFileSync(snapshot, JSON.stringify(nodes.filter(node => nodeEngine(node) === engine)), { mode: 0o600 });
      cores[engine] = {
        executable: process.execPath,
        // Freeze the mock listeners too, so restarts use the running snapshot.
        args: [mock, engine, root, snapshot],
      };
    }
    for (const node of nodes.filter(node => node.tunnel.mode !== "none")) {
      const snapshot = join(snapshots, "cloudflared-" + node.id + ".json");
      writeFileSync(snapshot, JSON.stringify([node]), { mode: 0o600 });
      tunnels[node.id] = {
        executable: process.execPath,
        args: [mock, "cloudflared:" + node.id, root, snapshot],
      };
    }
    await runDaemonWorker(paths, {
      cores,
      tunnels,
      skipPreflight: true,
      healthIntervalMs: 50,
      backoffBaseMs: 80,
    });
  } else {
    throw new Error(`Unsupported test entrypoint mode: ${mode}`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

// Intentionally allow a natural exit. Tests verify that daemon cleanup really
// releases its owned children and timers rather than relying on process.exit.
