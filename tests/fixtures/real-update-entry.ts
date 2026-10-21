// Real-core integration entrypoint: only local Shadowsocks listeners are permitted.
import { basename, dirname, join, resolve } from "node:path";
import { appendFileSync } from "node:fs";
import childProcess from "node:child_process";
import { mock } from "bun:test";
import { createPaths, readConfig } from "../../src/core.ts";

globalThis.fetch = (async () => { throw new Error("Unexpected outbound request from real updater fixture"); }) as unknown as typeof fetch;

try {
  const mode = process.argv[2];
  if (mode !== "--worker" && mode !== "--core-host") throw new Error("Unsupported real updater fixture mode");
  const host = mode === "--core-host";
  if (host && (!/^run-[a-f0-9-]{36}$/.test(basename(process.cwd())) || basename(dirname(process.cwd())) !== ".nexus-edge")) throw new Error("Core host must belong to this fixture's runtime directory");
  const root = host ? resolve(process.cwd(), "../..") : process.cwd();
  const paths = { ...createPaths(join(root, "nexus-edge.ts"), process.execPath), entry: import.meta.path };
  const config = readConfig(paths);
  if (config.webhook.kind !== "none" || config.webhook.url || config.warp || !config.nodes.length || config.nodes.some(node => node.protocol !== "shadowsocks" || node.listen !== "127.0.0.1" || node.address !== "127.0.0.1" || node.tunnel.mode !== "none" || node.egress !== "direct")) {
    throw new Error("Real updater fixture requires localhost-only Shadowsocks, no tunnel, WARP or notifications");
  }
  // Observe real child handles without changing executable, arguments, options,
  // streams or lifecycle. Some Linux test kernels omit /proc/.../children.
  const originalSpawn = childProcess.spawn;
  const observedSpawn = ((...arguments_: unknown[]) => {
    const child = Reflect.apply(originalSpawn, childProcess, arguments_);
    const command = String(arguments_[0]), args = Array.isArray(arguments_[1]) ? arguments_[1] as string[] : [];
    const selectedCore = basename(command) === "sing-box" && args[0] === "run" && args[1] === "-c";
    if (args.includes("--core-host") || selectedCore) child.once("spawn", () => {
      appendFileSync(join(root, "owned-spawns.jsonl"), JSON.stringify({ parent: process.pid, pid: child.pid, executable: command }) + "\n", { mode: 0o600 });
    });
    return child;
  }) as typeof childProcess.spawn;
  // Bun snapshots built-in ESM namespace exports, so install the transparent
  // observer before importing the daemon. Every call still uses originalSpawn.
  mock.module("node:child_process", () => ({ ...childProcess, default: childProcess, spawn: observedSpawn }));
  const { runCoreHost, runDaemonWorker } = await import("../../src/daemon.ts");
  if (host) {
    const executable = process.argv[3]!, args = process.argv.slice(4);
    if (basename(executable) !== "sing-box" || dirname(dirname(resolve(executable))) !== paths.bin || args.length !== 3 || args[0] !== "run" || args[1] !== "-c" || resolve(args[2]!) !== join(process.cwd(), "sing-box.json")) throw new Error("Unexpected executable or arguments in real updater fixture");
    process.exitCode = await runCoreHost(executable, args);
  } else await runDaemonWorker(paths);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
