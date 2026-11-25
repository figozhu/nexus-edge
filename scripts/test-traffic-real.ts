/** Download pinned, hash-verified official cores only into a fresh temporary fixture. Never use installed node data. */
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createPaths, defaultConfig, createDefaultNode } from "../src/core.ts";
import { ensureBinaries } from "../src/network.ts";

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== "--entry")) throw new Error("用法：bun scripts/test-traffic-real.ts [--entry 程序路径]");
const entry = resolve(args[1] ?? "nexus-edge.ts");
if (!existsSync(entry)) throw new Error("请先构建待测入口。");
const root = mkdtempSync(join(tmpdir(), "nexus-traffic-cores-"));
try {
  const config = defaultConfig(); config.nodes = [createDefaultNode("vless"), createDefaultNode("socks")];
  const binaries = await ensureBinaries(createPaths(join(root, "fixture.ts")), config, console.log);
  const test = Bun.spawn([process.execPath, "test", "tests/real-proxy.test.ts", "tests/traffic-worker.test.ts"], {
    cwd: resolve(import.meta.dir, ".."), stdout: "inherit", stderr: "inherit",
    env: { ...process.env, NEXUS_EDGE_SINGBOX_TEST_BINARY: binaries.singBox!, NEXUS_EDGE_XRAY_TEST_BINARY: binaries.xray!, NEXUS_EDGE_TEST_TRAFFIC: "1", NEXUS_EDGE_TRAFFIC_TEST_ENTRY: entry },
  });
  process.exitCode = await test.exited;
} finally { rmSync(root, { recursive: true, force: true }); }
