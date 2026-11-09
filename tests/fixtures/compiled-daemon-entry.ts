import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { createPaths, readConfig } from "../../src/core.ts";
import { runDaemonWorker, runCoreHost } from "../../src/daemon.ts";

// 仅供编译测试：注入回环 HTTP 核心，禁止下载、隧道、防火墙和系统服务操作。
const paths = createPaths(process.execPath, process.execPath);
const [mode, ...args] = process.argv.slice(2);
try {
  if (mode === "--worker") {
    const node = readConfig(paths).nodes[0]!;
    await runDaemonWorker(paths, {
      cores: { xray: { executable: process.execPath, args: ["--fake-core", String(node.port)] } },
      skipPreflight: true, healthIntervalMs: 50, backoffBaseMs: 80,
    });
  } else if (mode === "--core-host") {
    process.exitCode = await runCoreHost(args[0]!, args.slice(1));
  } else if (mode === "--fake-core") {
    const server = Bun.serve({ hostname: "127.0.0.1", port: Number(args[0]), fetch: () => new Response("compiled-loopback-ok") });
    writeFileSync(join(dirname(process.execPath), "core-pid.txt"), String(process.pid));
    /** 只停止本测试监听器；core-host 会等待退出，测试随后确认 PID 已结束。 */
    const stop = (): void => { void server.stop(true); };
    process.on("SIGTERM", stop); process.on("SIGINT", stop);
  } else throw new Error(`未知测试命令：${mode}`);
} catch (error) { console.error(error); process.exitCode = 1; }
