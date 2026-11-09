import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultNode, createPaths, defaultConfig, writeConfig } from "../src/core.ts";
import { getDaemonStatus, stopDaemonGracefully, waitForReady } from "../src/daemon.ts";

/** 获取一个当前可用的回环 TCP 端口，供真实编译进程测试使用，不修改宿主网络设置。 */
async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("无法分配测试端口。");
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return address.port;
}

/** 限时等待测试进程的 close 事件，并清除定时器，避免正常退出后残留超时任务。 */
async function waitForClosed(closed: Promise<void> | undefined, timeout = 10000): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([closed, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("测试 worker 退出超时。")), timeout);
    })]);
  } finally { clearTimeout(timer); }
}

test("编译 worker → core-host → 回环核心在无 Bun PATH 下就绪、传输和退出", async () => {
  const root = mkdtempSync(join(tmpdir(), "nexus-compiled-daemon-"));
  const executable = join(root, process.platform === "win32" ? "fixture.exe" : "fixture");
  const paths = createPaths(executable, executable);
  let worker: ReturnType<typeof spawn> | undefined;
  let closed: Promise<void> | undefined;
  let errors = "";
  try {
    const build = Bun.spawn([process.execPath, "build", join(import.meta.dir, "fixtures", "compiled-daemon-entry.ts"), "--compile", `--outfile=${executable}`], { stdout: "pipe", stderr: "pipe" });
    const [code, output] = await Promise.all([build.exited, new Response(build.stderr).text()]);
    expect(code, output).toBe(0);
    const config = defaultConfig(), node = createDefaultNode("vless");
    node.listen = node.address = "127.0.0.1";
    node.port = node.publicPort = await availablePort();
    config.nodes = [node]; writeConfig(paths, config);
    // 只保留 Windows ACL 所需的系统工具；Bun 和项目源码目录均不在 PATH 中。
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.toLowerCase() === "path" || key === "BUN_BE_BUN") delete env[key];
    env.PATH = process.platform === "win32" ? join(process.env.SystemRoot || "C:\\Windows", "System32") : "";
    const otherCwd = join(root, "不同 工作目录"); mkdirSync(otherCwd);
    worker = spawn(executable, ["--worker"], { cwd: otherCwd, env, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    worker.stderr!.on("data", data => { errors += data; });
    closed = new Promise<void>((resolve, reject) => { worker!.once("error", reject); worker!.once("close", () => resolve()); });
    const status = await waitForReady(paths, 15000);
    expect(status?.phase, errors).toBe("ready");
    const response = await fetch(`http://127.0.0.1:${node.port}/`, { proxy: "", signal: AbortSignal.timeout(2000) });
    expect(await response.text()).toBe("compiled-loopback-ok");
    const corePid = Number(readFileSync(join(root, "core-pid.txt"), "utf8"));
    await stopDaemonGracefully(paths);
    await waitForClosed(closed);
    expect(worker.exitCode, errors).toBe(0);
    expect(await getDaemonStatus(paths)).toBeNull();
    expect(() => process.kill(corePid, 0)).toThrow();
  } finally {
    // 只处理本测试创建的句柄，不按磁盘上未知 PID 强杀进程。
    try {
      if (worker && worker.exitCode === null && worker.signalCode === null) {
        try { await stopDaemonGracefully(paths); }
        finally { worker.kill(); }
      }
    } finally {
      try {
        try { await waitForClosed(closed, 5000); }
        catch { worker?.kill("SIGKILL"); await waitForClosed(closed, 5000); }
      } finally { rmSync(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); }
    }
  }
}, 60000);
