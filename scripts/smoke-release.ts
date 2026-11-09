import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { APP_VERSION, createPaths, defaultConfig, writeConfig } from "../src/core.ts";
import { acquireDaemonLock, startDetachedDaemon, stopDaemonGracefully } from "../src/daemon.ts";
import { releaseTargets, type ReleaseTarget } from "./build-release.ts";

/**
 * 在无 Bun PATH、中文空格目录和不同 cwd 下验收真实发布程序。
 * @param binary 已构建的本机可执行文件；不允许运行其他平台文件。
 * @returns 验证完成的 Promise；所有子进程均限时并清理，仅操作临时目录。
 */
export async function smokeRelease(binary: string): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), "nexus-compiled-"));
  const portable = join(directory, "发布 中文 空格");
  const cwd = join(directory, "其他 工作目录");
  mkdirSync(portable); mkdirSync(cwd);
  const entry = join(portable, process.platform === "win32" ? "nexus-edge.exe" : "nexus-edge");
  copyFileSync(binary, entry); chmodSync(entry, 0o755);
  const env = { ...process.env };
  // 不让测试机安装的 Bun 意外掩盖程序对子运行时的依赖。
  for (const key of Object.keys(env)) if (key.toLowerCase() === "path") delete env[key];
  env.PATH = (process.env.PATH ?? "").split(delimiter).filter(part => part && !existsSync(join(part, process.platform === "win32" ? "bun.exe" : "bun"))).join(delimiter);
  delete env.BUN_BE_BUN;
  const paths = createPaths(entry, entry);
  /** 执行一次限时 CLI，断言退出码并返回合并输出；仅操作当前临时安装。 */
  const run = (args: string[], expected = 0): string => {
    const result = spawnSync(entry, args, { cwd, env, encoding: "utf8", timeout: 30000, windowsHide: true });
    if (result.error) throw result.error;
    assert.equal(result.status, expected, `${args.join(" ")}\n${result.stdout}\n${result.stderr}`);
    return result.stdout + result.stderr;
  };
  try {
    assert.equal(run(["--version"]).trim(), APP_VERSION);
    assert.match(run(["--help"]), /NexusEdge/);
    assert.equal(existsSync(paths.data), false);
    assert.match(run(["--not-a-command"], 1), /不识别的参数/);
    assert.match(run(["--firewall-request", "../escape"], 1), /无效的防火墙请求/);
    assert.match(run(["--local"], 1), /管理面板需要交互式/);
    writeConfig(paths, defaultConfig());
    assert.equal(JSON.parse(readFileSync(paths.config, "utf8")).nodes.length, 0);
    assert.deepEqual(readdirSync(cwd), [], "程序必须按 exe 目录保存配置，而不是 cwd");

    // core-host 再启动同一个 exe；保持 stdin 开启直到子进程自然结束，验证参数及退出码。
    const host = spawn(entry, ["--core-host", entry, "--version"], { cwd, env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let output = "";
    host.stdout.on("data", data => { output += data; });
    const timer = setTimeout(() => host.kill(), 15000);
    try {
      const code = await new Promise<number | null>((done, fail) => { host.once("error", fail); host.once("close", done); });
      assert.equal(code, 0); assert.equal(output.trim(), APP_VERSION);
    } finally { clearTimeout(timer); host.stdin.destroy(); if (host.exitCode === null) host.kill(); }

    // 空配置 worker 应自行拒绝启动；此处走生产 detached 启动器并检查锁释放。
    const oldPath = process.env.PATH;
    try { process.env.PATH = env.PATH; await startDetachedDaemon(paths); }
    finally { process.env.PATH = oldPath; }
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && (!existsSync(paths.log) || !readFileSync(paths.log, "utf8").includes("没有已启用的节点"))) await Bun.sleep(100);
    assert.match(readFileSync(paths.log, "utf8"), /没有已启用的节点/);
    // 退出日志可能先于进程释放句柄，等待锁可重新获取。
    let released = false;
    while (!released && Date.now() < deadline) {
      try { const unlock = acquireDaemonLock(paths); unlock(); released = true; }
      catch { await Bun.sleep(100); }
    }
    assert.equal(released, true, "worker 未释放 SQLite 锁");
    const original = readFileSync(paths.config);
    run(["--uninstall", "--local", "--keep-config"]);
    assert.deepEqual(readFileSync(paths.config), original);
    run(["--uninstall", "--local", "--remove-config"]);
    assert.equal(existsSync(paths.config), false);
    assert.equal(existsSync(entry), true, "便携程序应保留");
    console.log(`PASS ${binary}：无外部 Bun、CLI、中文路径、core-host、detached worker、SQLite 和卸载`);
  } finally {
    if (existsSync(paths.data)) await stopDaemonGracefully(paths);
    // Windows 在进程退出后可能延迟释放可执行文件映射；仅重试本测试目录。
    rmSync(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
}

if (import.meta.main) {
  try {
    const id = `${process.platform === "win32" ? "windows" : process.platform}-${process.arch}` as ReleaseTarget;
    if (!(id in releaseTargets)) throw new Error(`当前平台不受支持：${id}`);
    if (process.argv.length > 3) throw new Error("用法：bun run test:release [本机可执行文件]");
    const binary = process.argv[2] ? resolve(process.argv[2]) : resolve(import.meta.dir, "..", "dist", id, releaseTargets[id].file);
    await smokeRelease(binary);
  } catch (error) { console.error(error); process.exitCode = 1; }
}
