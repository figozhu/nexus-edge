import { afterEach, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import { createPaths, defaultConfig, type AppPaths } from "../src/core.ts";
import { acquireDaemonLock } from "../src/daemon.ts";
import { acquireCoreSelectionLock } from "../src/network.ts";
import { requestUninstall, uninstallApplication, type UninstallOperations } from "../src/uninstall.ts";
import { assertUninstallTarget, systemInstallRoot, platformInternals, platformPowerShell } from "../src/platform.ts";
import { nexusMain } from "../src/main.ts";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

/** 创建只含测试数据的独立安装，返回标准路径与原始配置文本，不操作任何真实服务。 */
function fixture(): { paths: AppPaths; original: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-uninstall-中文 空格-"));
  roots.push(root);
  const paths = createPaths(path.join(root, "nexus-edge.ts"));
  fs.mkdirSync(paths.bin, { recursive: true });
  const original = JSON.stringify({ ...defaultConfig(), firewall: { mode: "manual", linuxBackend: "auto", firewalldZone: "" } });
  for (const name of ["config.json", "config.json.bak", "config.json.schema1.bak"]) fs.writeFileSync(path.join(paths.data, name), original);
  fs.writeFileSync(paths.entry, "// 用户下载的程序\n");
  fs.writeFileSync(path.join(root, "unrelated.txt"), "其他文件");
  fs.writeFileSync(path.join(paths.bin, "core.exe"), "缓存");
  fs.writeFileSync(paths.log, "日志");
  fs.writeFileSync(paths.link, "含凭据的导出链接");
  fs.mkdirSync(path.join(paths.data, "updates"));
  fs.writeFileSync(path.join(paths.data, "updates", "config.backup.json"), original);
  return { paths, original };
}

/** 返回无系统副作用的操作替身；调用记录验证停止/清理/删除顺序，锁仍使用真实 SQLite。 */
function operations(calls: string[]): Partial<UninstallOperations> {
  return {
    validate: () => { calls.push("validate"); },
    unregister: async () => { calls.push("unregister"); },
    stop: async () => { calls.push("stop"); },
    firewall: async (_paths, config) => {
      calls.push("firewall");
      expect(config.nodes).toEqual([]);
      return { backend: "windows", status: "synced", changed: true, detail: "已清理", warnings: [], rules: [] };
    },
    program: async paths => { calls.push("program"); expect(fs.existsSync(paths.log)).toBe(false); return false; },
  };
}

test("保留配置逐字节不变，清理缓存/日志/导出，便携代码与无关文件保留", async () => {
  const { paths, original } = fixture(), calls: string[] = [];
  await uninstallApplication(paths, true, operations(calls));
  expect(calls).toEqual(["validate", "unregister", "stop", "firewall", "program"]);
  expect(fs.readdirSync(paths.data).sort()).toEqual(["config.json", "config.json.bak", "config.json.schema1.bak", "core-update-lock.sqlite", "daemon-lock.sqlite", "updates"]);
  expect(fs.readFileSync(paths.config, "utf8")).toBe(original);
  expect(fs.readFileSync(paths.config + ".bak", "utf8")).toBe(original);
  expect(fs.existsSync(paths.entry)).toBe(true);
  expect(fs.readFileSync(path.join(paths.root, "unrelated.txt"), "utf8")).toBe("其他文件");
});

test("删除全部数据并允许重复卸载，保持便携根目录", async () => {
  const { paths } = fixture();
  for (let attempt = 0; attempt < 2; attempt++) {
    await uninstallApplication(paths, false, operations([]));
    expect(fs.readdirSync(paths.data).sort()).toEqual(["core-update-lock.sqlite", "daemon-lock.sqlite"]);
    expect(fs.existsSync(paths.entry)).toBe(true);
  }
});

for (const failing of ["unregister", "stop", "firewall"] as const) {
  test(`${failing} 失败保留全部配置和内核，释放锁以允许重试`, async () => {
    const { paths, original } = fixture(), calls: string[] = [];
    await expect(uninstallApplication(paths, false, { ...operations(calls), [failing]: async () => { throw new Error("模拟失败"); } })).rejects.toThrow("模拟失败");
    expect(calls).not.toContain("program");
    expect(fs.readFileSync(paths.config, "utf8")).toBe(original);
    expect(fs.existsSync(path.join(paths.bin, "core.exe"))).toBe(true);
    const release = acquireCoreSelectionLock(paths); release();
  });
}

test("防火墙 inactive 不被当成已清理，保留归属记录", async () => {
  const { paths } = fixture();
  const journal = path.join(paths.data, "firewall-linux-state.json");
  fs.writeFileSync(journal, "归属记录");
  await expect(uninstallApplication(paths, false, { ...operations([]), firewall: async () => ({ backend: "ufw", status: "inactive", changed: false, detail: "持久规则可能仍在", rules: [], warnings: [] }) })).rejects.toThrow("无法确认规则清理完成");
  expect(fs.readFileSync(journal, "utf8")).toBe("归属记录");
  expect(fs.existsSync(paths.config)).toBe(true);
});

test("损坏配置可以保留卸载，不会自动创建新节点或覆盖原文件", async () => {
  const { paths } = fixture();
  fs.writeFileSync(paths.config, "{损坏但需保留");
  await uninstallApplication(paths, true, operations([]));
  expect(fs.readFileSync(paths.config, "utf8")).toBe("{损坏但需保留");
});

test("内核更新锁占用时不停止服务", async () => {
  const { paths } = fixture(), calls: string[] = [];
  const release = acquireCoreSelectionLock(paths);
  try { await expect(uninstallApplication(paths, false, operations(calls))).rejects.toThrow("内核更新"); }
  finally { release(); }
  expect(calls).toEqual(["validate"]);
});

test("后台锁仍占用时拒绝删除，即使状态查询或停止替身误报完成", async () => {
  const { paths } = fixture(), calls: string[] = [];
  const release = acquireDaemonLock(paths);
  try { await expect(uninstallApplication(paths, false, operations(calls))).rejects.toThrow("守护进程占用"); }
  finally { release(); }
  expect(calls).not.toContain("firewall");
  expect(fs.existsSync(paths.config)).toBe(true);
});

test("数据目录内 junction 不会指向外部删除，预检在注销前失败", async () => {
  const { paths } = fixture(), outside = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-uninstall-outside-")), calls: string[] = [];
  roots.push(outside);
  fs.writeFileSync(path.join(outside, "keep.txt"), "保留");
  fs.symlinkSync(outside, path.join(paths.data, "redirect"), process.platform === "win32" ? "junction" : "dir");
  await expect(uninstallApplication(paths, false, operations(calls))).rejects.toThrow("链接");
  expect(calls).toEqual(["validate"]);
  expect(fs.readFileSync(path.join(outside, "keep.txt"), "utf8")).toBe("保留");
});

test("无效/冲突卸载参数在任何卸载操作前被拒绝", async () => {
  for (const args of [["--keep-config", "--remove-config"], ["--keep-config", "--keep-config"], ["--local", "--system"], ["--unknown"]]) await expect(nexusMain(["--uninstall", ...args], "nexus-edge.ts")).rejects.toThrow("卸载参数无效");
});

test("新版便携入口提权卸载旧系统副本时，执行新版并固定系统目标", async () => {
  const source = fixture().paths, target = fixture().paths;
  const calls: unknown[] = [];
  await requestUninstall(target, true, source, { admin: () => false, system: () => true, elevate: async (entry, args) => { calls.push({ entry, args }); } });
  expect(calls).toEqual([{ entry: source, args: ["--uninstall", "--system", "--keep-config"] }]);
});

test("固定系统根目录的非专用运行时不能被当作便携卸载", () => {
  const paths = createPaths(path.join(systemInstallRoot(), "nexus-edge.ts"), path.join(os.tmpdir(), "external-bun"));
  expect(() => assertUninstallTarget(paths)).toThrow("专用入口和运行时");
});

test("程序清理期间持锁，释放后其他进程取得的锁路径不会被删除", async () => {
  const { paths } = fixture();
  let releaseNew: (() => void) | undefined;
  const ops = operations([]);
  ops.program = async () => {
    expect(() => acquireDaemonLock(paths)).toThrow("守护进程占用");
    expect(() => acquireCoreSelectionLock(paths)).toThrow("内核更新");
    return false;
  };
  ops.lockDaemon = current => {
    const release = acquireDaemonLock(current);
    return () => { release(); releaseNew = acquireDaemonLock(current); };
  };
  try {
    await uninstallApplication(paths, false, ops);
    expect(fs.existsSync(paths.lockDb)).toBe(true);
    expect(() => acquireDaemonLock(paths)).toThrow("守护进程占用");
  } finally { releaseNew?.(); }
});

test.skipIf(process.platform !== "win32")("真实 PowerShell 执行注销脚本，归属冲突或仍运行时保留任务", async () => {
  const { paths } = fixture(), spec = platformInternals.taskSpec(paths, "user");
  // 全部系统 cmdlet 被局部函数替换，只验证脚本控制流，不访问宿主机计划任务。
  const mocks = `
function Get-ScheduledTask { $script:task }
function Unregister-ScheduledTask { 'REMOVED' }
function Disable-ScheduledTask { 'DISABLED' }
`;
  const setup = platformInternals.powerShellPayload(spec) + `$script:task = [pscustomobject]@{ TaskName=$p.name; Description=$p.marker; Actions=@([pscustomobject]@{Execute=$p.runtime;Arguments=$p.arguments;WorkingDirectory=$p.root}); State='Ready' }\n`;
  const remove = platformInternals.buildUninstallTaskScript(spec, true);
  expect(await platformPowerShell(mocks + setup + remove)).toBe("REMOVED");
  await expect(platformPowerShell(mocks + setup + "$script:task.Description='其他程序'\n" + remove)).rejects.toThrow("不匹配");
  await expect(platformPowerShell(mocks + setup + "$script:task.State='Running'\n" + remove)).rejects.toThrow("仍在运行");
  expect(await platformPowerShell(mocks + "$script:task=$null\n" + remove)).toBe("");
}, 30000);

test.skipIf(process.platform !== "win32")("退出清理脚本只删除专用运行时，保留配置和无关文件", async () => {
  const { paths } = fixture();
  paths.runtime = path.join(paths.root, "runtime", "bun.exe");
  fs.mkdirSync(path.dirname(paths.runtime));
  fs.writeFileSync(paths.runtime, "可删除的测试文件，不是真实 Bun");
  await platformPowerShell(platformInternals.buildRuntimeCleanup(paths));
  expect(fs.existsSync(paths.runtime)).toBe(false);
  expect(fs.existsSync(paths.config)).toBe(true);
  expect(fs.existsSync(path.join(paths.root, "unrelated.txt"))).toBe(true);
  // 新的安装标记防止旧清理进程误删后来安装的运行器。
  fs.mkdirSync(path.dirname(paths.runtime));
  fs.writeFileSync(paths.runtime, "新运行器");
  fs.writeFileSync(path.join(paths.root, "installation.json"), "新安装");
  await platformPowerShell(platformInternals.buildRuntimeCleanup(paths));
  expect(fs.readFileSync(paths.runtime, "utf8")).toBe("新运行器");
}, 30000);

test.skipIf(process.platform !== "win32")("实际运行中的专用 Bun 在进程退出后才被清理", async () => {
  const { paths } = fixture();
  paths.runtime = path.join(paths.root, "runtime", "bun.exe");
  fs.mkdirSync(path.dirname(paths.runtime));
  fs.copyFileSync(process.execPath, paths.runtime);
  const child = cp.spawn(paths.runtime, ["-e", "console.log('READY'); setInterval(() => {}, 1000);"], { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  const exited = new Promise<void>(resolve => child.once("exit", () => resolve()));
  let cleanup: Promise<string> | undefined;
  try {
    await new Promise<void>((resolve, reject) => { child.stdout!.once("data", () => resolve()); child.once("error", reject); });
    cleanup = platformPowerShell(platformInternals.buildRuntimeCleanup(paths));
    await Bun.sleep(1000);
    expect(fs.existsSync(paths.runtime)).toBe(true);
    child.kill();
    await exited;
    await cleanup;
    expect(fs.existsSync(paths.runtime)).toBe(false);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited;
    await cleanup;
  }
}, 15000);
