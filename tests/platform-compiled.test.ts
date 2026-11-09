import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as cp from "node:child_process";
import { createPaths, isCompiledEntry, appArguments, type AppPaths } from "../src/core.ts";
import { installedScriptVersion, platformInternals as platform, platformPowerShell } from "../src/platform.ts";

const temporaryRoots: string[] = [];

/**
 * 创建隔离的中文路径测试目录，不使用真实系统安装根目录。
 * @returns 绝对临时路径；afterEach 在所有子进程结束后清理。
 */
function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-compiled-中文 空格-"));
  temporaryRoots.push(root);
  return root;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

/**
 * 解码 Windows 命令构建器的 JSON 数据载荷，避免测试依赖 PowerShell 字符串转义。
 * @param script 由平台构建器产生的 PowerShell 程序。
 * @returns 原始载荷对象；不执行任何系统命令。
 */
function payload(script: string): { runtime: string; arguments: string; compiled?: boolean } {
  const encoded = script.match(/FromBase64String\('([^']+)'\)/)?.[1];
  if (!encoded) throw new Error("测试程序缺少数据载荷。");
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}

describe("独立程序平台兼容", () => {
  test("脚本与独立程序参数不互相混入，用户参数原样保留", () => {
    const root = temporaryRoot(), executable = path.join(root, "renamed program.exe");
    const compiled = createPaths(executable, executable);
    const script = createPaths(path.join(root, "nexus-edge.ts"), process.execPath);
    const args = ["--core-host", "含 空格", 'a"b', "", "尾随\\"];
    expect(isCompiledEntry(compiled)).toBe(true);
    expect(isCompiledEntry(script)).toBe(false);
    expect(appArguments(compiled, args)).toEqual(args);
    expect(appArguments(script, args)).toEqual([script.entry, ...args]);
    expect(appArguments(compiled, [])).toEqual([]);
  });

  test("只识别两种固定系统布局，拒绝标记指定外部入口或外部运行时", () => {
    const root = temporaryRoot();
    for (const compiled of [false, true]) {
      const paths = platform.systemPaths(compiled, root);
      const marker = platform.makeInstallMarker(paths, true);
      expect(isCompiledEntry(paths)).toBe(compiled);
      expect(platform.pathsFromMarker(marker, root)).toEqual(paths);
      expect(platform.pathsFromMarker({ ...marker, entry: path.join(root, "other.exe") }, root)).toBeNull();
      expect(platform.pathsFromMarker({ ...marker, runtime: process.execPath }, root)).toBeNull();
      expect(platform.pathsFromMarker({ ...marker, schema: 2 }, root)).toBeNull();
    }
    expect(platform.pathsFromMarker(null, root)).toBeNull();
  });

  test("跨格式系统升级在写入前拒绝，同格式允许继续验证", () => {
    const root = temporaryRoot();
    const compiled = platform.systemPaths(true, root), script = platform.systemPaths(false, root);
    expect(() => platform.requireMatchingFormat(compiled, script)).toThrow("保留配置");
    expect(() => platform.requireMatchingFormat(script, compiled)).toThrow("发布格式不同");
    expect(() => platform.requireMatchingFormat(compiled, compiled)).not.toThrow();
    expect(() => platform.requireMatchingFormat(script, script)).not.toThrow();
    expect(fs.readdirSync(root)).toEqual([]);
  });

  test("Windows 提权和任务只传内部参数，空参数面板省略 ArgumentList", () => {
    const executable = path.join(temporaryRoot(), "nexus-edge.exe");
    const paths = createPaths(executable, executable);
    const elevation = platform.buildElevationScript(paths, ["--worker"]);
    expect(payload(elevation).arguments).toBe('"--worker"');
    expect(platform.taskSpec(paths, "user").arguments).toBe('"--worker"');
    const panel = platform.buildElevationScript(paths, []);
    expect(payload(panel).arguments).toBe("");
    expect(panel).toContain("if ($p.arguments.Length -gt 0)");
    expect(panel).toContain("@argumentOptions");
    expect(panel).toContain("-WindowStyle Normal");
  });

  test("systemd 独立程序命令只包含一个可执行文件路径", () => {
    const executable = "/opt/nexus-edge/nexus-edge";
    const paths = { ...createPaths(executable, executable), root: "/opt/nexus-edge", entry: executable, runtime: executable };
    const command = platform.systemdUnit(paths).split("\n").find(line => line.startsWith("ExecStart="));
    expect(command).toBe(`ExecStart=${platform.quoteSystemd(executable, true)} "--worker"`);
  });

  test("复制程序保留所有二进制字节，不进行 UTF-8 转换", () => {
    const root = temporaryRoot(), source = path.join(root, "source.exe"), destination = path.join(root, "target.exe");
    const bytes = Buffer.from([0x4d, 0x5a, 0, 0xff, 0xfe, 0x80, 0xc0, 10]);
    fs.writeFileSync(source, bytes);
    platform.copyRegularTree(source, destination);
    expect(fs.readFileSync(destination)).toEqual(bytes);
    platform.assertStandaloneEntry(createPaths(destination, destination));
    fs.writeFileSync(destination, "不是可执行文件");
    expect(() => platform.assertStandaloneEntry(createPaths(destination, destination))).toThrow("PE / Linux ELF");
  });

  test("独立程序版本通过真实 --version 命令读取，保留脚本旧版解析", () => {
    expect(installedScriptVersion(process.execPath)).toBe(Bun.version);
    const entry = path.join(temporaryRoot(), "nexus-edge.ts");
    fs.writeFileSync(entry, 'export const APP_VERSION = "2.3.3";');
    expect(installedScriptVersion(entry)).toBe("2.3.3");
  });
});

test.skipIf(process.platform !== "win32")("真实 PowerShell 的空参数提权构建不传 ArgumentList", async () => {
  const executable = path.join(temporaryRoot(), "nexus-edge.exe");
  const paths = createPaths(executable, executable);
  // 替身仅报告绑定参数，不执行 UAC、不创建进程、不写计划任务。
  const mock = `
function Start-Process {
  param($FilePath, $ArgumentList, $WorkingDirectory, $Verb, $WindowStyle, [switch]$PassThru, [switch]$Wait)
  [Console]::WriteLine(([ordered]@{ argumentListBound=$PSBoundParameters.ContainsKey('ArgumentList'); executable=$FilePath } | ConvertTo-Json -Compress))
  [pscustomobject]@{ ExitCode=0 }
}
`;
  const result = JSON.parse(await platformPowerShell(mock + platform.buildElevationScript(paths, [])));
  expect(result).toEqual({ argumentListBound: false, executable });
}, 15000);

test.skipIf(process.platform !== "win32")("Windows 独立 EXE 退出清理限定固定文件并保留新安装", async () => {
  const root = temporaryRoot(), paths = platform.systemPaths(true, root);
  fs.writeFileSync(paths.entry, "仅测试清理，无可执行代码");
  fs.mkdirSync(paths.data);
  fs.writeFileSync(paths.config, "保留配置");
  fs.writeFileSync(path.join(root, "unrelated.txt"), "保留其他文件");
  const script = platform.buildRuntimeCleanup(paths);
  expect(payload(script).compiled).toBe(true);
  await platformPowerShell(script);
  expect(fs.existsSync(paths.entry)).toBe(false);
  expect(fs.readFileSync(paths.config, "utf8")).toBe("保留配置");
  expect(fs.readFileSync(path.join(root, "unrelated.txt"), "utf8")).toBe("保留其他文件");
  fs.writeFileSync(paths.entry, "新安装");
  fs.writeFileSync(path.join(root, "installation.json"), "新安装标记");
  await platformPowerShell(script);
  expect(fs.readFileSync(paths.entry, "utf8")).toBe("新安装");
}, 15000);

test.skipIf(process.platform !== "win32")("占用的 Windows 程序替换失败时原文件逐字节不变", async () => {
  const root = temporaryRoot(), executable = path.join(root, "nexus-edge.exe"), replacement = path.join(root, "replacement.exe");
  fs.copyFileSync(process.execPath, executable);
  const original = fs.readFileSync(executable);
  fs.writeFileSync(replacement, Buffer.from([0x4d, 0x5a, 0xff, 0xfe]));
  const child = cp.spawn(executable, ["-e", "console.log('READY'); setInterval(() => {}, 1000);"], { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  const exited = new Promise<void>(resolve => child.once("exit", () => resolve()));
  try {
    await new Promise<void>((resolve, reject) => { child.stdout!.once("data", () => resolve()); child.once("error", reject); });
    expect(() => platform.copyRegularTree(replacement, executable)).toThrow();
    expect(fs.readFileSync(executable)).toEqual(original);
    expect(fs.readdirSync(root).filter(name => name.endsWith(".new"))).toEqual([]);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited;
  }
}, 15000);
