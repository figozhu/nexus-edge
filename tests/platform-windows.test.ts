import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createPaths } from "../src/core.ts";
import { enableStartup, disableStartup, getStartupStatus, startManaged, isAdministrator, platformPowerShell, platformInternals as platform } from "../src/platform.ts";

/**
 * 等待测试任务写入完成标记；只读取本用例创建的临时文件。
 * @param file 标记文件的绝对路径。
 * @returns 标记写入并可解析后的内容；20 秒未完成则抛错。
 */
async function waitForTask(file: string): Promise<{ arguments: string[] }> {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { await Bun.sleep(100); }
  }
  throw new Error(`测试计划任务未在 20 秒内生成标记：${file}`);
}

/**
 * 删除本用例创建的任务，严格检查归属标记后才停止及注销。
 * @param spec 本测试的唯一任务名和归属标记。
 * @returns 清理完成的 Promise；归属冲突会抛错而保留任务。
 */
async function removeTask(spec: { name: string; marker: string }): Promise<void> {
  await platformPowerShell(platform.powerShellPayload(spec) + `
$task = Get-ScheduledTask -TaskPath '\\' | Where-Object { $_.TaskName -eq $p.name } | Select-Object -First 1
if ($task) {
  if ($task.Description -ne $p.marker) { throw '测试任务归属冲突，已保留。' }
  Stop-ScheduledTask -TaskName $p.name -TaskPath '\\'
  Unregister-ScheduledTask -TaskName $p.name -TaskPath '\\' -Confirm:$false
}
`);
}

// 真实任务写入需显式启用；默认测试运行只保留无系统副作用的单元/ACL回归。
describe.skipIf(process.platform !== "win32" || process.env.NEXUS_PLATFORM_WINDOWS_INTEGRATION !== "1")("Windows real scheduled tasks", () => {
  test("registers, runs, disables and re-enables a Unicode portable login task", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-startup-用户 空格-"));
    const paths = createPaths(path.join(root, "nexus-edge.ts"));
    const marker = path.join(root, "completed.json");
    fs.writeFileSync(paths.entry, `await Bun.write(${JSON.stringify(marker)}, JSON.stringify({ arguments: process.argv.slice(2) }));\n`);
    const spec = platform.taskSpec(paths, "user");
    try {
      await enableStartup(paths, "user");
      expect(await getStartupStatus(paths)).toMatchObject({ mode: "windows-user", enabled: true });
      await startManaged(paths);
      expect(await waitForTask(marker)).toEqual({ arguments: ["--worker"] });
      await disableStartup(paths);
      expect(await getStartupStatus(paths)).toMatchObject({ mode: "windows-user", enabled: false });
      await enableStartup(paths, "user");
      expect(await getStartupStatus(paths)).toMatchObject({ mode: "windows-user", enabled: true });
    } finally {
      await removeTask(spec);
      fs.rmSync(root, { recursive: true, force: true });
    }
  }, 60000);

  test("registers and runs a separate SYSTEM boot task with no timeout or battery cutoff", async () => {
    expect(isAdministrator()).toBe(true);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-startup-system-"));
    const paths = createPaths(path.join(root, "nexus-edge.ts"));
    const marker = path.join(root, "completed.json");
    fs.writeFileSync(paths.entry, `await Bun.write(${JSON.stringify(marker)}, JSON.stringify({ arguments: process.argv.slice(2) }));\n`);
    // 名字含随机临时目录标识，绝不会覆盖真实 NexusEdge-System 任务。
    const spec = { ...platform.taskSpec(paths, "system"), name: "NexusEdge-Test-" + path.basename(root) };
    try {
      await platformPowerShell(platform.buildTaskScript(spec));
      const actual = JSON.parse(await platformPowerShell(platform.powerShellPayload(spec) + `
$task = Get-ScheduledTask -TaskName $p.name -TaskPath '\\'
$sid = $task.Principal.UserId
if ($sid -notmatch '^S-1-') { $sid = (New-Object Security.Principal.NTAccount($sid)).Translate([Security.Principal.SecurityIdentifier]).Value }
[ordered]@{ sid = $sid; trigger = $task.Triggers[0].CimClass.CimClassName; timeout = $task.Settings.ExecutionTimeLimit; battery = $task.Settings.DisallowStartIfOnBatteries; stopOnBattery = $task.Settings.StopIfGoingOnBatteries; instances = [string]$task.Settings.MultipleInstances; logon = [string]$task.Principal.LogonType; level = [string]$task.Principal.RunLevel } | ConvertTo-Json -Compress
`));
      expect(actual).toMatchObject({ sid: "S-1-5-18", trigger: "MSFT_TaskBootTrigger", timeout: "PT0S", battery: false, stopOnBattery: false });
      expect(["IgnoreNew", "2"]).toContain(actual.instances);
      expect(["ServiceAccount", "5"]).toContain(actual.logon);
      expect(["Highest", "1"]).toContain(actual.level);
      await platformPowerShell(platform.powerShellPayload(spec) + "Start-ScheduledTask -TaskName $p.name -TaskPath '\\'");
      expect(await waitForTask(marker)).toEqual({ arguments: ["--worker"] });
    } finally {
      await removeTask(spec);
      fs.rmSync(root, { recursive: true, force: true });
    }
  }, 60000);
});
