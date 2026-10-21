import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import { createPaths, type AppPaths } from "../src/core";
import { platformInternals as platform, installedScriptVersion } from "../src/platform";

const temporaryDirs: string[] = [];
function temporaryDir(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-platform-test-"));
  temporaryDirs.push(directory);
  return directory;
}
afterEach(() => { for (const dir of temporaryDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

function windowsPaths(root = String.raw`C:\ProgramData\NexusEdge`): AppPaths {
  const data = path.win32.join(root, ".nexus-edge");
  return {
    root, entry: path.win32.join(root, "nexus-edge.ts"), runtime: path.win32.join(root, "runtime", "bun.exe"), data,
    bin: path.win32.join(data, "bin"), config: path.win32.join(data, "config.json"),
    runtimeState: path.win32.join(data, "runtime.json"), log: path.win32.join(data, "daemon.log"),
    link: path.win32.join(data, "node-link.txt"), lockDb: path.win32.join(data, "daemon-lock.sqlite"), xrayConfig: path.win32.join(data, "xray.json"),
    tokenFile: path.win32.join(data, "tunnel-token.txt"), singConfig: path.win32.join(data, "sing-box.json"),
  };
}

/** Independent Windows argv reader: runs of backslashes only escape a following quote. */
function parseWindowsArguments(commandLine: string): string[] {
  const result: string[] = [];
  let i = 0;
  while (i < commandLine.length) {
    while (/[ \t]/.test(commandLine[i] || "") && i < commandLine.length) i++;
    if (i === commandLine.length) break;
    let argument = "", quoted = false;
    while (i < commandLine.length) {
      if (!quoted && /[ \t]/.test(commandLine[i]!)) break;
      let slashes = 0;
      while (commandLine[i] === "\\") { slashes++; i++; }
      if (commandLine[i] === '"') {
        argument += "\\".repeat(Math.floor(slashes / 2));
        if (slashes % 2) argument += '"'; else quoted = !quoted;
        i++;
      } else {
        argument += "\\".repeat(slashes);
        if (i < commandLine.length && (quoted || !/[ \t]/.test(commandLine[i]!))) argument += commandLine[i++];
      }
    }
    result.push(argument);
  }
  return result;
}

function taskFixture(mode: "system" | "user" = "system") {
  const spec = platform.taskSpec(windowsPaths(), mode);
  const sid = mode === "system" ? "S-1-5-18" : "S-1-5-21-123-456-789-1001";
  return {
    spec,
    snapshot: {
      name: spec.name, description: spec.marker, state: "Running", taskEnabled: true,
      actions: [{ execute: spec.runtime, arguments: spec.arguments, workingDirectory: spec.root }],
      principal: { userId: sid, logonType: mode === "system" ? "ServiceAccount" : "Interactive", runLevel: mode === "system" ? "Highest" : "Limited" },
      triggers: [{ type: mode === "system" ? "MSFT_TaskBootTrigger" : "MSFT_TaskLogonTrigger", enabled: true, userId: mode === "system" ? "" : sid }],
      executionTimeLimit: "PT0S", allowBattery: true, keepOnBattery: true, multipleInstances: "IgnoreNew", lastResult: 0, currentSid: "S-1-5-21-123-456-789-1001", currentIsAdmin: false,
    },
  };
}

describe("Windows argument boundaries", () => {
  test("detects both published script versions for system-copy upgrade handoff", () => {
    const entry = path.join(temporaryDir(), "nexus-edge.ts");
    for (const version of ["1.0.0", "2.0.0"]) {
      fs.writeFileSync(entry, `#!/usr/bin/env bun\nexport const APP_VERSION = "${version}";\n`);
      expect(installedScriptVersion(entry)).toBe(version);
    }
    fs.writeFileSync(entry, "// unknown file\n");
    expect(installedScriptVersion(entry)).toBeNull();
    expect(installedScriptVersion(entry + ".missing")).toBeNull();
  });
  test("round-trips spaces, Unicode, quotes, apostrophes and trailing backslashes", () => {
    const args = [
      "", "--worker", String.raw`C:\Users\测试 用户\O'Brien\nexus-edge.ts`,
      'x"y', 'a\\"b', 'a\\\\"b', "C:\\trailing\\", "\\\\server\\share with spaces\\",
      "$env:TEMP; & whoami", "%PATH%", "two\twords", "''", '"', "\\",
    ];
    expect(parseWindowsArguments(platform.windowsArguments(args))).toEqual(args);
  });

  test("rejects NUL and line breaks before reaching an OS command", () => {
    for (const value of ["bad\0arg", "bad\narg", "bad\rarg"]) expect(() => platform.quoteWindowsArg(value)).toThrow();
  });

  test("PowerShell JSON payload keeps path text out of executable syntax", () => {
    const value = { root: String.raw`C:\测试\O'Brien\$(Remove-Item *)`, arguments: '"x y" --worker', quote: "'; throw 'oops" };
    const script = platform.powerShellPayload(value);
    expect(script).not.toContain("Remove-Item");
    expect(script).not.toContain(value.quote);
    const encoded = script.match(/FromBase64String\('([^']+)'\)/)?.[1];
    expect(JSON.parse(Buffer.from(encoded!, "base64").toString("utf8"))).toEqual(value);
    expect(Buffer.from(platform.encodePowerShell("输出 '中文'"), "base64").toString("utf16le")).toBe("输出 '中文'");
  });
});

describe("scheduled task definition", () => {
  test("system task is genuinely pre-login and has no duration or battery cutoff", () => {
    const { spec } = taskFixture();
    const script = platform.buildTaskScript(spec);
    expect(script).toContain("New-ScheduledTaskTrigger -AtStartup");
    expect(script).toContain("-UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest");
    expect(script).toContain("-ExecutionTimeLimit ([TimeSpan]::Zero)");
    expect(script).toContain("-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries");
    expect(script).toContain("-MultipleInstances IgnoreNew");
    expect(script).toContain("-WorkingDirectory $p.root");
    expect(script).not.toContain("-AtLogOn");
    expect(parseWindowsArguments(spec.arguments)).toEqual([windowsPaths().entry, "--worker"]);
  });

  test("optional user task uses the current interactive user and an explicit login trigger", () => {
    const { spec } = taskFixture("user");
    const script = platform.buildTaskScript(spec);
    expect(script).toContain("-AtLogOn -User $sid");
    expect(script).toContain("-LogonType Interactive -RunLevel Limited");
    expect(script).not.toContain("-AtStartup");
    expect(script).not.toContain("ServiceAccount");
  });

  test("portable task identity is stable across path case but unique per directory", () => {
    expect(platform.taskSpec(windowsPaths(String.raw`C:\Users\ME\Apps`), "user").name).toBe(platform.taskSpec(windowsPaths(String.raw`c:\users\me\apps`), "user").name);
    expect(platform.taskSpec(windowsPaths(String.raw`C:\Users\ME\Apps`), "user").name).not.toBe(platform.taskSpec(windowsPaths(String.raw`C:\Users\ME\Other`), "user").name);
    expect(platform.taskSpec(windowsPaths(), "system").name).toBe("NexusEdge-System");
  });

  test("re-enabling an existing login task preserves its principal and derives its trigger from that identity", () => {
    const script = platform.buildTaskScript(taskFixture("user").spec);
    expect(script).toContain("$principal = $t.Principal\n  $sid = $principal.UserId");
    expect(script).toContain("} else {\n  $principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited\n}");
    expect(script).toContain("$trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid");
    expect(script).toContain("$t.Principal.LogonType -notin @('Interactive', '3')");
  });
});

describe("actual task status validation", () => {
  test("accepts a matching SYSTEM boot task and optional interactive user task", () => {
    for (const mode of ["system", "user"] as const) {
      const { spec, snapshot } = taskFixture(mode);
      const status = platform.assessTask(spec, snapshot);
      expect(status.enabled).toBe(true);
      expect(status.running).toBe(true);
      expect(status.mode).toBe(mode === "system" ? "windows-system" : "windows-user");
    }
  });

  test("existence alone does not certify principal, trigger, action, power policy or duration", () => {
    const mutations = [
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.principal.userId = "S-1-5-21-999"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.principal.logonType = "Interactive"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.principal.runLevel = "Limited"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.triggers[0]!.type = "MSFT_TaskLogonTrigger"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.actions[0]!.execute = String.raw`C:\Users\Someone\bun.exe`; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.actions[0]!.arguments = 'run "wrong.ts" --worker'; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.actions[0]!.workingDirectory = String.raw`C:\Windows`; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.executionTimeLimit = "PT72H"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.allowBattery = false; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.keepOnBattery = false; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.multipleInstances = "Parallel"; },
      (task: ReturnType<typeof taskFixture>["snapshot"]) => { task.description = "someone else's task"; },
    ];
    for (const mutate of mutations) {
      const { spec, snapshot } = taskFixture();
      mutate(snapshot);
      expect(platform.assessTask(spec, snapshot).enabled).toBe(false);
      expect(platform.assessTask(spec, snapshot).detail).toContain("异常");
    }
  });

  test("removing automatic triggers preserves running status and manual management mode", () => {
    const { spec, snapshot } = taskFixture();
    snapshot.triggers = [];
    expect(platform.assessTask(spec, snapshot)).toMatchObject({ mode: "windows-system", enabled: false, running: true });
    expect(platform.assessTask(spec, snapshot).detail).not.toContain("异常");
    expect(platform.assessTask(spec, null)).toMatchObject({ mode: "none", enabled: false, running: false });
  });

  test("disabled tasks and disabled triggers are not reported as enabled", () => {
    const { spec, snapshot } = taskFixture();
    snapshot.taskEnabled = false;
    expect(platform.assessTask(spec, snapshot).enabled).toBe(false);
    snapshot.taskEnabled = true;
    snapshot.triggers[0]!.enabled = false;
    expect(platform.assessTask(spec, snapshot).enabled).toBe(false);
  });

  test("accepts numeric CIM enums and case-insensitive Windows paths", () => {
    const { spec, snapshot } = taskFixture();
    snapshot.principal.logonType = "5";
    snapshot.principal.runLevel = "1";
    snapshot.multipleInstances = "2";
    snapshot.state = "4";
    snapshot.actions[0]!.execute = snapshot.actions[0]!.execute.toUpperCase();
    snapshot.actions[0]!.workingDirectory = snapshot.actions[0]!.workingDirectory.toUpperCase();
    expect(platform.assessTask(spec, snapshot)).toMatchObject({ enabled: true, running: true });
  });

  test("an alternate UAC administrator can manage the original user's owned login task", () => {
    const { spec, snapshot } = taskFixture("user");
    snapshot.currentSid = "S-1-5-21-123-456-789-1002";
    expect(platform.assessTask(spec, snapshot).enabled).toBe(false);
    snapshot.currentIsAdmin = true;
    expect(platform.assessTask(spec, snapshot).enabled).toBe(true);
    snapshot.principal.userId = "S-1-5-18";
    snapshot.triggers[0]!.userId = "S-1-5-18";
    expect(platform.assessTask(spec, snapshot).enabled).toBe(false);
  });
});

describe("Linux service definition", () => {
  test("keeps worker in the service cgroup, preserves argv and does not revive clean shutdowns", () => {
    const paths = createPaths('/opt/a path/$name%foo/"quoted"/nexus-edge.ts', "/opt/a path/runtime/bun");
    const unit = platform.systemdUnit(paths);
    expect(unit).toContain("Type=simple\nUser=root\n");
    expect(unit).toContain('ExecStart="/opt/a path/runtime/bun" "/opt/a path/$$name%%foo/\\"quoted\\"/nexus-edge.ts" "--worker"');
    expect(unit).toContain('WorkingDirectory=/opt/a path/$name%%foo/"quoted"');
    expect(unit).toContain("Restart=on-failure");
    expect(unit).toContain("KillMode=control-group");
    expect(unit).toContain("UMask=0077");
    expect(unit).not.toContain("Restart=always");
    expect(unit).not.toContain("/bin/sh");
  });

  test("rejects unit directive injection through path control characters", () => {
    for (const value of ["/opt/x\nExecStart=bad", "/opt/x\r", "/opt/x\0"]) expect(() => platform.quoteSystemd(value, true)).toThrow();
    for (const value of ["relative/path", "/opt/x\nExecStart=bad", "/opt/x\r", "/opt/x\0"]) expect(() => platform.systemdWorkingDirectory(value)).toThrow();
  });

  test.skipIf(process.platform !== "linux" || !fs.existsSync("/usr/bin/systemd-analyze") || !fs.existsSync("/usr/lib/systemd/system/sysinit.target"))("systemd's own parser accepts the generated unit with real paths containing spaces and specifier characters", () => {
    const directory = temporaryDir();
    const fixture = path.join(directory, "space %specifier $name O'Brien 测试");
    fs.mkdirSync(fixture);
    const entry = path.join(fixture, "nexus-edge.ts");
    fs.writeFileSync(entry, "// Never executed by this syntax test.\n");
    const unitFile = path.join(directory, "nexus-edge.service");
    fs.writeFileSync(unitFile, platform.systemdUnit(createPaths(entry, process.execPath)));
    const result = cp.spawnSync("/usr/bin/systemd-analyze", ["verify", unitFile], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) throw new Error(`systemd-analyze verify: ${result.error?.message || result.stderr || result.stdout}`);
    expect(result.status).toBe(0);
  });
});

describe("protected copy boundary", () => {
  test("prepared and legacy copies remain undiscoverable until an explicit active marker", () => {
    const paths = createPaths("/opt/nexus-edge/nexus-edge.ts", "/opt/nexus-edge/runtime/bun");
    const prepared = platform.makeInstallMarker(paths, false);
    expect(prepared.active).toBe(false);
    expect(platform.installMarkerActive(prepared, paths)).toBe(false);
    const legacy = { schema: 1, app: "NexusEdge", entry: paths.entry, runtime: paths.runtime };
    expect(platform.installMarkerActive(legacy, paths)).toBe(false);
    expect(platform.installMarkerActive({ ...legacy, active: "true" }, paths)).toBe(false);
    const activated = platform.makeInstallMarker(paths, true);
    expect(platform.installMarkerActive(activated, paths)).toBe(true);
    expect(platform.installMarkerActive({ ...activated, entry: "/tmp/untrusted/nexus-edge.ts" }, paths)).toBe(false);
    expect(platform.installMarkerActive({ ...activated, runtime: "/tmp/untrusted/bun" }, paths)).toBe(false);
    expect(platform.installMarkerActive({ ...activated, active: false }, paths)).toBe(false);
  });

  test("copies ordinary binary and metadata files without following links", () => {
    const dir = temporaryDir();
    const source = path.join(dir, "source"), destination = path.join(dir, "target");
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, "core"), Buffer.from([0, 1, 2, 255]), { mode: 0o755 });
    fs.writeFileSync(path.join(source, "asset.json"), '{"version":"1"}', { mode: 0o600 });
    platform.copyRegularTree(source, destination);
    expect(fs.readFileSync(path.join(destination, "core"))).toEqual(Buffer.from([0, 1, 2, 255]));
    expect(fs.readFileSync(path.join(destination, "asset.json"), "utf8")).toBe('{"version":"1"}');
    if (process.platform !== "win32") {
      expect(fs.statSync(path.join(destination, "core")).mode & 0o777).toBe(0o700);
      expect(fs.statSync(path.join(destination, "asset.json")).mode & 0o777).toBe(0o600);
    }
  });

  test.skipIf(process.platform === "win32")("rejects source symlinks and destination symlinks", () => {
    const dir = temporaryDir();
    fs.writeFileSync(path.join(dir, "secret"), "leave me alone");
    fs.symlinkSync(path.join(dir, "secret"), path.join(dir, "source-link"));
    expect(() => platform.copyRegularTree(path.join(dir, "source-link"), path.join(dir, "copied"))).toThrow("链接");
    fs.writeFileSync(path.join(dir, "input"), "new data");
    fs.symlinkSync(path.join(dir, "secret"), path.join(dir, "destination-link"));
    expect(() => platform.copyRegularTree(path.join(dir, "input"), path.join(dir, "destination-link"))).toThrow("链接");
    expect(fs.readFileSync(path.join(dir, "secret"), "utf8")).toBe("leave me alone");
  });

  test.skipIf(process.platform === "win32")("read-only files under a user-writable ancestor do not count as protected", () => {
    const dir = temporaryDir();
    const entry = path.join(dir, "nexus-edge.ts");
    fs.writeFileSync(entry, "// fixture", { mode: 0o444 });
    fs.chmodSync(dir, 0o777);
    expect(platform.linuxProtected(entry)).toBe(false);
  });
});
