import { describe, expect, test } from "bun:test";
import * as cp from "node:child_process";
import * as path from "node:path";
import { hostIpv6Internals as ipv6, inspectHostIpv6, runHostIpv6Helper, setHostIpv6Enabled, type HostIpv6Dependencies, type HostIpv6LinuxSnapshot } from "../src/ipv6.ts";

/** 创建内存内核和策略文件替身；所有读写均隔离，绝不操作宿主网络。 */
function linuxFixture(original: HostIpv6LinuxSnapshot = { all: 0, default: 0, lo: 0, eth0: 0 }) {
  const state = { values: { ...original }, policy: null as string | null, events: [] as string[], failOnce: "" };
  const deps: HostIpv6Dependencies = {
    platform: "linux", isAdministrator: () => true,
    powerShell: async () => { throw new Error("Linux 不应调用 PowerShell"); },
    linuxRead: () => ({ ...state.values }), linuxReadPolicy: () => state.policy,
    linuxWritePolicy: content => { state.events.push("policy"); state.policy = content; },
    linuxWrite: (name, disabled) => {
      state.events.push(`${name}=${disabled}`);
      if (state.failOnce === name) { state.failOnce = ""; throw new Error(`${name} 写入被拒绝`); }
      if (name === "all") for (const key of Object.keys(state.values)) state.values[key] = disabled;
      else state.values[name] = disabled;
    },
  };
  return { state, deps };
}

describe("本机 Linux IPv6 开关", () => {
  test("读各接口判断状态，不能把 conf/all 当作是否已全部禁用", async () => {
    const env = linuxFixture({ all: 1, default: 1, lo: 0, eth0: 1 });
    const status = await inspectHostIpv6(env.deps);
    expect(status.state).toBe("mixed");
    expect(status.interfaces).toEqual([{ name: "lo", enabled: true }, { name: "eth0", enabled: false }]);
    expect(status.defaultEnabled).toBe(false);
    expect(env.state.events).toEqual([]);
  });

  test("禁用和重新开启同时更新现有接口、后续接口默认值和自有策略", async () => {
    const env = linuxFixture();
    const disabled = await setHostIpv6Enabled(false, env.deps);
    expect(disabled.state).toBe("disabled");
    expect(disabled.defaultEnabled).toBe(false);
    expect(disabled.persistedEnabled).toBe(false);
    expect(env.state.events.slice(0, 3)).toEqual(["policy", "all=1", "default=1"]);
    expect(env.state.policy).toBe(ipv6.policy(false));
    const enabled = await setHostIpv6Enabled(true, env.deps);
    expect(enabled.state).toBe("enabled");
    expect(enabled.defaultEnabled).toBe(true);
    expect(env.state.policy).toBe(ipv6.policy(true));
    expect(enabled.persistedEnabled).toBe(true);
  });

  test("部分写入失败恢复混合开关原值及原持久化内容", async () => {
    const before: HostIpv6LinuxSnapshot = { all: 0, default: 1, lo: 0, eth0: 1, "eth0.42": 0 };
    const env = linuxFixture(before);
    const policy = env.state.policy = ipv6.policy(true);
    env.state.failOnce = "default";
    await expect(setHostIpv6Enabled(false, env.deps)).rejects.toThrow("已恢复原接口开关");
    expect(env.state.values).toEqual(before);
    expect(env.state.policy).toBe(policy);
  });

  test("新建持久化配置失败时不修改 live 网络开关", async () => {
    const env = linuxFixture();
    env.deps.linuxWritePolicy = () => { throw new Error("配置文件只读"); };
    await expect(setHostIpv6Enabled(false, env.deps)).rejects.toThrow("配置文件只读");
    expect(env.state.events).toEqual([]);
    expect(env.state.values.eth0).toBe(0);
  });

  test("持久化替换后报错也恢复旧文件，不触碰 live 网络开关", async () => {
    const env = linuxFixture();
    let first = true;
    env.deps.linuxWritePolicy = content => {
      env.state.policy = content;
      if (first) { first = false; throw new Error("重命名后设置权限失败"); }
    };
    await expect(setHostIpv6Enabled(false, env.deps)).rejects.toThrow("重命名后设置权限失败");
    expect(env.state.policy).toBeNull();
    expect(env.state.events).toEqual([]);
  });

  test("验证失败会回滚，并单独报告无法恢复的接口", async () => {
    const env = linuxFixture();
    const write = env.deps.linuxWrite;
    env.deps.linuxWrite = (name, value) => {
      if (name === "default" && value === 1) throw new Error("default 被锁定");
      if (name === "eth0" && value === 0) throw new Error("eth0 已移除");
      write(name, value);
    };
    await expect(setHostIpv6Enabled(false, env.deps)).rejects.toThrow("eth0：eth0 已移除");
    expect(env.state.policy).toBeNull();
  });

  test("内核禁用 IPv6 或控制项不完整时不写配置", async () => {
    const env = linuxFixture({});
    expect((await inspectHostIpv6(env.deps)).state).toBe("unavailable");
    await expect(setHostIpv6Enabled(true, env.deps)).rejects.toThrow("完整 IPv6 控制项");
    expect(env.state.events).toEqual([]);
  });

  test("没有管理员权限和非布尔参数都在写入前拒绝", async () => {
    const env = linuxFixture(); env.deps.isAdministrator = () => false;
    await expect(setHostIpv6Enabled(false, env.deps)).rejects.toThrow("管理员");
    await expect(setHostIpv6Enabled("false" as never, env.deps)).rejects.toThrow("true 或 false");
    expect(env.state.events).toEqual([]);
  });

  test("helper 严格限制参数且不能接受路径、网卡名或额外选项", async () => {
    const env = linuxFixture();
    for (const args of [[], ["false"], ["enable", "eth0"], ["disable", "/etc/passwd"], ["enable; reboot"]]) await expect(runHostIpv6Helper(args, env.deps)).rejects.toThrow("enable 或 disable");
    expect(env.state.events).toEqual([]);
  });

  test("proc 路径只容许一个非控制字符路径段", () => {
    expect(ipv6.procFile("eth0.42")).toBe("/proc/sys/net/ipv6/conf/eth0.42/disable_ipv6");
    for (const value of ["", "..", ".", "../all", "eth0\\all", "eth0\n", "eth0\0"]) expect(() => ipv6.procFile(value)).toThrow();
  });
});

describe("本机 Windows IPv6 状态", () => {
  test("严格区分布尔开关，并接受空列表为不可管理", () => {
    expect(ipv6.windowsStatus("[]").state).toBe("unavailable");
    expect(ipv6.windowsStatus('[{"name":"以太网 [1]","enabled":true}]').state).toBe("enabled");
    expect(ipv6.windowsStatus('[{"name":"NIC 1","enabled":true},{"name":"NIC 2","enabled":false}]').state).toBe("mixed");
    for (const value of ["null", "{}", '[{"name":"NIC","enabled":"false"}]', "bad-json"]) expect(() => ipv6.windowsStatus(value)).toThrow();
  });

  test("只读查询脚本不包含绑定修改，写脚本仅使用系统返回的 CIM 对象", () => {
    expect(ipv6.windowsScript()).not.toContain("Set-NetAdapterBinding");
    expect(ipv6.windowsScript(false)).toContain("-ComponentID 'ms_tcpip6'");
    expect(ipv6.windowsScript(false)).toContain("-InputObject $item.binding");
    expect(ipv6.windowsScript(false)).not.toContain("-Name $item");
    expect(ipv6.windowsScript(false)).toContain("$desired = $false");
    expect(ipv6.windowsScript(true)).toContain("$desired = $true");
  });

  test("系统返回成功但目标状态不符时拒绝宣告完成", async () => {
    await expect(setHostIpv6Enabled(false, { platform: "win32", isAdministrator: () => true,
      powerShell: async () => '[{"name":"NIC","enabled":true}]' })).rejects.toThrow("状态与目标不一致");
  });
});

const psExecutable = process.platform === "win32" ? path.win32.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe") : process.env.NEXUS_FIREWALL_PWSH;

/**
 * 在真实 PowerShell 解析器中执行生产脚本，NetAdapter cmdlet 全部被内存函数覆盖。
 * 返回记录结果；任何函数缺失都会失败，测试不会触及真实网卡或注册表。
 */
function executeMockedWindows(enabled: boolean, mode: "success" | "fail" = "success"): { state: unknown[]; updates: string[]; error: string } {
  const script = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$script:bindings = @([pscustomobject]@{ Name = 'NIC [1]'; Enabled = $true }, [pscustomobject]@{ Name = '测试网卡'; Enabled = $false })
$script:updates = @()
$script:failure = ${mode === "fail" ? "$true" : "$false"}
function Get-NetAdapterBinding {
  param($Name, $ComponentID, [switch]$IncludeHidden, [switch]$AllBindings, $ErrorAction)
  if ($ComponentID -ne 'ms_tcpip6') { throw '意外修改其他协议' }
  return $script:bindings
}
function Set-NetAdapterBinding {
  param($InputObject, [bool]$Enabled, $Confirm, $ErrorAction)
  $script:updates += ($InputObject.Name + '=' + $Enabled)
  $InputObject.Enabled = $Enabled
  if ($script:failure -and $InputObject.Name -eq 'NIC [1]') { $script:failure = $false; throw '模拟网卡设置失败' }
}
$failureText = ''
try { $null = & { ${ipv6.windowsScript(enabled)} } } catch { $failureText = $_.Exception.Message }
ConvertTo-Json -Compress -Depth 6 -InputObject @{ state = @($script:bindings | ForEach-Object { @{ name = $_.Name; enabled = $_.Enabled } }); updates = @($script:updates); error = $failureText }
`;
  const result = cp.spawnSync(psExecutable!, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", windowsHide: true, timeout: 20000 });
  if (result.error || result.status !== 0) throw new Error(result.error?.message || result.stderr || `PowerShell 退出码 ${result.status}`);
  return JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
}

describe("真实 PowerShell 执行 IPv6 脚本（网卡 provider 全部替换）", () => {
  test.skipIf(!psExecutable)("按 CIM 对象禁用网卡且保留精确名称", () => {
    const result = executeMockedWindows(false);
    expect(result.error).toBe("");
    expect(result.state).toEqual([{ name: "NIC [1]", enabled: false }, { name: "测试网卡", enabled: false }]);
    expect(result.updates).toEqual(["NIC [1]=False"]);
  });
  test.skipIf(!psExecutable)("开启原本禁用的网卡", () => {
    const result = executeMockedWindows(true);
    expect(result.error).toBe("");
    expect(result.state).toEqual([{ name: "NIC [1]", enabled: true }, { name: "测试网卡", enabled: true }]);
    expect(result.updates).toEqual(["测试网卡=True"]);
  });
  test.skipIf(!psExecutable)("写失败恢复每个原始绑定状态并报告原错误", () => {
    const result = executeMockedWindows(false, "fail");
    expect(result.error).toContain("模拟网卡设置失败");
    expect(result.error).toContain("已恢复操作前的接口开关");
    expect(result.state).toEqual([{ name: "NIC [1]", enabled: true }, { name: "测试网卡", enabled: false }]);
  });
});
