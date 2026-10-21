import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as cp from "node:child_process";
import { createDefaultNode, createPaths, defaultConfig, type AppConfig, type AppPaths, type NodeConfig, type NodeProtocol } from "../src/core.ts";
import { applyFirewallPlan, buildFirewallPlan, firewallInternals as fw, firewallScope, inspectFirewallPlan, readFirewallRecord, runFirewallCommand, validateFirewallPlan, writeFirewallRecord, type FirewallPlan, type FirewallResult, type FirewallStatus } from "../src/firewall.ts";

const dirs: string[] = [];
function tempPaths(): AppPaths {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-firewall-test-")); dirs.push(root);
  return createPaths(path.join(root, "nexus-edge.ts"), process.execPath);
}
afterEach(() => { for (const directory of dirs.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
function winPaths(root = String.raw`C:\NexusEdge`): AppPaths {
  const result = createPaths(path.join("/tmp", "nexus-windows", "nexus-edge.ts"), process.execPath);
  return { ...result, root, bin: path.win32.join(root, ".nexus-edge", "bin") };
}
function node(protocol: NodeProtocol = "vless", overrides: Partial<NodeConfig> = {}): NodeConfig { return { ...createDefaultNode(protocol), ...overrides }; }
function config(nodes: NodeConfig[]): AppConfig { return { ...defaultConfig(), nodes }; }
function planFixture(nodes = [node()]): { paths: AppPaths; plan: FirewallPlan } { const paths = winPaths(); return { paths, plan: buildFirewallPlan(paths, config(nodes), "win32") }; }
function windowsReply(plan: FirewallPlan, status: FirewallStatus = "synced", patch: Record<string, unknown> = {}) {
  return {
    schema: 1, scope: plan.scope, fingerprint: plan.fingerprint, status, changed: false, detail: "测试防火墙状态", warnings: [],
    matchedPersistent: plan.rules.map(rule => rule.key), matchedActive: plan.rules.map(rule => rule.key), staleCount: 0,
    ownershipConflicts: 0, policyChecked: true, serviceRunning: true, ...patch,
  };
}
function response(value: unknown) { return { code: 0, stdout: JSON.stringify(value), stderr: "" }; }

describe("finite local inbound firewall plan", () => {
  test("NAT publicPort never becomes the local firewall port", () => {
    const { plan } = planFixture([node("vless", { port: 24443, publicPort: 443, address: "198.51.100.9" })]);
    expect(plan.rules.map(rule => rule.port)).toEqual([24443]);
    expect(plan.warnings.join(" ")).toContain("本地监听端口 24443");
    expect(plan.rules[0]!.destination).toBe("0.0.0.0/0");
  });

  test("disabled, tunnel-only, and every IPv4/IPv6 loopback spelling expose no port", () => {
    const listens = ["127.0.0.1", "127.20.30.40", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:7f14:1e28", "0:0:0:0:0:ffff:7f00:1"];
    const nodes = listens.map(listen => node("shadowsocks", { listen }));
    nodes.push(node("vless", { enabled: false }), node("vmess", { direct: false, listen: "0.0.0.0" }));
    expect(planFixture(nodes).plan.rules).toEqual([]);
  });

  test("maps core listening protocols, including QUIC and dynamic SOCKS UDP", () => {
    const nodes = [node("vless", { port: 20001 }), node("vmess", { port: 20002 }), node("shadowsocks", { port: 20003 }), node("hysteria2", { port: 20004 }), node("tuic", { port: 20005 }), node("socks", { port: 20006 }), node("trojan", { port: 20007 }), node("anytls", { port: 20008 }), node("naive", { port: 20009 })];
    const { plan } = planFixture(nodes);
    const pairs = plan.rules.map(rule => `${rule.protocol}/${rule.port}`).sort();
    expect(pairs).toEqual(["tcp/20001", "tcp/20002", "tcp/20003", "tcp/20006", "tcp/20007", "tcp/20008", "tcp/20009", "udp/20003", "udp/20004", "udp/20005"]);
    expect(plan.warnings.join(" ")).toContain("UDP 转发使用动态端口");
  });

  test("IPv6 wildcard covers both families; exact bind addresses remain exact", () => {
    const dual = planFixture([node("shadowsocks", { listen: "::" })]).plan;
    expect(dual.rules.map(rule => `${rule.protocol}/${rule.family}/${rule.destination}`)).toEqual(["tcp/4/0.0.0.0/0", "tcp/6/::/0", "udp/4/0.0.0.0/0", "udp/6/::/0"]);
    const exact = planFixture([node("vless", { listen: "2001:0DB8:0:0:0:0:0:4" }), node("vless", { listen: "::ffff:c000:204" })]).plan;
    expect(exact.rules.map(rule => [rule.family, rule.destination])).toEqual([[4, "192.0.2.4"], [6, "2001:db8::4"]]);
  });

  test("rules and fingerprints deduplicate deterministically and contain no secrets", () => {
    const a = node("shadowsocks", { port: 30000 }), b = node("vless", { port: 30001, listen: "192.0.2.7" });
    const original = planFixture([a, b, a]).plan, reordered = planFixture([b, a]).plan;
    expect(original.rules).toEqual(reordered.rules);
    expect(original.fingerprint).toBe(reordered.fingerprint);
    expect(JSON.stringify(original)).not.toContain(a.password);
    expect(JSON.stringify(original)).not.toContain(a.uuid);
    const secretChange = planFixture([{ ...a, uuid: "different-uuid", password: "different-password", address: "other.example", name: "new name" }, b]).plan;
    expect(secretChange.fingerprint).toBe(original.fingerprint);
    expect(original.rules.every(rule => /^[a-f0-9]{16}$/.test(rule.key))).toBe(true);
  });

  test("ownership is installation-scoped and Windows paths are case-insensitive", () => {
    expect(firewallScope(winPaths(String.raw`C:\Apps\Nexus`), "win32")).toBe(firewallScope(winPaths("c:\\apps\\nexus\\"), "win32"));
    expect(firewallScope(winPaths(String.raw`C:\Apps\Nexus`), "win32")).not.toBe(firewallScope(winPaths(String.raw`C:\Apps\Other`), "win32"));
    const paths = tempPaths();
    expect(firewallScope(paths, "linux")).not.toBe(firewallScope({ ...paths, root: paths.root.toUpperCase() }, "linux"));
  });

  test("valid maximum plan fits limits and malformed listeners never reach commands", () => {
    const nodes = Array.from({ length: 32 }, (_, i) => node("shadowsocks", { listen: "::", port: 40000 + i }));
    expect(planFixture(nodes).plan.rules).toHaveLength(128);
    expect(() => planFixture([...nodes, node()])).toThrow();
    for (const listen of ["localhost", "0.0.0.0; whoami", "fe80::1%eth0", "192.0.2.1/24", " 0.0.0.0"]) expect(() => planFixture([node("vless", { listen })])).toThrow();
    for (const port of [0, 65536, -1, NaN, 4.5]) expect(() => planFixture([node("vless", { port })])).toThrow();
  });
});

describe("helper plan validation", () => {
  test("accepts a canonical round trip and rejects cross-install replay", () => {
    const { plan } = planFixture([node("shadowsocks", { listen: "::" })]);
    expect(validateFirewallPlan(JSON.parse(JSON.stringify(plan)), plan.scope)).toEqual(plan);
    expect(() => validateFirewallPlan(plan, "a".repeat(20))).toThrow();
  });

  test("rejects unsupported protocols, all-port ranges, loopbacks and tampered rules", () => {
    const { plan } = planFixture();
    const invalid = [
      { protocol: "any" }, { port: "1-65535" }, { port: 0 }, { family: "4" }, { family: 6 },
      { destination: "Any" }, { destination: "127.0.0.1" }, { destination: "192.0.2.0/24" }, { destination: "::/0" },
      { destination: "0.0.0.0/0; Remove-NetFirewallRule" }, { key: "0".repeat(16) },
    ];
    for (const patch of invalid) expect(() => validateFirewallPlan({ ...plan, rules: [{ ...plan.rules[0], ...patch }] }, plan.scope)).toThrow();
    expect(() => validateFirewallPlan({ ...plan, rules: [...plan.rules, ...plan.rules] }, plan.scope)).toThrow();
    expect(() => validateFirewallPlan({ ...plan, fingerprint: "0".repeat(64) }, plan.scope)).toThrow();
    expect(() => validateFirewallPlan({ ...plan, warnings: ["x".repeat(601)] }, plan.scope)).toThrow();
  });
});

describe("Windows invocation and trustworthy results", () => {
  test("encoded loader is short and Unicode, quotes and shell syntax stay JSON data", () => {
    const paths = winPaths("C:\\测试\\O'Brien\\$(Remove-Item *)"), plan = buildFirewallPlan(paths, config([node()]), "win32");
    const command = fw.windowsCommand(paths, plan, "apply");
    expect(command.args).toContain("-EncodedCommand");
    expect(command.args.join(" ").length).toBeLessThan(3000);
    expect(command.args.join(" ")).not.toContain("O'Brien");
    const loader = Buffer.from(command.args.at(-1)!, "base64").toString("utf16le");
    expect(loader).toBe(fw.windowsLoader);
    expect(loader).toContain("InputEncoding");
    const envelope = JSON.parse(command.options.stdin);
    expect(envelope.payload.binRoot).toBe(path.win32.join(paths.root, ".nexus-edge", "bin") + "\\");
    const script = Buffer.from(envelope.script, "base64").toString("utf8");
    expect(script).toBe(fw.windowsScript);
    expect(script).toContain("检测到可能");
    expect(script).not.toContain("O'Brien");
    expect(script).not.toContain("Remove-Item");
  });

  test("maximum rule plan uses stdin without approaching Windows command-line limit", () => {
    const { paths, plan } = planFixture(Array.from({ length: 32 }, (_, i) => node("shadowsocks", { listen: "::", port: 50000 + i })));
    const command = fw.windowsCommand(paths, plan, "apply");
    expect(command.args.join(" ").length).toBeLessThan(3000);
    expect(Buffer.byteLength(command.options.stdin)).toBeLessThan(256 * 1024);
    expect(JSON.parse(command.options.stdin).payload.rules).toHaveLength(128);
  });

  test("script checks ownership, effective filters and policy; it never changes global defaults", () => {
    const script = fw.windowsScript;
    expect(script).toContain("[string]$rule.Group -ceq [string]$p.group");
    expect(script).toContain("[string]$rule.Description -ceq (Marker $key)");
    expect(script).toContain("-PolicyStore PersistentStore");
    expect(script).toContain("-PolicyStore ActiveStore");
    expect(script).toContain("Get-NetFirewallPortFilter");
    expect(script).toContain("Get-NetFirewallAddressFilter");
    expect(script).toContain("AllowLocalFirewallRules");
    expect(script).toContain("AllowInboundRules");
    expect(script).toContain("DomainAuthenticated");
    expect(script).toContain("Profile='Any'");
    expect(script).toContain("0.0.0.0-255.255.255.255");
    expect(script).toContain("OverrideBlockRules=$false");
    expect(script).not.toMatch(/Set-NetFirewallProfile|Disable-NetFirewall|Enable-NetFirewall|netsh|Start-Service|Stop-Service/);
    expect(script).not.toMatch(/Remove-NetFirewallRule[^\n]*(-Group|-DisplayGroup|\*)/);
    expect(script.indexOf("New-NetFirewallRule @parameters")).toBeLessThan(script.indexOf("# Verify every new desired rule"));
    expect(script.indexOf("# Verify every new desired rule")).toBeLessThan(script.indexOf("Remove-NetFirewallRule -PolicyStore"));
  });

  test("synced requires exact persistent and ACTIVE proof, not existence or exit code alone", () => {
    const { plan } = planFixture([node("shadowsocks")]);
    expect(fw.windowsResponse(plan, response(windowsReply(plan))).status).toBe("synced");
    for (const patch of [{ matchedActive: [] }, { matchedPersistent: [] }, { staleCount: 1 }, { policyChecked: false }, { ownershipConflicts: 1 }, { serviceRunning: false }, { fingerprint: "x" }, { scope: "x" }, { matchedActive: [plan.rules[0]!.key, plan.rules[0]!.key] }]) {
      expect(fw.windowsResponse(plan, response(windowsReply(plan, "synced", patch))).status).toBe("error");
    }
    expect(fw.windowsResponse(plan, { code: 0, stdout: "{}", stderr: "" }).status).toBe("error");
    expect(fw.windowsResponse(plan, { code: 0, stdout: "partial json", stderr: "" }).status).toBe("error");
    expect(fw.windowsResponse(plan, { code: 5, stdout: "", stderr: "denied" }).status).toBe("error");
    expect(fw.windowsResponse(plan, { code: 0, stdout: "incomplete result", stderr: "" }, "apply").changed).toBe(true);
  });

  test("permission, inactive, organization policy and partial failure remain distinct", async () => {
    const { paths, plan } = planFixture();
    for (const status of ["permission-required", "inactive", "unsupported", "blocked", "error", "needs-update"] as const) {
      const result = await applyFirewallPlan(paths, plan, { platform: "win32", runner: async () => response(windowsReply(plan, status, { changed: true })) });
      expect(result.status).toBe(status);
      expect(result.changed).toBe(true);
    }
  });

  test("maximum-size plan cannot crowd out an application-block warning", () => {
    const { plan } = planFixture();
    plan.warnings = Array.from({ length: 64 }, (_, i) => `节点 ${i} 的端口映射提示`);
    const result = fw.windowsResponse(plan, response(windowsReply(plan, "synced", { warnings: ["当前内核仍有应用程序阻止规则，需要核对。"] })));
    expect(result.warnings).toHaveLength(64);
    expect(result.warnings[0]).toContain("应用程序阻止规则");
  });

  test("unsupported OS performs no command, malformed IPC never dispatches", async () => {
    const paths = tempPaths(), cfg = config([node()]);
    let calls = 0;
    const runner = async () => { calls++; throw new Error("unexpected command"); };
    expect((await inspectFirewallPlan(paths, buildFirewallPlan(paths, cfg, "darwin"), { platform: "darwin", runner })).status).toBe("unsupported");
    await expect(applyFirewallPlan(paths, { ...buildFirewallPlan(paths, cfg), fingerprint: "tampered" }, { runner })).rejects.toThrow();
    expect(calls).toBe(0);
  });
});

describe("small sanitized status record", () => {
  test("record round trips without credentials and cannot substitute for an OS inspection", () => {
    const paths = tempPaths(), cfg = config([node("shadowsocks")]), plan = buildFirewallPlan(paths, cfg);
    const result: FirewallResult = { backend: "ufw", status: "synced", changed: true, detail: "端口已同步", rules: plan.rules, warnings: plan.warnings };
    writeFirewallRecord(paths, plan, result);
    expect(readFirewallRecord(paths)?.result).toEqual(result);
    const text = fs.readFileSync(path.join(paths.data, "firewall-state.json"), "utf8");
    expect(text).not.toContain(cfg.nodes[0]!.uuid);
    expect(text).not.toContain(cfg.nodes[0]!.password);
    if (process.platform !== "win32") expect(fs.statSync(path.join(paths.data, "firewall-state.json")).mode & 0o777).toBe(0o644);
    const tampered = JSON.parse(text); tampered.result.rules[0].port++;
    fs.writeFileSync(path.join(paths.data, "firewall-state.json"), JSON.stringify(tampered));
    expect(readFirewallRecord(paths)).toBeNull();
  });

  test("malformed, oversized, cross-install and symlink records are rejected", () => {
    const paths = tempPaths(); fs.mkdirSync(paths.data);
    const file = path.join(paths.data, "firewall-state.json");
    for (const content of ["{broken", "x".repeat(140 * 1024), JSON.stringify({ schema: 1, scope: "f".repeat(20) })]) { fs.writeFileSync(file, content); expect(readFirewallRecord(paths)).toBeNull(); }
    fs.unlinkSync(file);
    const target = path.join(paths.root, "elsewhere.json"); fs.writeFileSync(target, "untouched"); fs.symlinkSync(target, file);
    const plan = buildFirewallPlan(paths, config([]));
    expect(readFirewallRecord(paths)).toBeNull();
    expect(() => writeFirewallRecord(paths, plan, { backend: "none", status: "synced", changed: false, detail: "empty", warnings: [], rules: [] })).toThrow();
    expect(fs.readFileSync(target, "utf8")).toBe("untouched");
  });
});

describe("shell-free bounded command runner (ordinary processes only)", () => {
  test("preserves stdin and arguments without evaluating shell syntax", async () => {
    const argument = "$(whoami); `exit`; 'quoted'", input = "中文 stdin\n";
    const result = await runFirewallCommand(process.execPath, ["-e", "process.stdin.setEncoding('utf8');let s='';process.stdin.on('data',v=>s+=v);process.stdin.on('end',()=>process.stdout.write(JSON.stringify([process.argv[1],s])));", argument], { stdin: input });
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual([argument, input]);
  });
  test("missing executable and oversized input fail without firewall side effects", async () => {
    await expect(runFirewallCommand(path.join(tempPaths().root, "missing-exe"), [])).rejects.toThrow();
    await expect(runFirewallCommand(process.execPath, ["--version"], { stdin: "x".repeat(256 * 1024 + 1) })).rejects.toThrow();
  });
});

// Optional executable PowerShell coverage: every NetSecurity/Get-Service command
// below is an in-memory mock. This works with a portable Linux pwsh and never
// invokes the host's real firewall, even when the tests run as an administrator.
const powershellTest = process.env.NEXUS_FIREWALL_PWSH ? test : test.skip;
function mockWindowsRule(plan: FirewallPlan, rule = plan.rules[0]!) {
  return {
    Name: `NexusEdge-${plan.scope}-${rule.key}`, Group: `NexusEdge-${plan.scope}`, Description: `NexusEdge managed inbound v1; scope=${plan.scope}; key=${rule.key}`,
    DisplayName: "Managed test port", Enabled: "True", Direction: "Inbound", Action: "Allow", Profile: "Any", EdgeTraversalPolicy: "Block",
    MockPort: { Protocol: rule.protocol.toUpperCase(), LocalPort: [String(rule.port)], RemotePort: ["Any"] },
    MockAddress: { LocalAddress: [rule.destination], RemoteAddress: ["Any"] },
    MockApp: { Program: "Any", Package: "Any" }, MockService: { Service: "Any" }, MockInterface: { InterfaceAlias: ["Any"] },
    MockInterfaceType: { InterfaceType: "Any" }, MockSecurity: { Authentication: "NotRequired", Encryption: "NotRequired", OverrideBlockRules: false },
  };
}

const WINDOWS_MOCKS = String.raw`
$script:mockRules = @($p.fixture.rules)
$script:mockEvents = @()
$script:mockNewCount = 0
function Save-Mock {
  @{rules=@($script:mockRules);events=@($script:mockEvents)} | ConvertTo-Json -Depth 12 -Compress | Set-Content -LiteralPath $p.fixture.stateFile -Encoding UTF8
}
function Add-MockEvent($action, $name) { $script:mockEvents += @{action=$action;name=$name}; Save-Mock }
function Get-Service { [CmdletBinding()] param($Name) [pscustomobject]@{Status=$p.fixture.service} }
function Get-NetFirewallRule {
  [CmdletBinding()] param($PolicyStore, $Name)
  Add-MockEvent ('read-' + $PolicyStore) $Name
  if ($p.fixture.denied) { throw [UnauthorizedAccessException]::new('mock access denied') }
  foreach ($rule in @($script:mockRules)) {
    if ($Name -and [string]$rule.Name -ne [string]$Name) { continue }
    if ($PolicyStore -eq 'ActiveStore' -and [string]$rule.Name -in @($p.fixture.missingActive)) { continue }
    $rule
  }
}
function Get-NetFirewallProfile {
  [CmdletBinding()] param($PolicyStore)
  foreach ($name in @('Domain','Private','Public')) { [pscustomobject]@{Name=$name;Enabled=$p.fixture.enabled;AllowLocalFirewallRules=$p.fixture.localMerge;AllowInboundRules=$p.fixture.allowInbound;DefaultInboundAction=$p.fixture.defaultInbound} }
}
function Get-NetConnectionProfile { [CmdletBinding()] param() [pscustomobject]@{NetworkCategory=$p.fixture.networkCategory} }
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockPort } }
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockAddress } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockApp } }
function Get-NetFirewallServiceFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockService } }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockInterface } }
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockInterfaceType } }
function Get-NetFirewallSecurityFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject.MockSecurity } }
function Make-MockRule($v) {
  return [pscustomobject]@{
    Name=$v.Name;Group=$v.Group;Description=$v.Description;DisplayName=$v.DisplayName;Enabled=$v.Enabled;Direction=$v.Direction;Action=$v.Action;Profile=$v.Profile;EdgeTraversalPolicy=$v.EdgeTraversalPolicy
    MockPort=[pscustomobject]@{Protocol=$v.Protocol;LocalPort=@($v.LocalPort);RemotePort=@($v.RemotePort)}
    MockAddress=[pscustomobject]@{LocalAddress=@($v.LocalAddress);RemoteAddress=@($v.RemoteAddress)}
    MockApp=[pscustomobject]@{Program=$v.Program;Package='Any'};MockService=[pscustomobject]@{Service=$v.Service}
    MockInterface=[pscustomobject]@{InterfaceAlias=@($v.InterfaceAlias)};MockInterfaceType=[pscustomobject]@{InterfaceType=$v.InterfaceType}
    MockSecurity=[pscustomobject]@{Authentication=$v.Authentication;Encryption=$v.Encryption;OverrideBlockRules=$v.OverrideBlockRules}
  }
}
function New-NetFirewallRule {
  [CmdletBinding()] param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Enabled,$Direction,$Action,$Profile,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$Program,$Service,$InterfaceAlias,$InterfaceType,$EdgeTraversalPolicy,$Authentication,$Encryption,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping)
  $script:mockNewCount++
  if ($p.fixture.failNewAt -eq $script:mockNewCount) { throw 'mock new-rule failure' }
  $script:mockRules += (Make-MockRule $PSBoundParameters)
  Add-MockEvent 'new' $Name
}
function Set-NetFirewallRule {
  [CmdletBinding()] param($PolicyStore,$Name,$NewDisplayName,$Description,$Enabled,$Direction,$Action,$Profile,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$Program,$Service,$InterfaceAlias,$InterfaceType,$EdgeTraversalPolicy,$Authentication,$Encryption,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping)
  $old = @($script:mockRules | Where-Object { $_.Name -eq $Name })
  $values = @{}; foreach ($key in $PSBoundParameters.Keys) { $values[$key] = $PSBoundParameters[$key] }
  $values.Group=$old[0].Group; $values.DisplayName=$NewDisplayName
  $script:mockRules = @($script:mockRules | Where-Object { $_.Name -ne $Name }) + @((Make-MockRule $values))
  Add-MockEvent 'set' $Name
}
function Remove-NetFirewallRule {
  [CmdletBinding()] param($PolicyStore,$Name)
  $script:mockRules = @($script:mockRules | Where-Object { $_.Name -ne $Name })
  Add-MockEvent 'remove' $Name
}
Save-Mock
`;

function runPowerShellFixture(plan: FirewallPlan, fixture: Record<string, unknown> = {}, operation: "inspect" | "apply" = "inspect", administrator = true) {
  const paths = tempPaths(), stateFile = path.join(paths.root, "mock-state.json");
  const command = fw.windowsCommand(winPaths(), plan, operation), envelope = JSON.parse(command.options.stdin);
  const principalCheck = "$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
  expect(fw.windowsScript).toContain(principalCheck);
  // Only the host-specific identity probe is replaced. Actual rule planning,
  // mutation ordering, policy checks and verification execute unchanged.
  const body = WINDOWS_MOCKS + "\n" + fw.windowsScript.replace(principalCheck, `$admin = $${administrator ? "true" : "false"}`);
  envelope.script = Buffer.from(body, "utf8").toString("base64");
  envelope.payload.fixture = { rules: [], service: "Running", enabled: "True", localMerge: "True", allowInbound: "True", defaultInbound: "Block", networkCategory: "Public", missingActive: [], stateFile, ...fixture };
  if (fixture.binRoot) envelope.payload.binRoot = fixture.binRoot;
  if (fixture.programs) envelope.payload.programs = fixture.programs;
  const result = cp.spawnSync(process.env.NEXUS_FIREWALL_PWSH!, command.args, {
    input: JSON.stringify(envelope), encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024,
    env: { ...process.env, XDG_CACHE_HOME: path.join(paths.root, "cache"), XDG_CONFIG_HOME: path.join(paths.root, "config"), XDG_DATA_HOME: path.join(paths.root, "data") },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Mock PowerShell exited ${result.status}: ${result.stderr}`);
  const raw = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  const state = JSON.parse(fs.readFileSync(stateFile, "utf8").replace(/^\uFEFF/, "")) as { rules: ReturnType<typeof mockWindowsRule>[]; events: { action: string; name?: string }[] };
  return { raw, result: fw.windowsResponse(plan, { code: result.status, stdout: result.stdout, stderr: result.stderr }), state };
}

describe("PowerShell execution with in-memory NetSecurity mocks (optional NEXUS_FIREWALL_PWSH)", () => {
  powershellTest("actual script recognizes persisted/effective rules and needs-update without writes", () => {
    const { plan } = planFixture([node("shadowsocks", { listen: "::" })]);
    const missing = runPowerShellFixture(plan);
    expect(missing.result.status).toBe("needs-update");
    expect(missing.state.events.every(event => event.action.startsWith("read-"))).toBe(true);
    const present = runPowerShellFixture(plan, { rules: plan.rules.map(rule => mockWindowsRule(plan, rule)) });
    expect(present.result.status).toBe("synced");
    expect(present.result.changed).toBe(false);
  });

  powershellTest("apply adds before pruning, retains unrelated rules and is idempotent", () => {
    const { plan } = planFixture([node("shadowsocks", { port: 24443 })]);
    const oldRule = mockWindowsRule(plan, fw.makeRule("tcp", 24444, 4, "0.0.0.0/0"));
    const unrelated = { ...oldRule, Name: "some-other-rule", Group: "Other product", Description: "not owned" };
    const first = runPowerShellFixture(plan, { rules: [oldRule, unrelated] }, "apply");
    expect(first.result.status).toBe("synced");
    expect(first.result.changed).toBe(true);
    const mutations = first.state.events.filter(event => ["new", "set", "remove"].includes(event.action));
    expect(mutations.map(event => event.action)).toEqual(["new", "new", "remove"]);
    expect(mutations.at(-1)!.name).toBe(oldRule.Name);
    expect(first.state.rules.some(rule => rule.Name === unrelated.Name)).toBe(true);
    const second = runPowerShellFixture(plan, { rules: first.state.rules }, "apply");
    expect(second.result.status).toBe("synced");
    expect(second.result.changed).toBe(false);
    expect(second.state.events.some(event => event.action === "new" || event.action === "remove" || event.action === "set")).toBe(false);
  });

  powershellTest("owned shape is repaired but foreign ownership is never overwritten", () => {
    const { plan } = planFixture(), original = mockWindowsRule(plan);
    const damaged = { ...original, Enabled: "False", Profile: "Private", MockPort: { ...original.MockPort, LocalPort: ["9999"] } };
    const repaired = runPowerShellFixture(plan, { rules: [damaged] }, "apply");
    expect(repaired.result.status).toBe("synced");
    expect(repaired.state.events.filter(event => event.action === "set")).toHaveLength(1);
    const foreign = runPowerShellFixture(plan, { rules: [{ ...original, Description: "Someone else's rule" }] }, "apply");
    expect(foreign.result.status).toBe("blocked");
    expect(foreign.state.events.every(event => event.action.startsWith("read-"))).toBe(true);
  });

  powershellTest("partial creation or ineffective new rules preserve all previous owned rules", () => {
    const { plan } = planFixture([node("shadowsocks")]), oldRule = mockWindowsRule(plan, fw.makeRule("tcp", 8389, 4, "0.0.0.0/0"));
    const partial = runPowerShellFixture(plan, { rules: [oldRule], failNewAt: 2 }, "apply");
    expect(partial.result.status).toBe("error");
    expect(partial.result.changed).toBe(true);
    expect(partial.state.rules.some(rule => rule.Name === oldRule.Name)).toBe(true);
    expect(partial.state.events.some(event => event.action === "remove")).toBe(false);
    const ineffective = runPowerShellFixture(plan, { rules: [oldRule], missingActive: [`NexusEdge-${plan.scope}-${plan.rules[0]!.key}`] }, "apply");
    expect(ineffective.result.status).toBe("blocked");
    expect(ineffective.result.changed).toBe(true);
    expect(ineffective.state.events.some(event => event.action === "remove")).toBe(false);
  });

  powershellTest("permissions, stopped service, profile merge and shields-up retain accurate outcomes", () => {
    const { plan } = planFixture();
    expect(runPowerShellFixture(plan, {}, "apply", false).result.status).toBe("permission-required");
    const stopped = runPowerShellFixture(plan, { service: "Stopped" });
    expect(stopped.result.status).toBe("inactive");
    expect(stopped.state.events).toEqual([]);
    expect(runPowerShellFixture(plan, { denied: true }).result.status).toBe("permission-required");
    expect(runPowerShellFixture(plan, { localMerge: "False" }).result.status).toBe("blocked");
    expect(runPowerShellFixture(plan, { allowInbound: "False", defaultInbound: "Block", networkCategory: "DomainAuthenticated" }).result.status).toBe("blocked");
    expect(runPowerShellFixture(plan, { allowInbound: "False", defaultInbound: "Allow" }).result.status).toBe("inactive");
  });

  powershellTest("full global blocks gate but source IP bans only warn", () => {
    const { plan } = planFixture(), allow = mockWindowsRule(plan);
    const block = { ...allow, Name: "foreign-block", Group: "System", Description: "External policy", DisplayName: "Existing block rule", Action: "Block" };
    const blocked = runPowerShellFixture(plan, { rules: [allow, block] });
    expect(blocked.result.status).toBe("blocked");
    const ipBan = { ...block, MockAddress: { ...block.MockAddress, RemoteAddress: ["198.51.100.9"] } };
    const partial = runPowerShellFixture(plan, { rules: [allow, ipBan] });
    expect(partial.result.status).toBe("synced");
    expect(partial.result.warnings.join(" ")).toContain("部分来源");
    expect(partial.state.rules.some(rule => rule.Name === block.Name)).toBe(true);
    const ipsecOnly = { ...block, MockSecurity: { ...block.MockSecurity, Authentication: "Required" } };
    const conditional = runPowerShellFixture(plan, { rules: [allow, ipsecOnly] });
    expect(conditional.result.status).toBe("synced");
    expect(conditional.result.warnings).not.toEqual([]);
  });

  powershellTest("current core app-deny rules warn and obsolete cached app rules do not gate", () => {
    const { plan } = planFixture(), allow = mockWindowsRule(plan), root = tempPaths().root;
    const program = path.join(root, "selected", "xray.exe"), old = path.join(root, "old", "xray.exe");
    const block = { ...allow, Name: "app-denied", Group: "System", Description: "App denied prompt", DisplayName: "Denied Xray", Action: "Block", MockApp: { Program: program, Package: "Any" } };
    const current = runPowerShellFixture(plan, { rules: [allow, block], binRoot: root + path.sep, programs: [program] });
    expect(current.result.status).toBe("synced");
    expect(current.result.warnings.join(" ")).toContain("Denied Xray");
    expect(current.result.warnings.join(" ")).toContain("程序：");
    const obsolete = runPowerShellFixture(plan, { rules: [allow, { ...block, MockApp: { Program: old, Package: "Any" } }], binRoot: root + path.sep, programs: [program] });
    expect(obsolete.result.status).toBe("synced");
    expect(obsolete.result.warnings).toEqual([]);
  });

  powershellTest("empty reconciliation removes only owned rules without requiring active profiles", () => {
    const { plan } = planFixture(), allow = mockWindowsRule(plan), empty = fw.makePlan(plan.scope, []);
    const foreign = { ...allow, Name: "foreign", Group: "Other", Description: "not owned" };
    const removed = runPowerShellFixture(empty, { rules: [allow, foreign], service: "Stopped", localMerge: "False" }, "apply");
    expect(removed.result.status).toBe("synced");
    expect(removed.state.rules.map(rule => rule.Name)).toEqual(["foreign"]);
  });
});
