import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { configFingerprint, createDefaultNode, createPaths, defaultConfig, type AppConfig } from "../src/core.ts";
import { buildFirewallPlan, type FirewallPlan, type FirewallRecord, type FirewallResult } from "../src/firewall.ts";
import { runFirewallRequest, syncFirewallBackground, syncFirewallInteractive, type FirewallControlDependencies } from "../src/firewall-control.ts";

// All OS inspection, mutation, privilege checks and elevation are injected.
// Only temporary request/configuration files are real in these tests.
const directories: string[] = [];
afterEach(() => { for (const dir of directories.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

function resultFor(plan: FirewallPlan, status: FirewallResult["status"] = "synced", changed = false): FirewallResult {
  return { backend: "ufw", status, changed, detail: `Synthetic ${status}`, warnings: plan.warnings, rules: plan.rules };
}

function scenario(config: AppConfig = { ...defaultConfig(), nodes: [createDefaultNode("shadowsocks")] }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-edge-firewall-control-")); directories.push(root);
  const paths = createPaths(path.join(root, "nexus-edge.ts"));
  fs.mkdirSync(paths.data, { mode: 0o700 });
  fs.writeFileSync(paths.config, JSON.stringify(config) + "\n", { mode: 0o600 });
  const original = fs.readFileSync(paths.config, "utf8");
  const calls = { inspect: 0, apply: 0, elevate: 0, records: [] as FirewallRecord[], plans: [] as FirewallPlan[] };
  let record: FirewallRecord | null = null;
  const deps: FirewallControlDependencies = {
    platform: process.platform,
    isAdministrator: () => false,
    inspect: async (_paths, plan) => { calls.inspect++; return resultFor(plan, "needs-update"); },
    apply: async (_paths, plan) => { calls.apply++; calls.plans.push(structuredClone(plan)); return resultFor(plan, "synced", true); },
    elevate: async (selected, args) => {
      calls.elevate++;
      expect(args).toHaveLength(2); expect(args[0]).toBe("--firewall-request");
      expect(await runFirewallRequest(selected, args[1]!, { ...deps, isAdministrator: () => true })).toBe(0);
    },
    readRecord: () => record,
    writeRecord: (_paths, plan, result) => {
      record = { schema: 1, scope: plan.scope, fingerprint: plan.fingerprint, updatedAt: new Date(deps.now()).toISOString(), result };
      calls.records.push(record);
    },
    now: () => Date.UTC(2026, 9, 21),
  };
  return { paths, config, original, calls, deps, setRecord: (next: FirewallRecord) => { record = next; } };
}

function requestFiles(s: ReturnType<typeof scenario>, nonce: string) {
  return { request: path.join(s.paths.data, `firewall-request-${nonce}.json`), result: path.join(s.paths.data, `firewall-result-${nonce}.json`) };
}

function noTemporaryRequests(s: ReturnType<typeof scenario>): void {
  expect(fs.readdirSync(s.paths.data).filter(name => /^firewall-(request|result)-/.test(name))).toEqual([]);
}

function changedConfiguration(s: ReturnType<typeof scenario>): string {
  const edited = structuredClone(s.config);
  edited.nodes[0]!.port++;
  const text = JSON.stringify(edited) + "\n";
  fs.writeFileSync(s.paths.config, text);
  return text;
}

describe("interactive firewall synchronization", () => {
  test("old schema-2 settings default to auto; one nonce elevation sends only finite port metadata", async () => {
    const s = scenario(), reports: FirewallResult[] = [];
    const elevated = s.deps.elevate;
    s.deps.elevate = async (selected, args) => {
      const files = requestFiles(s, args[1]!);
      const text = fs.readFileSync(files.request, "utf8"), request = JSON.parse(text);
      expect(Object.keys(request).sort()).toEqual(["schema", "nonce", "scope", "createdAt", "expectedConfigHash", "plan", "options"].sort());
      expect(request.plan.rules).toHaveLength(2);
      expect(request.expectedConfigHash).toBe(configFingerprint(s.config));
      expect(text).not.toContain(s.config.nodes[0]!.uuid);
      expect(text).not.toContain(s.config.nodes[0]!.password);
      expect(text).not.toContain('"nodes"');
      const originalStat = fs.statSync(files.result);
      await elevated(selected, args);
      const after = fs.statSync(files.result);
      expect(after.ino).toBe(originalStat.ino); expect(after.uid).toBe(originalStat.uid); expect(after.gid).toBe(originalStat.gid);
      expect(after.mode).toBe(originalStat.mode);
    };
    const result = await syncFirewallInteractive(s.paths, s.config, { report: value => reports.push(value) }, s.deps);
    expect(result?.status).toBe("synced"); expect(result?.changed).toBe(true);
    expect(s.calls.inspect).toBe(1); expect(s.calls.apply).toBe(1); expect(s.calls.elevate).toBe(1);
    expect(reports).toEqual([result!]); expect(s.calls.records).toHaveLength(1);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(s.original);
    expect(fs.existsSync(s.paths.bin)).toBe(false);
    noTemporaryRequests(s);
  });

  test("an administrator applies directly without spawning another elevated process", async () => {
    const s = scenario(); s.deps.isAdministrator = () => true;
    expect((await syncFirewallInteractive(s.paths, s.config, {}, s.deps))?.status).toBe("synced");
    expect(s.calls.inspect).toBe(0); expect(s.calls.apply).toBe(1); expect(s.calls.elevate).toBe(0);
    noTemporaryRequests(s);
  });

  test("inspection of real effective rules avoids UAC when already synchronized", async () => {
    const s = scenario();
    s.deps.inspect = async (_paths, plan) => { s.calls.inspect++; return resultFor(plan); };
    expect((await syncFirewallInteractive(s.paths, s.config, {}, s.deps))?.status).toBe("synced");
    expect(s.calls.inspect).toBe(1); expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("a saved successful record never substitutes for current nonempty rule inspection", async () => {
    const s = scenario(), plan = buildFirewallPlan(s.paths, s.config);
    s.setRecord({ schema: 1, scope: plan.scope, fingerprint: plan.fingerprint, updatedAt: new Date(s.deps.now()).toISOString(), result: resultFor(plan) });
    await syncFirewallInteractive(s.paths, s.config, {}, s.deps);
    expect(s.calls.inspect).toBe(1); expect(s.calls.elevate).toBe(1);
  });

  for (const status of ["blocked", "error", "inactive", "unsupported"] as const) {
    test(`${status} is reported without an unrelated elevation retry`, async () => {
      const s = scenario(); s.deps.inspect = async (_paths, plan) => resultFor(plan, status);
      expect((await syncFirewallInteractive(s.paths, s.config, {}, s.deps))?.status).toBe(status);
      expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
    });
  }

  test("manual mode is quiet, while an explicit synchronization still works", async () => {
    const s = scenario();
    s.config.firewall = { mode: "manual", linuxBackend: "auto", firewalldZone: "" };
    fs.writeFileSync(s.paths.config, JSON.stringify(s.config));
    expect(await syncFirewallInteractive(s.paths, s.config, {}, s.deps)).toBeNull();
    expect(s.calls.inspect).toBe(0); expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
    expect((await syncFirewallInteractive(s.paths, s.config, { force: true }, s.deps))?.status).toBe("synced");
    expect(s.calls.elevate).toBe(1);
  });

  test("a fresh tunnel-only/empty installation does not ask for administrator access", async () => {
    const s = scenario(defaultConfig());
    expect((await syncFirewallInteractive(s.paths, s.config, {}, s.deps))?.rules).toEqual([]);
    expect(s.calls.inspect).toBe(0); expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("explicit cleanup checks actual rules even without a record and passes an empty desired plan", async () => {
    const s = scenario();
    await syncFirewallInteractive(s.paths, s.config, { remove: true }, s.deps);
    expect(s.calls.inspect).toBe(1); expect(s.calls.elevate).toBe(1);
    expect(s.calls.plans[0]!.rules).toEqual([]);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(s.original);
  });

  test("disabling the last node still reconciles previously recorded rules", async () => {
    const s = scenario(), oldPlan = buildFirewallPlan(s.paths, s.config);
    s.setRecord({ schema: 1, scope: oldPlan.scope, fingerprint: oldPlan.fingerprint, updatedAt: new Date(s.deps.now()).toISOString(), result: resultFor(oldPlan) });
    const candidate = { ...s.config, nodes: [] };
    await syncFirewallInteractive(s.paths, candidate, {}, s.deps);
    expect(s.calls.plans[0]!.rules).toEqual([]); expect(s.calls.elevate).toBe(1);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(s.original);
  });

  test("UAC cancellation cleans transient files and preserves every byte of the saved config", async () => {
    const s = scenario(); s.deps.elevate = async () => { throw new Error("Synthetic UAC cancelled"); };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("UAC cancelled");
    expect(s.calls.apply).toBe(0); expect(s.calls.records).toHaveLength(0);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(s.original); noTemporaryRequests(s);
  });

  test("a stale caller snapshot aborts before any OS operation", async () => {
    const s = scenario();
    await expect(syncFirewallInteractive(s.paths, s.config, { expectedConfigHash: "0".repeat(64) }, s.deps)).rejects.toThrow("配置已在其他位置修改");
    expect(s.calls.inspect).toBe(0); expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("a concurrent edit during inspection aborts before elevation", async () => {
    const s = scenario(); let edited = "";
    s.deps.inspect = async (_paths, plan) => { edited = changedConfiguration(s); return resultFor(plan, "needs-update"); };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("配置已在其他位置修改");
    expect(s.calls.elevate).toBe(0); expect(s.calls.apply).toBe(0);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(edited);
  });

  test("a concurrent edit while UAC is pending prevents the child from changing rules", async () => {
    const s = scenario(), elevated = s.deps.elevate; let edited = "";
    s.deps.elevate = async (selected, args) => { edited = changedConfiguration(s); await elevated(selected, args); };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("配置已在其他位置修改");
    expect(s.calls.apply).toBe(0); expect(fs.readFileSync(s.paths.config, "utf8")).toBe(edited); noTemporaryRequests(s);
  });

  test("an edit during rule synchronization is detected after the child returns", async () => {
    const s = scenario(); let edited = "";
    s.deps.apply = async (_paths, plan) => { s.calls.apply++; edited = changedConfiguration(s); return resultFor(plan, "synced", true); };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("配置已在其他位置修改");
    expect(s.calls.apply).toBe(1); expect(s.calls.records).toHaveLength(0);
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(edited); noTemporaryRequests(s);
  });

  test("cache write failure does not turn a confirmed port operation into a false failure", async () => {
    const s = scenario(); s.deps.isAdministrator = () => true;
    s.deps.writeRecord = () => { throw new Error("Synthetic read-only cache"); };
    const result = await syncFirewallInteractive(s.paths, s.config, {}, s.deps);
    expect(result?.status).toBe("synced"); expect(result?.warnings.join(" ")).toContain("无法保存状态记录");
  });
});

describe("privileged firewall request boundaries", () => {
  for (const field of ["nonce", "scope", "fingerprint"] as const) {
    test(`rejects a returned ${field} from a different request`, async () => {
      const s = scenario(), elevated = s.deps.elevate;
      s.deps.elevate = async (selected, args) => {
        await elevated(selected, args);
        const file = requestFiles(s, args[1]!).result, receipt = JSON.parse(fs.readFileSync(file, "utf8"));
        receipt[field] = "different"; fs.writeFileSync(file, JSON.stringify(receipt));
      };
      await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("不匹配");
      expect(s.calls.records).toHaveLength(0); noTemporaryRequests(s);
    });
  }

  test("rejects a request for another installation before applying any rule", async () => {
    const s = scenario(), elevated = s.deps.elevate;
    s.deps.elevate = async (selected, args) => {
      const file = requestFiles(s, args[1]!).request, request = JSON.parse(fs.readFileSync(file, "utf8"));
      request.scope = "0".repeat(20); fs.writeFileSync(file, JSON.stringify(request));
      await elevated(selected, args);
    };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("不属于当前安装目录");
    expect(s.calls.apply).toBe(0); noTemporaryRequests(s);
  });

  test("rejects injected port/range text before reaching the firewall backend", async () => {
    const s = scenario(), elevated = s.deps.elevate;
    s.deps.elevate = async (selected, args) => {
      const file = requestFiles(s, args[1]!).request, request = JSON.parse(fs.readFileSync(file, "utf8"));
      request.plan.rules[0].port = "80; remove-all"; fs.writeFileSync(file, JSON.stringify(request));
      await elevated(selected, args);
    };
    await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("有限");
    expect(s.calls.apply).toBe(0); noTemporaryRequests(s);
  });

  test("rejects expired and oversized request files without a firewall operation", async () => {
    for (const oversized of [false, true]) {
      const s = scenario(), elevated = s.deps.elevate;
      s.deps.elevate = async (selected, args) => {
        const file = requestFiles(s, args[1]!).request, request = JSON.parse(fs.readFileSync(file, "utf8"));
        request.createdAt -= 31 * 60 * 1000;
        fs.writeFileSync(file, oversized ? " ".repeat(256 * 1024 + 1) : JSON.stringify(request));
        await elevated(selected, args);
      };
      await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow(oversized ? "文件过大" : "过期");
      expect(s.calls.apply).toBe(0); noTemporaryRequests(s);
    }
  });

  test("rejects traversal-shaped nonces without opening user-selected paths", async () => {
    const s = scenario();
    await expect(runFirewallRequest(s.paths, "../../outside", s.deps)).rejects.toThrow("请求 ID");
    expect(s.calls.apply).toBe(0);
  });

  test.skipIf(process.platform === "win32")("refuses symlink or hardlink receipts and preserves the target file", async () => {
    for (const hardlink of [false, true]) {
      const s = scenario(), elevated = s.deps.elevate;
      const target = path.join(s.paths.root, "unrelated-file.txt"); fs.writeFileSync(target, "must survive");
      s.deps.elevate = async (selected, args) => {
        const file = requestFiles(s, args[1]!).result; fs.unlinkSync(file);
        if (hardlink) fs.linkSync(target, file); else fs.symlinkSync(target, file);
        await elevated(selected, args);
      };
      await expect(syncFirewallInteractive(s.paths, s.config, {}, s.deps)).rejects.toThrow("普通文件");
      expect(s.calls.apply).toBe(0); expect(fs.readFileSync(target, "utf8")).toBe("must survive"); noTemporaryRequests(s);
    }
  });

  test("a non-elevated helper delivers permission-required without applying or re-elevating", async () => {
    const s = scenario();
    s.deps.elevate = async (selected, args) => { expect(await runFirewallRequest(selected, args[1]!, s.deps)).toBe(0); };
    expect((await syncFirewallInteractive(s.paths, s.config, {}, s.deps))?.status).toBe("permission-required");
    expect(s.calls.apply).toBe(0);
  });

  test("backend errors are delivered as a structured result instead of losing detail in a child exit code", async () => {
    const s = scenario(); s.deps.apply = async () => { throw new Error("Synthetic policy refused"); };
    const result = await syncFirewallInteractive(s.paths, s.config, {}, s.deps);
    expect(result?.status).toBe("error"); expect(result?.detail).toContain("Synthetic policy refused");
    expect(fs.readFileSync(s.paths.config, "utf8")).toBe(s.original); noTemporaryRequests(s);
  });
});

describe("background firewall synchronization", () => {
  test("an ordinary background worker only inspects and reports that the panel must authorize changes", async () => {
    const s = scenario();
    const result = await syncFirewallBackground(s.paths, s.config, s.deps);
    expect(result?.status).toBe("permission-required"); expect(result?.detail).toContain("后台不会请求提权");
    expect(s.calls.inspect).toBe(1); expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("a privileged worker applies rules for the installation root and records its result", async () => {
    const s = scenario(); s.deps.isAdministrator = () => true;
    expect((await syncFirewallBackground(s.paths, s.config, s.deps))?.status).toBe("synced");
    expect(s.calls.plans[0]!.scope).toBe(buildFirewallPlan(s.paths, s.config).scope);
    expect(s.calls.apply).toBe(1); expect(s.calls.inspect).toBe(0); expect(s.calls.elevate).toBe(0);
    expect(s.calls.records).toHaveLength(1);
  });

  test("manual and fresh empty configurations do not query the operating-system firewall", async () => {
    const s = scenario(); s.config.firewall = { mode: "manual", linuxBackend: "auto", firewalldZone: "" };
    expect(await syncFirewallBackground(s.paths, s.config, s.deps)).toBeNull();
    expect((await syncFirewallBackground(s.paths, defaultConfig(), s.deps))?.rules).toEqual([]);
    expect(s.calls.apply).toBe(0); expect(s.calls.inspect).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("a stale startup snapshot never prunes a newer configuration's rules", async () => {
    const s = scenario(); s.deps.isAdministrator = () => true; changedConfiguration(s);
    const result = await syncFirewallBackground(s.paths, s.config, s.deps);
    expect(result?.status).toBe("error"); expect(result?.detail).toContain("配置已在其他位置修改");
    expect(s.calls.apply).toBe(0); expect(s.calls.elevate).toBe(0);
  });

  test("backend failures are returned as status details so local core startup can continue", async () => {
    const s = scenario(); s.deps.isAdministrator = () => true;
    s.deps.apply = async () => { throw new Error("Synthetic backend unavailable"); };
    const result = await syncFirewallBackground(s.paths, s.config, s.deps);
    expect(result?.status).toBe("error"); expect(result?.detail).toContain("Synthetic backend unavailable");
    expect(s.calls.elevate).toBe(0);
  });
});
