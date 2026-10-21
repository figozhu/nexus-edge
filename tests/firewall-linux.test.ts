import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as sqlite from "bun:sqlite";
import { applyLinuxFirewall, inspectLinuxFirewall, transferLinuxUfwOwnership, linuxFirewallInternals as linux, type LinuxFirewallContext } from "../src/firewall-linux.ts";
import type { FirewallRule, FirewallPlan, FirewallOptions, FirewallCommandRunner, FirewallCommandResult } from "../src/firewall.ts";

const temporaryDirectories: string[] = [];
function context(): LinuxFirewallContext {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-firewall-linux-")); temporaryDirectories.push(directory);
  return { stateFile: path.join(directory, "firewall-linux-state.json") };
}
afterEach(() => { for (const directory of temporaryDirectories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
const scope = "0123456789abcdef0123", otherScope = "9876543210fedcba9876";
const auto: FirewallOptions = { linuxBackend: "auto", firewalldZone: "" };
function rule(port: number, protocol: "tcp" | "udp" = "tcp", family: 4 | 6 = 4, destination = family === 4 ? "0.0.0.0/0" : "::/0"): FirewallRule {
  const base = { port, protocol, family, destination };
  return { ...base, key: crypto.createHash("sha256").update(JSON.stringify([protocol, port, family, destination])).digest("hex").slice(0, 16) };
}
function plan(rules: FirewallRule[], id = scope): FirewallPlan { return { scope: id, fingerprint: crypto.createHash("sha256").update(JSON.stringify([id, rules])).digest("hex"), rules, warnings: [] }; }
function ok(stdout = ""): FirewallCommandResult { return { code: 0, stdout, stderr: "" }; }
function fail(stderr: string, code = 1): FirewallCommandResult { return { code, stdout: "", stderr }; }
const missing = () => fail("command not found", 127);

interface MockUfwRule { rule: FirewallRule; comment: string; action: "ALLOW" | "DENY"; source?: string }
class MockLinuxFirewall {
  manager: "ufw" | "firewalld" | "iptables" | "none" = "ufw";
  ufwRules: MockUfwRule[] = [];
  ufwMalformed: string[] = [];
  runtime = new Map<string, Set<string>>(); permanent = new Map<string, Set<string>>();
  activeZones = ["public"]; zones = ["public", "external", "internal"]; defaultZone = "public";
  v4: string[][] = [["-P", "INPUT", "DROP"], ["-P", "FORWARD", "ACCEPT"], ["-P", "OUTPUT", "ACCEPT"]];
  v6: string[][] = [["-P", "INPUT", "DROP"], ["-P", "FORWARD", "ACCEPT"], ["-P", "OUTPUT", "ACCEPT"]];
  nftChains: unknown[] = [];
  calls: { executable: string; args: string[] }[] = [];
  mutations: { executable: string; args: string[] }[] = [];
  intercept?: (executable: string, args: string[]) => FirewallCommandResult | undefined;
  async runner(executable: string, args: string[]): Promise<FirewallCommandResult> {
    this.calls.push({ executable, args: [...args] });
    const intercepted = this.intercept?.(executable, args); if (intercepted) return intercepted;
    if (executable === "ufw") {
      if (this.manager !== "ufw") return missing();
      if (args[0] === "status") return ok(this.ufwStatus());
      this.mutations.push({ executable, args: [...args] });
      const remove = args.includes("delete"), prepend = args[0] === "prepend";
      const spec = args.slice(args.indexOf("allow"));
      if (spec[0] !== "allow" || spec[1] !== "in") throw new Error("Unexpected UFW mutation");
      const destination = spec[spec.indexOf("to") + 1]!, source = spec[spec.indexOf("from") + 1]!;
      const family = source.includes(":") ? 6 : 4;
      const item = { rule: rule(Number(spec[spec.indexOf("port") + 1]), spec[spec.indexOf("proto") + 1] as "tcp" | "udp", family, destination), comment: spec[spec.indexOf("comment") + 1]!, action: "ALLOW" as const };
      const existing = this.ufwRules.findIndex(r => r.rule.key === item.rule.key && r.action === "ALLOW" && !r.source);
      if (remove) { if (existing >= 0) this.ufwRules.splice(existing, 1); return ok("Rule deleted"); }
      if (existing >= 0) { if (!prepend) this.ufwRules[existing]!.comment = item.comment; return ok(prepend ? "Skipping adding existing rule" : "Rule updated"); }
      if (prepend) this.ufwRules.unshift(item); else this.ufwRules.push(item);
      return ok("Rule added");
    }
    if (executable === "firewall-cmd") {
      if (this.manager !== "firewalld") return missing();
      if (args.includes("--state")) return ok("running\n");
      if (args.includes("--get-zones")) return ok(this.zones.join(" "));
      if (args.includes("--get-active-zones")) return ok(this.activeZones.map(zone => `${zone}\n  interfaces: eth-${zone}`).join("\n"));
      if (args.includes("--get-default-zone")) return ok(this.defaultZone);
      const zone = args.find(arg => arg.startsWith("--zone="))?.slice(7);
      if (!zone || !this.zones.includes(zone)) return fail("INVALID_ZONE");
      const rich = args.find(arg => /^--(query|add|remove)-rich-rule=/.test(arg)); if (!rich) throw new Error("Unexpected firewalld command");
      const [prefix, ...rest] = rich.split("="), value = rest.join("=");
      const store = args.includes("--permanent") ? this.permanent : this.runtime;
      let rules = store.get(zone); if (!rules) { rules = new Set(); store.set(zone, rules); }
      if (prefix === "--query-rich-rule") return rules.has(value) ? ok("yes\n") : { code: 1, stdout: "no\n", stderr: "" };
      this.mutations.push({ executable, args: [...args] });
      if (prefix === "--add-rich-rule") rules.add(value); else rules.delete(value);
      return ok("success");
    }
    if (executable === "nft") return this.manager === "iptables" || this.manager === "none" ? ok(JSON.stringify({ nftables: this.nftChains })) : missing();
    if (executable === "iptables" || executable === "ip6tables") {
      if (this.manager === "ufw" && args[2] === "-C") {
        const family = executable === "iptables" ? 4 : 6, destination = args[args.indexOf("-d") + 1]!, port = Number(args[args.indexOf("--dport") + 1]), protocol = args[args.indexOf("-p") + 1];
        return this.ufwRules.some(e => e.action === "ALLOW" && !e.source && e.rule.family === family && e.rule.destination === destination && e.rule.port === port && e.rule.protocol === protocol) ? ok() : fail("Bad rule (does a matching rule exist?)");
      }
      if (this.manager !== "iptables") return missing();
      if (args[0] === "--version") return ok("iptables v1.8.10 (nf_tables)");
      const lines = executable === "iptables" ? this.v4 : this.v6;
      const words = args.slice(2); if (args[0] !== "-w" || args[1] !== "5") throw new Error("Missing bounded xtables lock");
      if (words[0] === "-S") return ok(lines.map(line => line.map(token => /[\s"']/.test(token) ? JSON.stringify(token) : token).join(" ")).join("\n"));
      this.mutations.push({ executable, args: [...args] });
      const action = words[0], chain = words[1];
      if (action === "-N") { if (lines.some(line => line[0] === "-N" && line[1] === chain)) return fail("Chain already exists"); lines.push(words); }
      else if (action === "-A") lines.push(words);
      else if (action === "-I") { const index = lines.findIndex(line => line[0] === "-A" && line[1] === chain); lines.splice(index < 0 ? lines.length : index, 0, ["-A", chain!, ...words.slice(3)]); }
      else if (action === "-D") { const wanted = ["-A", ...words.slice(1)], index = lines.findIndex(line => JSON.stringify(line) === JSON.stringify(wanted)); if (index < 0) return fail("Bad rule (does a matching rule exist?)"); lines.splice(index, 1); }
      else if (action === "-X") { if (lines.some(line => line[0] === "-A" && (line[1] === chain || line.includes(chain!)))) return fail("Chain is not empty or referenced"); const index = lines.findIndex(line => line[0] === "-N" && line[1] === chain); if (index >= 0) lines.splice(index, 1); }
      else throw new Error(`Forbidden/unexpected iptables mutation ${action}`);
      return ok();
    }
    throw new Error(`Unexpected executable ${executable}`);
  }
  ufwStatus(): string {
    return "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n" + this.ufwRules.map((entry, i) => {
      const r = entry.rule, v6 = r.family === 6 ? " (v6)" : "", destination = r.destination.endsWith("/0") ? "" : r.destination + " ";
      return `[ ${i + 1}] ${destination}${r.port}/${r.protocol}${v6}                 ${entry.action} IN    ${entry.source || "Anywhere"}${v6}${entry.comment ? " # " + entry.comment : ""}`;
    }).concat(this.ufwMalformed).join("\n");
  }
  get run(): FirewallCommandRunner { return this.runner.bind(this); }
  ownUfw(r: FirewallRule, id = scope) { this.ufwRules.push({ rule: r, comment: linux.ufwComment(id, r), action: "ALLOW" }); }
}

describe("Linux backend detection and ownership boundaries", () => {
  test("inspection is read-only; explicit backend conflicts and ambiguous manager states do not fall through", async () => {
    const f = new MockLinuxFirewall(), c = context(), p = plan([rule(443)]);
    expect((await inspectLinuxFirewall(p, auto, f.run, c)).status).toBe("needs-update");
    expect(f.mutations).toHaveLength(0); expect(fs.readdirSync(path.dirname(c.stateFile))).toHaveLength(0);
    expect((await applyLinuxFirewall(p, { ...auto, linuxBackend: "iptables" }, f.run, c)).status).toBe("blocked");
    f.intercept = (exe, args) => exe === "firewall-cmd" && args[0] === "--state" ? ok("running") : undefined;
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    f.intercept = exe => exe === "ufw" ? fail("ERROR: You need to be root to run this script") : undefined;
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("permission-required");
  });
  test("invalid plans and corrupt or symlinked journals fail before firewall mutation", async () => {
    const f = new MockLinuxFirewall(), c = context();
    expect((await applyLinuxFirewall(plan([{ ...rule(443), destination: "0.0.0.0/0; reboot" }]), auto, f.run, c)).status).toBe("blocked");
    fs.writeFileSync(c.stateFile, "not JSON");
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked");
    fs.unlinkSync(c.stateFile); const target = path.join(path.dirname(c.stateFile), "unrelated"); fs.writeFileSync(target, "retain me"); fs.symlinkSync(target, c.stateFile);
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked");
    expect(fs.readFileSync(target, "utf8")).toBe("retain me"); expect(f.mutations).toHaveLength(0);
  });
  test("inactive managers and empty ACCEPT policies never cause the tool to enable a firewall", async () => {
    const f = new MockLinuxFirewall(), c = context();
    f.intercept = (exe, args) => exe === "ufw" && args[0] === "status" ? ok("Status: inactive") : undefined;
    expect((await applyLinuxFirewall(plan([rule(443)]), { ...auto, linuxBackend: "ufw" }, f.run, c)).status).toBe("inactive");
    f.intercept = undefined; f.manager = "iptables"; f.v4[0]![2] = "ACCEPT"; f.v6[0]![2] = "ACCEPT";
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("inactive"); expect(f.mutations).toHaveLength(0);
  });
  test("backend change requires explicit owned-rule cleanup", async () => {
    const f = new MockLinuxFirewall(), c = context(), p = plan([rule(443)]);
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("synced");
    f.manager = "firewalld";
    const switched = await applyLinuxFirewall(p, auto, f.run, c); expect(switched.status).toBe("blocked"); expect(switched.detail).toContain("ufw");
    f.manager = "ufw"; expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("synced");
    f.manager = "firewalld"; expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("synced");
  });
  test("concurrent privileged sync is bounded by an OS lock, released after its owner closes", async () => {
    const f = new MockLinuxFirewall(), c = context(), p = plan([rule(443)]);
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("synced");
    const database = new sqlite.Database(c.stateFile.replace(/\.json$/, "-lock.sqlite")); database.exec("BEGIN EXCLUSIVE");
    try { expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("blocked"); }
    finally { database.exec("ROLLBACK"); database.close(); }
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("synced");
  });
});

describe("UFW finite scoped rules", () => {
  test("dual-stack TCP/UDP creation is idempotent and preserves an equivalent manual allow comment", async () => {
    const f = new MockLinuxFirewall(), c = context();
    const manual = rule(443), udp = rule(8388, "udp"), v6 = rule(8443, "tcp", 6, "2001:db8::42");
    f.ufwRules.push({ rule: manual, action: "ALLOW", comment: "admin web rule" });
    const p = plan([manual, udp, v6]);
    const result = await applyLinuxFirewall(p, auto, f.run, c); expect(result.status).toBe("synced"); expect(result.warnings.join(" ")).toContain("手动");
    expect(f.ufwRules.find(e => e.rule.key === manual.key)?.comment).toBe("admin web rule");
    expect(f.mutations).toHaveLength(2); expect(f.mutations.every(m => m.args[0] === "prepend")).toBe(true);
    expect((await applyLinuxFirewall(p, auto, f.run, c)).changed).toBe(false); expect(f.mutations).toHaveLength(2);
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("synced");
    expect(f.ufwRules).toEqual([{ rule: manual, action: "ALLOW", comment: "admin web rule" }]);
    expect(f.mutations.every(m => !m.args.includes("reset") && !m.args.includes("disable") && !/^\d+$/.test(m.args[2] || ""))).toBe(true);
  });
  test("all new ports precede stale deletion; failed additions preserve every old port", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.ownUfw(rule(443)); f.ownUfw(rule(443, "tcp", 6));
    const wanted = plan([rule(8443), rule(8443, "tcp", 6)]);
    f.intercept = (exe, args) => exe === "ufw" && args[0] === "prepend" && args.includes("::/0") ? fail("IPv6 is disabled") : undefined;
    expect((await applyLinuxFirewall(wanted, auto, f.run, c)).status).toBe("error");
    expect(f.ufwRules.filter(e => e.rule.port === 443)).toHaveLength(2);
    expect(f.mutations.some(m => m.args.includes("delete"))).toBe(false);
    f.intercept = undefined; f.mutations = [];
    expect((await applyLinuxFirewall(wanted, auto, f.run, c)).status).toBe("synced");
    const firstDelete = f.mutations.findIndex(m => m.args.includes("delete"));
    expect(firstDelete).toBeGreaterThan(0); expect(f.mutations.slice(firstDelete).every(m => m.args.includes("delete"))).toBe(true);
  });
  test("unknown or forged owned rules are never deleted", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.ownUfw(rule(443));
    f.ufwRules[0]!.action = "DENY";
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    f.ufwRules = []; f.ufwMalformed = [`[ 4] Anywhere ALLOW IN 192.0.2.1 # NexusEdge:${scope}:4:tcp:443:0.0.0.0/0`];
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
  });
  test("earlier explicit DENY and a missing live kernel rule cannot be reported as opened", async () => {
    const f = new MockLinuxFirewall(), c = context();
    f.ufwRules.push({ rule: rule(443), action: "DENY", comment: "admin block" }, { rule: rule(443), action: "ALLOW", comment: "manual allow" });
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    f.ufwRules.shift();
    f.intercept = (exe, args) => exe === "iptables" && args.includes("-C") ? fail("Bad rule (does a matching rule exist?)") : undefined;
    expect((await inspectLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
  });
  test("unrelated numeric/range denies and client-specific IP bans do not block node startup", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.ownUfw(rule(8388));
    f.intercept = (exe, args) => exe === "ufw" && args.includes("numbered") ? ok("Status: active\n[ 1] 22 DENY IN Anywhere\n[ 2] 3000:4000/tcp DENY IN Anywhere\n[ 3] Anywhere DENY IN 203.0.113.5\n" + f.ufwStatus().split("\n").find(line => line.includes(linux.ufwComment(scope, rule(8388))))!) : undefined;
    const result = await applyLinuxFirewall(plan([rule(8388)]), auto, f.run, c);
    expect(result.status).toBe("synced"); expect(result.warnings.join(" ")).toContain("部分客户端"); expect(f.mutations).toHaveLength(0);
    f.intercept = (exe, args) => exe === "ufw" && args.includes("numbered") ? ok(`Status: active\n[ 1] 8000:9000 DENY IN Anywhere\n[ 2] 8388/tcp ALLOW IN Anywhere # ${linux.ufwComment(scope, rule(8388))}`) : undefined;
    expect((await inspectLinuxFirewall(plan([rule(8388)]), auto, f.run, c)).status).toBe("blocked");
  });
  test("a duplicate equivalent manual rule prevents ambiguous stale deletion", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.ownUfw(rule(443)); f.ufwRules.push({ rule: rule(443), action: "ALLOW", comment: "manual" });
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
  });
  test("explicit migration changes only verified source comments, preserves order, and rolls back", async () => {
    const f = new MockLinuxFirewall(), sourceContext = context(), targetContext = context();
    const owned = rule(443), manual = rule(8388, "udp"), rules = [owned, manual];
    f.ownUfw(owned); f.ufwRules.push({ rule: manual, comment: "manual untouched", action: "ALLOW" });
    const source = plan(rules), target = plan(rules, otherScope);
    expect((await applyLinuxFirewall(target, auto, f.run, targetContext)).status).toBe("blocked");
    const receipt = await transferLinuxUfwOwnership(source, target, f.run, sourceContext, targetContext);
    expect(receipt.result.status).toBe("synced"); expect(receipt.result.changed).toBe(true);
    expect(f.ufwRules.map(r => r.rule.key)).toEqual(rules.map(r => r.key));
    expect(f.ufwRules[0]!.comment).toBe(linux.ufwComment(otherScope, owned)); expect(f.ufwRules[1]!.comment).toBe("manual untouched");
    expect((await applyLinuxFirewall(target, auto, f.run, targetContext)).status).toBe("synced");
    expect((await receipt.rollback()).status).toBe("synced"); expect(f.ufwRules[0]!.comment).toBe(linux.ufwComment(scope, owned));
    expect(f.mutations.every(m => !m.args.includes("delete") && m.args[0] === "allow")).toBe(true);
  });
  test("migration rollback does not take over a rule subsequently changed by an administrator", async () => {
    const f = new MockLinuxFirewall(), sourceContext = context(), targetContext = context(); f.ownUfw(rule(443));
    const receipt = await transferLinuxUfwOwnership(plan([rule(443)]), plan([rule(443)], otherScope), f.run, sourceContext, targetContext);
    expect(receipt.result.status).toBe("synced"); f.ufwRules[0]!.comment = "new administrator owner";
    expect((await receipt.rollback()).status).toBe("blocked"); expect(f.ufwRules[0]!.comment).toBe("new administrator owner");
  });
  test("successful transfer lets source cleanup leave the target and manual rules intact", async () => {
    const f = new MockLinuxFirewall(), sourceContext = context(), targetContext = context(); f.ownUfw(rule(443));
    const source = plan([rule(443)]), target = plan([rule(443)], otherScope);
    expect((await applyLinuxFirewall(source, auto, f.run, sourceContext)).status).toBe("synced");
    const receipt = await transferLinuxUfwOwnership(source, target, f.run, sourceContext, targetContext); expect(receipt.result.status).toBe("synced");
    expect((await applyLinuxFirewall(plan([]), auto, f.run, sourceContext)).status).toBe("synced");
    expect((await inspectLinuxFirewall(target, auto, f.run, targetContext)).status).toBe("synced"); expect(f.ufwRules).toHaveLength(1);
  });
});

describe("firewalld runtime and permanent rule ownership", () => {
  test("runtime/permanent rules and exact destinations sync without reload; manual rules persist", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld";
    f.runtime.set("public", new Set(['rule family="ipv4" port port="22" protocol="tcp" accept']));
    const p = plan([rule(8443), rule(8388, "udp", 6, "2001:db8::7")]);
    expect((await inspectLinuxFirewall(p, auto, f.run, c)).status).toBe("needs-update"); expect(fs.existsSync(c.stateFile)).toBe(false);
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("synced"); expect(f.mutations).toHaveLength(4);
    expect(f.mutations.every(m => m.args.some(arg => arg.startsWith("--add-rich-rule=")))).toBe(true);
    expect(fs.statSync(c.stateFile).mode & 0o777).toBe(0o644);
    expect((await applyLinuxFirewall(p, auto, f.run, c)).changed).toBe(false); expect(f.mutations).toHaveLength(4);
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("synced");
    expect([...f.runtime.get("public")!]).toEqual(['rule family="ipv4" port port="22" protocol="tcp" accept']); expect(f.permanent.get("public")?.size).toBe(0);
    expect(f.calls.some(c => c.args.includes("--reload") || c.args.includes("--runtime-to-permanent"))).toBe(false);
  });
  test("changing port and zone verifies every addition before pruning the old zone", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld";
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("synced"); f.mutations = [];
    expect((await applyLinuxFirewall(plan([rule(8443), rule(8388, "udp")]), { ...auto, firewalldZone: "external" }, f.run, c)).status).toBe("synced");
    expect(f.mutations.slice(0, 4).every(m => m.args.includes("--zone=external") && m.args.some(a => a.startsWith("--add-rich-rule=")))).toBe(true);
    expect(f.mutations.slice(4).every(m => m.args.includes("--zone=public") && m.args.some(a => a.startsWith("--remove-rich-rule=")))).toBe(true);
    expect(f.runtime.get("public")?.size).toBe(0); expect(f.permanent.get("external")?.size).toBe(2);
  });
  test("ambiguous active zones require advanced override; no active zone uses the default", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld"; f.activeZones = ["public", "internal"];
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    f.activeZones = []; f.defaultZone = "external";
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("synced"); expect(f.runtime.get("external")?.size).toBe(1);
  });
  test("unowned exact collisions are refused even if only the permanent copy exists", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld";
    const p = plan([rule(443)]), rich = linux.richRule(scope, p.rules[0]!);
    f.permanent.set("public", new Set([rich]));
    expect((await applyLinuxFirewall(p, auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    expect(f.permanent.get("public")?.has(rich)).toBe(true);
  });
  test("failed permanent additions keep old ports and a recoverable finite intent journal", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld";
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("synced"); f.mutations = [];
    f.intercept = (exe, args) => exe === "firewall-cmd" && args.includes("--permanent") && args.some(arg => arg.startsWith("--add-rich-rule=")) ? fail("simulated write failure") : undefined;
    expect((await applyLinuxFirewall(plan([rule(8443)]), auto, f.run, c)).status).toBe("error");
    expect(f.runtime.get("public")?.has(linux.richRule(scope, rule(443)))).toBe(true); expect(f.permanent.get("public")?.has(linux.richRule(scope, rule(443)))).toBe(true);
    expect(f.mutations.some(m => m.args.some(arg => arg.startsWith("--remove-rich-rule=")))).toBe(false);
    const journal = JSON.parse(fs.readFileSync(c.stateFile, "utf8")); expect(journal.firewalld.find((c: any) => c.rule.port === 8443).permanent).toBe(true);
    f.intercept = undefined;
    expect((await applyLinuxFirewall(plan([rule(8443)]), auto, f.run, c)).status).toBe("synced"); expect(f.runtime.get("public")?.size).toBe(1); expect(f.permanent.get("public")?.size).toBe(1);
  });
  test("journal recovery rejects arbitrary rich-rule text and forged rule keys", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "firewalld";
    fs.writeFileSync(c.stateFile, JSON.stringify({ schema: 1, scope, firewalld: [{ zone: "public", rule: { ...rule(443), key: "feedfacefeedface", action: "drop" }, runtime: true, permanent: true }] }));
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
  });
});

describe("raw iptables safely scoped fallback", () => {
  test("unknown native nft input chains prevent misleading iptables ACCEPT success", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    f.nftChains = [{ chain: { family: "inet", table: "custom", name: "input", type: "filter", hook: "input", prio: 20, policy: "drop" } }];
    const result = await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c);
    expect(result.status).toBe("unsupported"); expect(result.detail).toContain("inet/custom/input"); expect(f.mutations).toHaveLength(0);
  });
  test("legacy iptables cannot treat a similarly named native nft INPUT chain as its own", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    f.nftChains = [{ chain: { family: "ip", table: "filter", name: "INPUT", type: "filter", hook: "input", prio: 0, policy: "drop" } }];
    f.intercept = (exe, args) => exe === "iptables" && args[0] === "--version" ? ok("iptables v1.8.10 (legacy)") : undefined;
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("unsupported"); expect(f.mutations).toHaveLength(0);
    f.nftChains = [];
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("synced");
  });
  test("IPv4 and IPv6 backend variants are checked independently", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    f.nftChains = [{ chain: { family: "ip6", table: "filter", name: "INPUT", type: "filter", hook: "input", prio: 0, policy: "drop" } }];
    f.intercept = (exe, args) => exe === "ip6tables" && args[0] === "--version" ? ok("ip6tables v1.8.10 (legacy)") : undefined;
    expect((await applyLinuxFirewall(plan([rule(443, "tcp", 6)]), auto, f.run, c)).status).toBe("unsupported"); expect(f.mutations).toHaveLength(0);
  });
  test("IPv4/IPv6 finite owned chains are idempotent, add before remove, preserve unrelated rules", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    f.nftChains = [{ chain: { family: "ip", table: "filter", name: "INPUT", type: "filter", hook: "input", prio: 0, policy: "drop" } }];
    const manual = ["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]; f.v4.push(manual);
    const initial = plan([rule(443), rule(443, "tcp", 6), rule(8388, "udp")]);
    const result = await applyLinuxFirewall(initial, auto, f.run, c); expect(result.status).toBe("synced"); expect(result.warnings.join(" ")).toContain("运行期");
    const count = f.mutations.length; expect((await applyLinuxFirewall(initial, auto, f.run, c)).changed).toBe(false); expect(f.mutations).toHaveLength(count);
    f.mutations = [];
    expect((await applyLinuxFirewall(plan([rule(8443), rule(8443, "tcp", 6)]), auto, f.run, c)).status).toBe("synced");
    const firstDelete = f.mutations.findIndex(m => m.args.includes("-D")); expect(firstDelete).toBe(2); expect(f.mutations.slice(firstDelete).every(m => m.args.includes("-D"))).toBe(true);
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("synced"); expect(f.v4).toContainEqual(manual);
    expect(f.v4.some(line => line.includes(linux.chain(scope)))).toBe(false); expect(f.v6.some(line => line.includes(linux.chain(scope)))).toBe(false);
    expect(f.mutations.some(m => m.args.includes("-F") || m.args.includes("-P") || m.executable.includes("save"))).toBe(false);
  });
  test("unowned chain names, foreign references, or externally reordered jumps are not taken over", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    f.v4.push(["-N", linux.chain(scope)]);
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    f.v4.pop(); expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("synced"); f.mutations = [];
    f.v4.splice(3, 0, ["-A", "INPUT", "-j", "DROP"]);
    expect((await applyLinuxFirewall(plan([rule(443)]), auto, f.run, c)).status).toBe("blocked"); expect(f.mutations).toHaveLength(0);
    // Cleanup may remove only its own later jump; it does not need to assert reachability.
    expect((await applyLinuxFirewall(plan([]), auto, f.run, c)).status).toBe("synced"); expect(f.v4).toContainEqual(["-A", "INPUT", "-j", "DROP"]);
  });
  test("an IPv6 add failure preserves stale IPv4 and IPv6 allows", async () => {
    const f = new MockLinuxFirewall(), c = context(); f.manager = "iptables";
    expect((await applyLinuxFirewall(plan([rule(443), rule(443, "tcp", 6)]), auto, f.run, c)).status).toBe("synced"); f.mutations = [];
    f.intercept = (exe, args) => exe === "ip6tables" && args.includes("-I") ? fail("simulated IPv6 failure") : undefined;
    expect((await applyLinuxFirewall(plan([rule(8443), rule(8443, "tcp", 6)]), auto, f.run, c)).status).toBe("error");
    expect(f.v4.some(line => line.includes("443"))).toBe(true); expect(f.v6.some(line => line.includes("443"))).toBe(true); expect(f.mutations.some(m => m.args.includes("-D"))).toBe(false);
  });
});
