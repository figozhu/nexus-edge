import * as linuxFirewallFs from "node:fs";
import * as linuxFirewallPath from "node:path";
import * as linuxFirewallNet from "node:net";
import * as linuxFirewallCrypto from "node:crypto";
import * as linuxFirewallSqlite from "bun:sqlite";
import type { FirewallRule, FirewallPlan, FirewallOptions, FirewallResult, FirewallCommandRunner } from "./firewall.ts";

/** The parent directory already exists and is private to this installation. No config/secrets are read here. */
export interface LinuxFirewallContext { stateFile: string }
type LinuxFirewallBackend = "ufw" | "firewalld" | "iptables" | "none";
type LinuxFirewallReply = Awaited<ReturnType<FirewallCommandRunner>>;
class LinuxFirewallFailure extends Error {
  constructor(readonly status: FirewallResult["status"], message: string) { super(message); }
}
interface LinuxFirewallSession {
  plan: FirewallPlan; runner: FirewallCommandRunner; backend: LinuxFirewallBackend; changed: boolean; warnings: string[];
  context: LinuxFirewallContext; journal?: LinuxFirewallJournal;
  ufwStatus?: string;
}
const linuxFirewallPermissionPattern = /permission denied|operation not permitted|must be root|need to be root|not authorized|not authorised|authorization.failed|access denied|authentication is required/i;
function linuxFirewallFail(status: FirewallResult["status"], detail: string): never { throw new LinuxFirewallFailure(status, detail); }
function linuxFirewallKey(rule: Omit<FirewallRule, "key">): string {
  return linuxFirewallCrypto.createHash("sha256").update(JSON.stringify([rule.protocol, rule.port, rule.family, rule.destination])).digest("hex").slice(0, 16);
}
function linuxFirewallValidateRule(value: unknown): FirewallRule {
  const r = value as FirewallRule;
  if (!r || !["tcp", "udp"].includes(r.protocol) || !Number.isInteger(r.port) || r.port < 1 || r.port > 65535 || ![4, 6].includes(r.family) || typeof r.destination !== "string") linuxFirewallFail("blocked", "防火墙规则格式不合法。");
  const wildcard = r.family === 4 ? "0.0.0.0/0" : "::/0";
  if (r.destination !== wildcard && linuxFirewallNet.isIP(r.destination) !== r.family) linuxFirewallFail("blocked", "防火墙仅接受明确的本机 IP 或监听全部地址。");
  if (r.destination !== wildcard) {
    if ((r.family === 4 && (r.destination.startsWith("127.") || r.destination === "0.0.0.0")) || (r.family === 6 && (r.destination === "::1" || r.destination === "::" || r.destination.startsWith("::ffff:") || new URL(`http://[${r.destination}]/`).hostname.slice(1, -1) !== r.destination))) linuxFirewallFail("blocked", "防火墙状态记录含非规范或回环监听地址。");
  }
  if (r.key !== linuxFirewallKey(r)) linuxFirewallFail("blocked", "防火墙规则标识校验失败。");
  return { key: r.key, protocol: r.protocol, port: r.port, family: r.family, destination: r.destination };
}
function linuxFirewallValidatePlan(plan: FirewallPlan): void {
  if (!/^[0-9a-f]{20}$/.test(plan.scope) || !/^[0-9a-f]{64}$/.test(plan.fingerprint) || !Array.isArray(plan.rules) || plan.rules.length > 128) linuxFirewallFail("blocked", "防火墙计划格式不合法。");
  const keys = plan.rules.map(rule => linuxFirewallValidateRule(rule).key);
  if (new Set(keys).size !== keys.length) linuxFirewallFail("blocked", "防火墙计划含重复规则。");
}
async function linuxFirewallRun(s: LinuxFirewallSession, executable: string, args: string[]): Promise<LinuxFirewallReply> {
  try { return await s.runner(executable, args, { timeoutMs: 20000, env: { LC_ALL: "C", LANG: "C" } }); }
  catch (error) {
    const e = error as NodeJS.ErrnoException;
    if (e.code === "ENOENT") return { code: 127, stdout: "", stderr: `${executable}: command not found` };
    if (e.code === "EACCES" || e.code === "EPERM") linuxFirewallFail("permission-required", `查询或设置 ${executable} 需要管理员权限。`);
    throw error;
  }
}
function linuxFirewallSuccess(r: LinuxFirewallReply, operation: string): string {
  if (r.code !== 0) {
    const detail = (r.stderr.trim() || r.stdout.trim() || `退出码 ${r.code}`).slice(0, 1500);
    linuxFirewallFail(linuxFirewallPermissionPattern.test(detail) ? "permission-required" : "error", `${operation}失败：${detail}`);
  }
  return r.stdout.trim();
}
async function linuxFirewallMutation(s: LinuxFirewallSession, executable: string, args: string[]): Promise<void> {
  if (s.plan.rules.length && s.journal && s.journal.backend !== s.backend) {
    s.journal.backend = s.backend as Exclude<LinuxFirewallBackend, "none">;
    linuxFirewallWriteJournal(s.context, s.journal);
  }
  // A command may partially succeed before returning an error. Do not claim an unchanged firewall afterwards.
  s.changed = true;
  linuxFirewallSuccess(await linuxFirewallRun(s, executable, args), `更新 ${executable} 规则`);
}
function linuxFirewallResult(s: LinuxFirewallSession, status: FirewallResult["status"], detail: string): FirewallResult {
  return { backend: s.backend, status, changed: s.changed, detail, warnings: [...new Set([...s.warnings, ...s.plan.warnings])], rules: s.plan.rules };
}
/** Read argv-like diagnostic output only. Never execute the parsed text or interpolate it into a shell. */
function linuxFirewallWords(text: string): string[] {
  const result: string[] = []; let word = "", quote = "", started = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === quote) quote = "";
      else if (c === "\\" && quote === '"') { if (++i >= text.length) linuxFirewallFail("blocked", "无法安全解析防火墙规则。"); word += text[i]!; }
      else word += c;
    } else if (c === "'" || c === '"') { quote = c; started = true; }
    else if (c === "\\") { if (++i >= text.length) linuxFirewallFail("blocked", "无法安全解析防火墙规则。"); word += text[i]!; started = true; }
    else if (/\s/.test(c)) { if (started) result.push(word); word = ""; started = false; }
    else { word += c; started = true; }
  }
  if (quote) linuxFirewallFail("blocked", "防火墙规则含未闭合的引号。");
  if (started) result.push(word);
  return result;
}
function linuxFirewallSameWords(a: string[], b: string[]): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function linuxFirewallNormalizeAddress(address: string, family: 4 | 6): string {
  if (address === "any" || address === "Anywhere" || address === (family === 4 ? "0.0.0.0/0" : "::/0")) return family === 4 ? "0.0.0.0/0" : "::/0";
  const plain = address.replace(family === 4 ? /\/32$/ : /\/128$/, "");
  if (linuxFirewallNet.isIP(plain) !== family) return "";
  return family === 6 ? new URL(`http://[${plain}]/`).hostname.slice(1, -1) : plain;
}

async function linuxFirewallDetect(s: LinuxFirewallSession, options: FirewallOptions): Promise<{ backend: LinuxFirewallBackend; active: boolean }> {
  const probes = await Promise.all([
    linuxFirewallRun(s, "ufw", ["status"]), linuxFirewallRun(s, "firewall-cmd", ["--state"]),
  ]);
  const ufw = probes[0]!, firewalld = probes[1]!;
  for (const [name, reply] of [["UFW", ufw], ["firewalld", firewalld]] as const) {
    if (reply.code !== 0 && linuxFirewallPermissionPattern.test(`${reply.stderr}\n${reply.stdout}`)) linuxFirewallFail("permission-required", `需要管理员权限才能确认 ${name} 的状态。`);
  }
  const ufwActive = ufw.code === 0 && /^Status:\s*active\s*$/mi.test(ufw.stdout);
  const firewalldActive = firewalld.code === 0 && /^running\s*$/mi.test(firewalld.stdout);
  const ufwKnown = ufw.code === 127 || ufwActive || (ufw.code === 0 && /^Status:\s*inactive\s*$/mi.test(ufw.stdout));
  const firewalldKnown = firewalld.code === 127 || firewalldActive || /not running|NOT_RUNNING/i.test(firewalld.stderr + firewalld.stdout);
  if (!ufwKnown || !firewalldKnown) linuxFirewallFail("blocked", "无法确认现有防火墙管理器状态；请先检查 ufw status / firewall-cmd --state，避免混用防火墙。");
  if (ufwActive && firewalldActive) linuxFirewallFail("blocked", "UFW 和 firewalld 同时运行。请先确定由哪个工具管理防火墙。");
  if (options.linuxBackend !== "auto") {
    if ((ufwActive && options.linuxBackend !== "ufw") || (firewalldActive && options.linuxBackend !== "firewalld")) linuxFirewallFail("blocked", "指定后端与正在运行的防火墙管理器不同，请在高级设置中选择当前管理器。");
    if (options.linuxBackend === "ufw") return { backend: "ufw", active: ufwActive };
    if (options.linuxBackend === "firewalld") return { backend: "firewalld", active: firewalldActive };
    return { backend: "iptables", active: true };
  }
  if (ufwActive) return { backend: "ufw", active: true };
  if (firewalldActive) return { backend: "firewalld", active: true };
  return { backend: "iptables", active: true };
}

interface LinuxUfwEntry { rule: FirewallRule; comment: string; action: string; anySource: boolean; raw: string }
function linuxUfwComment(scope: string, rule: FirewallRule): string { return `NexusEdge:${scope}:${rule.family}:${rule.protocol}:${rule.port}:${rule.destination}`; }
function linuxUfwSpec(scope: string, rule: FirewallRule): string[] {
  return ["allow", "in", "proto", rule.protocol, "from", rule.family === 4 ? "0.0.0.0/0" : "::/0", "to", rule.destination, "port", String(rule.port), "comment", linuxUfwComment(scope, rule)];
}
function linuxUfwParseStatus(text: string, scope: string): LinuxUfwEntry[] {
  const entries: LinuxUfwEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const marker = `NexusEdge:${scope}:`;
    const match = /^\s*(?:\[\s*\d+\]\s*)?(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+?)(?:\s+#\s*(.*))?\s*$/.exec(raw);
    if (!match) { if (raw.includes(marker)) linuxFirewallFail("blocked", "无法识别带本安装标记的 UFW 规则，已停止自动修改。"); continue; }
    const comment = match[5] || "", family: 4 | 6 = /\(v6\)/.test(match[1]! + match[4]!) ? 6 : 4;
    const destinationText = match[1]!.replace(/\s*\(v6\)/g, "").trim();
    const sourceText = match[4]!.replace(/\s*\(v6\)/g, "").trim();
    // UFW status renders a concrete destination as '<address> <port>/<protocol>'.
    const tokens = destinationText.split(/\s+/), portToken = tokens.find(token => /^\d+\/(tcp|udp)$/.test(token));
    let destination = "";
    if (portToken && tokens.length <= 2) destination = linuxFirewallNormalizeAddress(tokens.find(t => t !== portToken) || "Anywhere", family);
    if (!portToken || !destination || match[3] !== "IN") {
      if (comment.startsWith(marker)) linuxFirewallFail("blocked", "本安装的 UFW 标记出现在无法安全管理的规则上。");
      continue;
    }
    const [port, protocol] = portToken.split("/");
    const base = { protocol: protocol as "tcp" | "udp", port: Number(port), family, destination };
    const rule = linuxFirewallValidateRule({ ...base, key: linuxFirewallKey(base) });
    const entry = { rule, action: match[2]!, comment, anySource: linuxFirewallNormalizeAddress(sourceText, family) === (family === 4 ? "0.0.0.0/0" : "::/0"), raw };
    if (comment.startsWith(marker) && (entry.action !== "ALLOW" || !entry.anySource || comment !== linuxUfwComment(scope, rule))) linuxFirewallFail("blocked", "本安装的 UFW 规则标记与规则内容不一致；不会删除或接管该规则。");
    entries.push(entry);
  }
  return entries;
}
async function linuxUfwSnapshot(s: LinuxFirewallSession): Promise<LinuxUfwEntry[]> {
  const status = linuxFirewallSuccess(await linuxFirewallRun(s, "ufw", ["status", "numbered"]), "读取 UFW 规则");
  if (!/^Status:\s*active\s*$/mi.test(status)) linuxFirewallFail("inactive", "UFW 未启用；工具不会自动启用防火墙。已有规则将在 UFW 启用后生效。");
  s.ufwStatus = status;
  return linuxUfwParseStatus(status, s.plan.scope);
}
function linuxUfwCovers(entry: LinuxUfwEntry, rule: FirewallRule): boolean {
  return entry.action === "ALLOW" && entry.anySource && entry.rule.protocol === rule.protocol && entry.rule.port === rule.port && entry.rule.family === rule.family && (entry.rule.destination === rule.destination || entry.rule.destination === (rule.family === 4 ? "0.0.0.0/0" : "::/0"));
}
function linuxUfwCheckOrdering(s: LinuxFirewallSession, entries: LinuxUfwEntry[]): void {
  const lines = (s.ufwStatus || "").split(/\r?\n/);
  for (const rule of s.plan.rules) {
    const firstAllow = entries.find(entry => linuxUfwCovers(entry, rule));
    if (!firstAllow) continue;
    for (const line of lines.slice(0, lines.indexOf(firstAllow.raw))) {
      const denied = /^\s*(?:\[\s*\d+\]\s*)?(.+?)\s+(?:DENY|REJECT|LIMIT)\s+IN\s+(.+?)(?:\s+#.*)?\s*$/.exec(line);
      if (!denied) continue;
      const family = /\(v6\)/.test(denied[1]! + denied[2]!) || denied[1]!.split(/\s+/).some(t => linuxFirewallNet.isIP(t.split("/")[0]!) === 6) ? 6 : 4;
      if (family !== rule.family) continue;
      const tokens = denied[1]!.replace(/\s*\(v6\)/g, "").trim().split(/\s+/);
      const portToken = tokens.find(t => /^\d+(?::\d+)?(?:,\d+(?::\d+)?)*(?:\/(?:tcp|udp))?$/.test(t));
      if (portToken) {
        const [ports, protocol] = portToken.split("/");
        if (protocol && protocol !== rule.protocol) continue;
        if (!ports!.split(",").some(part => { const [first, last] = part.split(":").map(Number); return rule.port >= first! && rule.port <= (last ?? first!); })) continue;
      }
      const anyProtocol = tokens.find(t => /^Anywhere\/(tcp|udp)$/.test(t));
      if (anyProtocol && anyProtocol !== `Anywhere/${rule.protocol}`) continue;
      const address = tokens.find(t => linuxFirewallNet.isIP(t.replace(/\/(32|128)$/, "")) !== 0);
      if (address && !rule.destination.endsWith("/0") && linuxFirewallNormalizeAddress(address, rule.family) !== rule.destination) continue;
      const source = denied[2]!.replace(/\s*\(v6\)/g, "").replace(/\s*\(log(?:-all)?\)\s*$/, "").replace(/\/(tcp|udp)$/, "").trim();
      const unrestrictedSource = linuxFirewallNormalizeAddress(source, rule.family) === (rule.family === 4 ? "0.0.0.0/0" : "::/0");
      const remaining = tokens.filter(t => t !== portToken && t !== address && !/^Anywhere(?:\/(tcp|udp))?$/.test(t));
      if (!unrestrictedSource || remaining.length || (address && rule.destination.endsWith("/0"))) {
        const warning = `UFW 在 ${rule.port}/${rule.protocol} 放行前还有来源、网卡或范围限制规则；它们可能限制部分客户端，工具保留这些限制。`;
        if (!s.warnings.includes(warning)) s.warnings.push(warning);
        continue;
      }
      linuxFirewallFail("blocked", `UFW 的 ${rule.port}/${rule.protocol} 放行规则之前存在拒绝或限制规则；请检查 ufw status numbered 的顺序，工具不会接管已有手动规则。`);
    }
  }
}
async function linuxUfwCheckRuntime(s: LinuxFirewallSession, entries: LinuxUfwEntry[]): Promise<void> {
  for (const rule of s.plan.rules) {
    const covering = entries.find(entry => linuxUfwCovers(entry, rule));
    if (!covering) continue;
    const r = covering.rule, executable = r.family === 4 ? "iptables" : "ip6tables", chain = r.family === 4 ? "ufw-user-input" : "ufw6-user-input";
    const reply = await linuxFirewallRun(s, executable, ["-w", "5", "-C", chain, "-p", r.protocol, "-m", r.protocol, "-d", r.destination, "--dport", String(r.port), "-j", "ACCEPT"]);
    if (reply.code === 1 && !linuxFirewallPermissionPattern.test(reply.stderr + reply.stdout)) linuxFirewallFail("blocked", `UFW 中 ${r.port}/${r.protocol} 的配置与当前内核用户链不一致，不能确认已放行；请检查 UFW 状态和系统防火墙日志。`);
    linuxFirewallSuccess(reply, `验证 UFW 的 IPv${r.family} 内核端口规则`);
  }
}
async function linuxUfwSync(s: LinuxFirewallSession, apply: boolean): Promise<FirewallResult> {
  let entries = await linuxUfwSnapshot(s);
  const own = () => entries.filter(e => e.comment.startsWith(`NexusEdge:${s.plan.scope}:`));
  const missing = s.plan.rules.filter(rule => !entries.some(entry => linuxUfwCovers(entry, rule)));
  const stale = own().filter(entry => !s.plan.rules.some(rule => rule.key === entry.rule.key));
  if (s.plan.rules.some(rule => entries.some(entry => linuxUfwCovers(entry, rule) && /^NexusEdge:[0-9a-f]{20}:/.test(entry.comment) && !entry.comment.startsWith(`NexusEdge:${s.plan.scope}:`)))) linuxFirewallFail("blocked", "另一个 NexusEdge 安装的 UFW 规则覆盖了此端口。UFW 不能并存等价规则；请先明确旧安装的规则归属，再迁移，避免清理旧安装时关闭新节点端口。");
  // UFW deletion matches the rule body. Duplicate bodies with another comment cannot be removed safely.
  for (const entry of stale) if (entries.filter(e => e.action === "ALLOW" && e.anySource && e.rule.key === entry.rule.key).length !== 1) linuxFirewallFail("blocked", "UFW 中存在相同内容但不同归属的规则；请手动检查，工具不会按序号删除。");
  linuxUfwCheckOrdering(s, entries);
  s.warnings.push("UFW 自定义 before/after 规则和外部网络策略仍可能阻止连接；此状态仅确认 UFW 用户规则。");
  if (s.plan.rules.some(rule => entries.some(entry => linuxUfwCovers(entry, rule) && !entry.comment.startsWith(`NexusEdge:${s.plan.scope}:`)))) s.warnings.push("已有手动放行规则覆盖部分端口；工具保留其归属，移除本工具规则时不会删除它们。");
  if (!apply) { await linuxUfwCheckRuntime(s, entries); return linuxFirewallResult(s, missing.length || stale.length ? "needs-update" : "synced", missing.length || stale.length ? "UFW 端口规则需要同步。" : "UFW 端口配置及内核用户规则与当前节点一致。"); }
  for (const rule of missing) {
    // prepend deliberately does not replace the comment on an equivalent manual rule (ufw(8)).
    await linuxFirewallMutation(s, "ufw", ["prepend", ...linuxUfwSpec(s.plan.scope, rule)]);
    entries = await linuxUfwSnapshot(s);
    if (!entries.some(e => e.comment === linuxUfwComment(s.plan.scope, rule) && e.rule.key === rule.key)) linuxFirewallFail("blocked", "UFW 未能确认新规则的归属（可能已有等价规则，或 IPv6 未启用）；保留原有规则。");
  }
  linuxUfwCheckOrdering(s, entries); await linuxUfwCheckRuntime(s, entries);
  for (const entry of stale) {
    entries = await linuxUfwSnapshot(s);
    const same = entries.filter(e => e.action === "ALLOW" && e.anySource && e.rule.key === entry.rule.key);
    if (!same.some(e => e.comment === entry.comment)) continue;
    if (same.length !== 1) linuxFirewallFail("blocked", "UFW 规则在同步期间发生变化，已停止清理旧规则。");
    await linuxFirewallMutation(s, "ufw", ["--force", "delete", ...linuxUfwSpec(s.plan.scope, entry.rule)]);
  }
  entries = await linuxUfwSnapshot(s);
  if (s.plan.rules.some(rule => !entries.some(entry => linuxUfwCovers(entry, rule))) || own().some(entry => !s.plan.rules.some(rule => rule.key === entry.rule.key))) linuxFirewallFail("error", "UFW 最终校验失败；请检查状态，不能确认全部端口规则已同步。");
  linuxUfwCheckOrdering(s, entries); await linuxUfwCheckRuntime(s, entries);
  return linuxFirewallResult(s, "synced", "UFW 已同步并验证当前节点端口配置及内核用户规则，规则会由 UFW 持久保存。");
}

interface LinuxFirewalldClaim { zone: string; rule: FirewallRule; runtime: boolean; permanent: boolean }
interface LinuxFirewallJournal { schema: 1; scope: string; backend?: Exclude<LinuxFirewallBackend, "none">; firewalld: LinuxFirewalldClaim[] }
function linuxFirewalldZoneValid(zone: string): boolean { return /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(zone); }
function linuxFirewallCheckStatePath(context: LinuxFirewallContext): void {
  const parent = linuxFirewallPath.dirname(context.stateFile);
  if (!linuxFirewallPath.isAbsolute(context.stateFile) || linuxFirewallPath.basename(context.stateFile) !== "firewall-linux-state.json") linuxFirewallFail("blocked", "防火墙状态文件必须位于安装数据目录。");
  const stat = linuxFirewallFs.lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || linuxFirewallFs.realpathSync(parent) !== linuxFirewallPath.resolve(parent)) linuxFirewallFail("blocked", "防火墙状态目录不是受保护的真实目录，已停止写入。");
  try { const old = linuxFirewallFs.lstatSync(context.stateFile); if (!old.isFile() || old.isSymbolicLink() || old.nlink !== 1 || old.size > 512 * 1024) linuxFirewallFail("blocked", "防火墙状态文件类型或大小不合法。"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}
function linuxFirewallReadJournal(plan: FirewallPlan, context: LinuxFirewallContext): LinuxFirewallJournal {
  linuxFirewallCheckStatePath(context);
  let value: unknown;
  try {
    const fd = linuxFirewallFs.openSync(context.stateFile, linuxFirewallFs.constants.O_RDONLY | linuxFirewallFs.constants.O_NOFOLLOW);
    try { const stat = linuxFirewallFs.fstatSync(fd); if (!stat.isFile() || stat.nlink !== 1 || stat.size > 512 * 1024) linuxFirewallFail("blocked", "防火墙状态文件不合法。"); value = JSON.parse(linuxFirewallFs.readFileSync(fd, "utf8")); }
    finally { linuxFirewallFs.closeSync(fd); }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { schema: 1, scope: plan.scope, firewalld: [] };
    if (error instanceof SyntaxError) linuxFirewallFail("blocked", "防火墙归属记录已损坏；请先检查状态文件，不能安全清理已有规则。");
    throw error;
  }
  const j = value as LinuxFirewallJournal;
  if (!j || j.schema !== 1 || j.scope !== plan.scope || (j.backend !== undefined && !["ufw", "firewalld", "iptables"].includes(j.backend)) || !Array.isArray(j.firewalld) || j.firewalld.length > 1024) linuxFirewallFail("blocked", "防火墙归属记录不属于当前安装或格式不合法。");
  const ids = new Set<string>();
  for (const claim of j.firewalld) {
    if (!claim || !linuxFirewalldZoneValid(claim.zone) || typeof claim.runtime !== "boolean" || typeof claim.permanent !== "boolean") linuxFirewallFail("blocked", "防火墙归属记录含非法条目。");
    claim.rule = linuxFirewallValidateRule(claim.rule);
    const id = `${claim.zone}/${claim.rule.key}`; if (ids.has(id)) linuxFirewallFail("blocked", "防火墙归属记录含重复条目。"); ids.add(id);
  }
  return j;
}
function linuxFirewallWriteJournal(context: LinuxFirewallContext, journal: LinuxFirewallJournal): void {
  linuxFirewallCheckStatePath(context);
  const temporary = `${context.stateFile}.${process.pid}.${linuxFirewallCrypto.randomBytes(6).toString("hex")}.tmp`;
  let fd: number | undefined;
  try {
    fd = linuxFirewallFs.openSync(temporary, "wx", 0o600);
    linuxFirewallFs.writeFileSync(fd, JSON.stringify(journal, null, 2) + "\n", "utf8");
    // Only finite ports and ownership metadata; readable after sudo without changing directory ownership.
    linuxFirewallFs.fchmodSync(fd, 0o644); linuxFirewallFs.fsyncSync(fd); linuxFirewallFs.closeSync(fd); fd = undefined;
    linuxFirewallCheckStatePath(context); linuxFirewallFs.renameSync(temporary, context.stateFile);
    const parentFd = linuxFirewallFs.openSync(linuxFirewallPath.dirname(context.stateFile), "r");
    try { linuxFirewallFs.fsyncSync(parentFd); } finally { linuxFirewallFs.closeSync(parentFd); }
  } finally {
    if (fd !== undefined) linuxFirewallFs.closeSync(fd);
    try { linuxFirewallFs.unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
}
/** OS-backed SQLite lock: a crash releases the lock, unlike PID files, while the intent journal survives. */
function linuxFirewallAcquireLocks(contexts: LinuxFirewallContext[]): () => void {
  const databases: linuxFirewallSqlite.Database[] = [];
  try {
    for (const context of [...new Map(contexts.map(c => [c.stateFile, c])).values()].sort((a, b) => a.stateFile.localeCompare(b.stateFile))) {
      linuxFirewallCheckStatePath(context);
      const lockFile = context.stateFile.replace(/\.json$/, "-lock.sqlite");
      try { const stat = linuxFirewallFs.lstatSync(lockFile); if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 1024 * 1024) linuxFirewallFail("blocked", "防火墙同步锁文件不合法。"); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        const fd = linuxFirewallFs.openSync(lockFile, "wx", 0o644); linuxFirewallFs.closeSync(fd);
      }
      const database = new linuxFirewallSqlite.Database(lockFile, { create: true }); databases.push(database);
      try { database.exec("PRAGMA busy_timeout = 3000; BEGIN EXCLUSIVE;"); }
      catch (error) {
        if (/locked|busy/i.test(String(error))) linuxFirewallFail("blocked", "另一个进程正在同步防火墙，请稍后重试。");
        if (/readonly|permission/i.test(String(error))) linuxFirewallFail("permission-required", "同步防火墙需要管理员权限才能取得安装目录的同步锁。");
        throw error;
      }
    }
  } catch (error) { for (const database of databases.reverse()) database.close(); throw error; }
  return () => { for (const database of databases.reverse()) { try { database.exec("ROLLBACK;"); } finally { database.close(); } } };
}
function linuxFirewalldRichRule(scope: string, rule: FirewallRule): string {
  const priority = -10000 - Number.parseInt(scope.slice(0, 8), 16) % 20000;
  return `rule family="ipv${rule.family}" priority="${priority}" destination address="${rule.destination}" port port="${rule.port}" protocol="${rule.protocol}" accept`;
}
function linuxFirewalldArgs(claim: LinuxFirewalldClaim, permanent: boolean, action: "query" | "add" | "remove", scope: string): string[] {
  return [...(permanent ? ["--permanent"] : []), `--zone=${claim.zone}`, `--${action}-rich-rule=${linuxFirewalldRichRule(scope, claim.rule)}`];
}
async function linuxFirewalldHas(s: LinuxFirewallSession, claim: LinuxFirewalldClaim, permanent: boolean): Promise<boolean> {
  const r = await linuxFirewallRun(s, "firewall-cmd", linuxFirewalldArgs(claim, permanent, "query", s.plan.scope));
  if (r.code === 0 && /^yes\s*$/i.test(r.stdout.trim())) return true;
  if (r.code === 1 && /^no\s*$/i.test(r.stdout.trim())) return false;
  linuxFirewallSuccess(r, "查询 firewalld 规则");
  linuxFirewallFail("error", "firewalld 返回了无法确认的查询结果。");
}
async function linuxFirewalldSelectZone(s: LinuxFirewallSession, options: FirewallOptions): Promise<string> {
  const zones = linuxFirewallSuccess(await linuxFirewallRun(s, "firewall-cmd", ["--get-zones"]), "查询 firewalld zones").split(/\s+/).filter(Boolean);
  let zone = options.firewalldZone;
  if (!zone) {
    const active = linuxFirewallSuccess(await linuxFirewallRun(s, "firewall-cmd", ["--get-active-zones"]), "查询活动 firewalld zone").split(/\r?\n/).filter(line => line.trim() && !/^\s/.test(line)).map(line => line.trim().replace(/\s+\(default\)$/, ""));
    if (active.length > 1) linuxFirewallFail("blocked", `检测到多个活动 zone（${active.join("、")}），请在防火墙高级设置中选择服务器入站网卡对应的 zone。`);
    zone = active[0] || linuxFirewallSuccess(await linuxFirewallRun(s, "firewall-cmd", ["--get-default-zone"]), "查询默认 firewalld zone");
  }
  if (!linuxFirewalldZoneValid(zone) || !zones.includes(zone)) linuxFirewallFail("blocked", "所选 firewalld zone 不存在或名称不合法。");
  return zone;
}
async function linuxFirewalldSync(s: LinuxFirewallSession, options: FirewallOptions, context: LinuxFirewallContext, apply: boolean): Promise<FirewallResult> {
  const journal = s.journal!;
  const zone = s.plan.rules.length ? await linuxFirewalldSelectZone(s, options) : "";
  const desired = s.plan.rules.map(rule => ({ zone, rule, runtime: false, permanent: false }));
  const pending: { claim: LinuxFirewalldClaim; permanent: boolean }[] = [];
  const stale = journal.firewalld.filter(claim => !desired.some(d => d.zone === claim.zone && d.rule.key === claim.rule.key));
  // Read every prospective rule before writing anything. An equal priority does not establish ownership.
  for (const wanted of desired) {
    const claim = journal.firewalld.find(c => c.zone === wanted.zone && c.rule.key === wanted.rule.key) || wanted;
    for (const permanent of [false, true]) {
      const key = permanent ? "permanent" : "runtime";
      const exists = await linuxFirewalldHas(s, claim, permanent);
      if (exists && !claim[key]) linuxFirewallFail("blocked", `firewalld 的 ${claim.zone} zone 已有相同优先级和内容的${permanent ? "永久" : "运行时"}规则，但不属于本安装；不会接管它。`);
      if (!exists) pending.push({ claim, permanent });
    }
  }
  s.warnings.push("firewalld 仅同步所选 zone 的规则；其他 zone、策略对象或云安全组仍需按实际入站路径检查。");
  if (!apply) return linuxFirewallResult(s, pending.length || stale.length ? "needs-update" : "synced", pending.length || stale.length ? "firewalld 端口规则需要同步。" : "firewalld 运行时和永久端口规则均已验证。");
  for (const addition of pending) {
    const { claim, permanent } = addition, key = permanent ? "permanent" : "runtime";
    // Recheck the absence immediately before recording intent, and record before the OS mutation.
    if (await linuxFirewalldHas(s, claim, permanent)) linuxFirewallFail("blocked", "firewalld 规则在同步期间发生变化，已停止修改。");
    if (!journal.firewalld.includes(claim)) journal.firewalld.push(claim);
    claim[key] = true; linuxFirewallWriteJournal(context, journal);
    await linuxFirewallMutation(s, "firewall-cmd", linuxFirewalldArgs(claim, permanent, "add", s.plan.scope));
    if (!await linuxFirewalldHas(s, claim, permanent)) linuxFirewallFail("error", "firewalld 新规则校验失败，尚未清理旧规则。");
  }
  // All new runtime and persistent rules have been verified before pruning any old port/zone.
  for (const claim of stale) {
    for (const permanent of [false, true]) {
      const key = permanent ? "permanent" : "runtime";
      if (!claim[key]) continue;
      if (await linuxFirewalldHas(s, claim, permanent)) await linuxFirewallMutation(s, "firewall-cmd", linuxFirewalldArgs(claim, permanent, "remove", s.plan.scope));
      if (await linuxFirewalldHas(s, claim, permanent)) linuxFirewallFail("error", "firewalld 旧规则仍然存在，清理未完成。");
      claim[key] = false; linuxFirewallWriteJournal(context, journal);
    }
    journal.firewalld = journal.firewalld.filter(c => c !== claim); linuxFirewallWriteJournal(context, journal);
  }
  for (const wanted of desired) for (const permanent of [false, true]) if (!await linuxFirewalldHas(s, wanted, permanent)) linuxFirewallFail("error", "firewalld 最终校验失败，不能确认全部端口规则已同步。");
  return linuxFirewallResult(s, "synced", zone ? `firewalld 已同步 ${zone} zone 的运行时及永久端口规则，无需 reload。` : "已移除本安装创建的 firewalld 端口规则。");
}

interface LinuxIptablesSnapshot { family: 4 | 6; executable: string; available: boolean; lines: string[][]; owned: FirewallRule[]; chainExists: boolean; jumpExists: boolean; active: boolean }
function linuxIptablesChain(scope: string): string { return `NXE_${scope}`; }
function linuxIptablesOwner(scope: string): string[] { return ["-m", "comment", "--comment", `NexusEdge:${scope}:owner`, "-j", "RETURN"]; }
function linuxIptablesJump(scope: string): string[] { return ["-m", "comment", "--comment", `NexusEdge:${scope}:jump`, "-j", linuxIptablesChain(scope)]; }
function linuxIptablesRule(scope: string, rule: FirewallRule): string[] {
  return ["-d", rule.destination, "-p", rule.protocol, "-m", rule.protocol, "--dport", String(rule.port), "-m", "comment", "--comment", `NexusEdge:${scope}:${rule.key}`, "-j", "ACCEPT"];
}
function linuxIptablesParseRule(words: string[], scope: string, family: 4 | 6): FirewallRule | undefined {
  let destination = family === 4 ? "0.0.0.0/0" : "::/0", protocol = "", port = "", comment = "", target = "";
  const modules: string[] = [], seen = new Set<string>();
  for (let i = 0; i < words.length; i += 2) {
    const flag = words[i]!, value = words[i + 1]; if (value === undefined) return;
    if (flag !== "-m" && seen.has(flag)) return; seen.add(flag);
    if (flag === "-d") destination = linuxFirewallNormalizeAddress(value, family);
    else if (flag === "-p") protocol = value;
    else if (flag === "--dport") port = value;
    else if (flag === "--comment") comment = value;
    else if (flag === "-j") target = value;
    else if (flag === "-m") modules.push(value);
    else return;
  }
  if (!destination || !["tcp", "udp"].includes(protocol) || !/^\d+$/.test(port) || target !== "ACCEPT" || modules.length !== 2 || !modules.includes("comment") || !modules.includes(protocol)) return;
  const base = { protocol: protocol as "tcp" | "udp", port: Number(port), family, destination };
  const rule = { ...base, key: linuxFirewallKey(base) };
  if (comment !== `NexusEdge:${scope}:${rule.key}`) return;
  return linuxFirewallValidateRule(rule);
}
async function linuxIptablesSnapshot(s: LinuxFirewallSession, family: 4 | 6): Promise<LinuxIptablesSnapshot> {
  const executable = family === 4 ? "iptables" : "ip6tables", chain = linuxIptablesChain(s.plan.scope);
  const reply = await linuxFirewallRun(s, executable, ["-w", "5", "-S"]);
  if (reply.code === 127) return { family, executable, available: false, lines: [], owned: [], chainExists: false, jumpExists: false, active: false };
  if (family === 6 && reply.code !== 0 && /address family not supported|protocol not supported/i.test(reply.stderr)) return { family, executable, available: false, lines: [], owned: [], chainExists: false, jumpExists: false, active: false };
  const text = linuxFirewallSuccess(reply, `读取 ${executable} filter 表`);
  if (/incompatible|use .?nft/i.test(reply.stderr)) linuxFirewallFail("unsupported", `${executable} 无法完整读取现有规则；请使用当前系统防火墙管理工具手动放行。`);
  const lines = text.split(/\r?\n/).filter(line => line.trim() && !line.startsWith("#")).map(linuxFirewallWords);
  if (!lines.some(line => line[0] === "-P" && line[1] === "INPUT")) linuxFirewallFail("blocked", `${executable} 返回了无法识别的 INPUT 链。`);
  const chainExists = lines.some(line => linuxFirewallSameWords(line, ["-N", chain]));
  const chainRules = lines.filter(line => line[0] === "-A" && line[1] === chain).map(line => line.slice(2));
  const ownMarker = linuxIptablesOwner(s.plan.scope);
  const ownerCount = chainRules.filter(line => linuxFirewallSameWords(line, ownMarker)).length;
  if (chainExists && (ownerCount !== 1 || !linuxFirewallSameWords(chainRules[chainRules.length - 1] || [], ownMarker))) linuxFirewallFail("blocked", `${executable} 的 ${chain} 链没有完整的本安装标记，不会接管或清空它。`);
  const owned: FirewallRule[] = [];
  for (const words of chainRules) {
    if (linuxFirewallSameWords(words, ownMarker)) continue;
    const rule = linuxIptablesParseRule(words, s.plan.scope, family);
    if (!rule) linuxFirewallFail("blocked", `${executable} 的本安装链包含其他规则，不会修改。`);
    if (owned.some(r => r.key === rule.key)) linuxFirewallFail("blocked", `${executable} 的本安装链包含重复规则，请先手动检查。`);
    owned.push(rule);
  }
  const references = lines.filter(line => line[0] === "-A" && line.some((word, i) => (word === "-j" || word === "-g") && line[i + 1] === chain));
  if (references.length > 1 || references.some(line => line[1] !== "INPUT" || !linuxFirewallSameWords(line.slice(2), linuxIptablesJump(s.plan.scope)))) linuxFirewallFail("blocked", `${executable} 存在其他规则引用本安装链，已停止自动修改。`);
  const jumpExists = references.length === 1;
  const inputRules = lines.filter(line => line[0] === "-A" && line[1] === "INPUT");
  if (jumpExists && s.plan.rules.some(rule => rule.family === family) && inputRules[0] !== references[0]) linuxFirewallFail("blocked", `${executable} 的本安装入口前出现了其他 INPUT 规则；请检查顺序，避免错误报告端口已放行。`);
  const active = lines.some(line => line[0] === "-P" && line[1] === "INPUT" && line[2] !== "ACCEPT") || inputRules.length > 0 || chainExists;
  return { family, executable, available: true, lines, owned, chainExists, jumpExists, active };
}
async function linuxIptablesCheckNft(s: LinuxFirewallSession): Promise<void> {
  const [nft, version4, version6] = await Promise.all([linuxFirewallRun(s, "nft", ["-j", "list", "ruleset"]), linuxFirewallRun(s, "iptables", ["--version"]), linuxFirewallRun(s, "ip6tables", ["--version"])]);
  for (const version of [version4, version6]) if (version.code !== 127) linuxFirewallSuccess(version, "查询 iptables 后端");
  if (nft.code === 127) {
    if (version4.code === 127 && version6.code === 127) return;
    linuxFirewallFail("unsupported", "无法检查原生 nftables 策略（nft 命令不可用）。请安装 nft 以完成只读检测，或手动放行端口。");
  }
  const raw = linuxFirewallSuccess(nft, "检查 nftables input 链");
  let data: { nftables?: { chain?: { family?: string; table?: string; name?: string; hook?: string; type?: string; prio?: number | string } }[] };
  try { data = JSON.parse(raw); } catch { linuxFirewallFail("blocked", "无法解析 nftables 规则集，已停止自动放行。"); }
  if (!Array.isArray(data.nftables)) linuxFirewallFail("blocked", "nftables 规则集格式无法确认。");
  const conflicts = data.nftables.flatMap(entry => {
    const c = entry.chain;
    if (!c || c.hook !== "input") return [];
    const version = c.family === "ip" ? version4 : c.family === "ip6" ? version6 : undefined;
    if (version?.code === 0 && /nf_tables/.test(version.stdout) && c.table === "filter" && c.name === "INPUT" && c.type === "filter" && [0, "filter"].includes(c.prio!)) return [];
    return [`${c.family}/${c.table}/${c.name}`];
  });
  if (conflicts.length) linuxFirewallFail("unsupported", `检测到原生 nftables input 链（${conflicts.join("、")}）。独立 iptables ACCEPT 无法保证绕过其 DROP 策略，请在现有 nftables 管理配置中放行这些端口。`);
}
async function linuxIptablesSync(s: LinuxFirewallSession, apply: boolean): Promise<FirewallResult> {
  await linuxIptablesCheckNft(s);
  let snapshots = await Promise.all(([4, 6] as const).map(family => linuxIptablesSnapshot(s, family)));
  for (const rule of s.plan.rules) if (!snapshots.find(snapshot => snapshot.family === rule.family)?.available) linuxFirewallFail("unsupported", `当前系统缺少 ${rule.family === 4 ? "iptables" : "ip6tables"}，无法自动处理所需的 IPv${rule.family} 端口。`);
  if (!snapshots.some(snapshot => snapshot.available)) return linuxFirewallResult(s, "inactive", "未检测到正在管理本机端口的 UFW、firewalld 或可用的 iptables；未创建防火墙策略。");
  if (!snapshots.some(snapshot => snapshot.active)) return linuxFirewallResult(s, "inactive", "iptables INPUT 当前未设置过滤规则且默认允许入站，无需额外放行；工具不会替您启用防火墙。");
  s.warnings.push("iptables 规则仅在当前内核运行期生效；本工具以管理员权限启动时会重新同步。不会保存或覆盖系统的整个规则集。");
  s.warnings.push("此状态验证本机 filter/INPUT 规则；其他内核过滤路径、路由和云安全组仍可能影响连通性。");
  const changed = snapshots.some(snapshot => {
    const desired = s.plan.rules.filter(rule => rule.family === snapshot.family);
    return desired.some(rule => !snapshot.owned.some(owned => owned.key === rule.key)) || snapshot.owned.some(rule => !desired.some(wanted => wanted.key === rule.key)) || (desired.length > 0 && !snapshot.jumpExists) || (desired.length === 0 && snapshot.chainExists);
  });
  if (!apply) return linuxFirewallResult(s, changed ? "needs-update" : "synced", changed ? "iptables 端口规则需要同步。" : "iptables 本安装端口规则已验证。");
  // Create all ports in both address families before any stale port is deleted.
  for (const snapshot of snapshots) {
    const desired = s.plan.rules.filter(rule => rule.family === snapshot.family);
    if (!desired.length) continue;
    const chain = linuxIptablesChain(s.plan.scope), base = ["-w", "5"];
    if (!snapshot.chainExists) {
      await linuxFirewallMutation(s, snapshot.executable, [...base, "-N", chain]);
      await linuxFirewallMutation(s, snapshot.executable, [...base, "-A", chain, ...linuxIptablesOwner(s.plan.scope)]);
    }
    for (const rule of desired) if (!snapshot.owned.some(owned => owned.key === rule.key)) await linuxFirewallMutation(s, snapshot.executable, [...base, "-I", chain, "1", ...linuxIptablesRule(s.plan.scope, rule)]);
    if (!snapshot.jumpExists) await linuxFirewallMutation(s, snapshot.executable, [...base, "-I", "INPUT", "1", ...linuxIptablesJump(s.plan.scope)]);
  }
  snapshots = await Promise.all(([4, 6] as const).map(family => linuxIptablesSnapshot(s, family)));
  for (const rule of s.plan.rules) if (!snapshots.some(snapshot => snapshot.family === rule.family && snapshot.jumpExists && snapshot.owned.some(owned => owned.key === rule.key))) linuxFirewallFail("error", "iptables 新规则校验失败，保留旧端口规则。");
  for (const snapshot of snapshots) {
    if (!snapshot.available || !snapshot.chainExists) continue;
    const desired = s.plan.rules.filter(rule => rule.family === snapshot.family), chain = linuxIptablesChain(s.plan.scope), base = ["-w", "5"];
    for (const rule of snapshot.owned) if (!desired.some(wanted => wanted.key === rule.key)) await linuxFirewallMutation(s, snapshot.executable, [...base, "-D", chain, ...linuxIptablesRule(s.plan.scope, rule)]);
    if (!desired.length) {
      if (snapshot.jumpExists) await linuxFirewallMutation(s, snapshot.executable, [...base, "-D", "INPUT", ...linuxIptablesJump(s.plan.scope)]);
      await linuxFirewallMutation(s, snapshot.executable, [...base, "-D", chain, ...linuxIptablesOwner(s.plan.scope)]);
      await linuxFirewallMutation(s, snapshot.executable, [...base, "-X", chain]);
    }
  }
  snapshots = await Promise.all(([4, 6] as const).map(family => linuxIptablesSnapshot(s, family)));
  for (const snapshot of snapshots) {
    const desired = s.plan.rules.filter(rule => rule.family === snapshot.family);
    if (desired.some(rule => !snapshot.jumpExists || !snapshot.owned.some(owned => owned.key === rule.key)) || snapshot.owned.some(rule => !desired.some(wanted => wanted.key === rule.key)) || (!desired.length && snapshot.chainExists)) linuxFirewallFail("error", "iptables 最终规则校验失败，部分规则可能尚未同步。");
  }
  return linuxFirewallResult(s, "synced", "iptables 已同步并验证本安装的 IPv4 / IPv6 端口规则。");
}

async function linuxFirewallOperate(plan: FirewallPlan, options: FirewallOptions, runner: FirewallCommandRunner, context: LinuxFirewallContext, apply: boolean): Promise<FirewallResult> {
  const s: LinuxFirewallSession = { plan, runner, backend: "none", changed: false, warnings: [], context };
  let release: (() => void) | undefined;
  try {
    linuxFirewallValidatePlan(plan);
    if (!["auto", "ufw", "firewalld", "iptables"].includes(options.linuxBackend) || typeof options.firewalldZone !== "string") linuxFirewallFail("blocked", "Linux 防火墙设置格式不合法。");
    const detected = await linuxFirewallDetect(s, options); s.backend = detected.backend;
    if (!detected.active) return linuxFirewallResult(s, "inactive", plan.rules.length ? `${detected.backend} 未运行；工具不会自动开启防火墙，也未修改已有策略。` : `${detected.backend} 未运行；已有持久规则仍保留。请恢复原防火墙后端后重试移除本工具规则。`);
    if (apply) release = linuxFirewallAcquireLocks([context]);
    s.journal = linuxFirewallReadJournal(plan, context);
    if (s.journal.backend && s.journal.backend !== s.backend) linuxFirewallFail("blocked", `本安装仍记录由 ${s.journal.backend} 管理的规则。请恢复旧后端设置并使用“移除本工具规则”，然后再切换；不要同时启用两个管理器。`);
    if (s.backend !== "firewalld" && s.journal.firewalld.some(claim => claim.runtime || claim.permanent)) linuxFirewallFail("blocked", "本安装尚有 firewalld 规则记录，请先使用 firewalld 清理或确认旧规则，不能直接混用其他后端。");
    const result = s.backend === "ufw" ? await linuxUfwSync(s, apply) : s.backend === "firewalld" ? await linuxFirewalldSync(s, options, context, apply) : await linuxIptablesSync(s, apply);
    if (apply && plan.rules.length && result.status === "synced" && !s.journal.backend) { s.journal.backend = s.backend as Exclude<LinuxFirewallBackend, "none">; linuxFirewallWriteJournal(context, s.journal); }
    if (apply && !plan.rules.length && result.status === "synced" && s.journal.backend) { delete s.journal.backend; linuxFirewallWriteJournal(context, s.journal); }
    return result;
  } catch (error) {
    if (error instanceof LinuxFirewallFailure) return linuxFirewallResult(s, error.status, error.message);
    const e = error as NodeJS.ErrnoException;
    return linuxFirewallResult(s, e.code === "EACCES" || e.code === "EPERM" ? "permission-required" : "error", `Linux 防火墙操作未完成：${e.message || String(error)}`);
  } finally { release?.(); }
}
export async function inspectLinuxFirewall(plan: FirewallPlan, options: FirewallOptions, runner: FirewallCommandRunner, context: LinuxFirewallContext): Promise<FirewallResult> {
  return linuxFirewallOperate(plan, options, runner, context, false);
}
export async function applyLinuxFirewall(plan: FirewallPlan, options: FirewallOptions, runner: FirewallCommandRunner, context: LinuxFirewallContext): Promise<FirewallResult> {
  return linuxFirewallOperate(plan, options, runner, context, true);
}

export interface LinuxUfwOwnershipTransfer { result: FirewallResult; rollback: () => Promise<FirewallResult> }
/** Explicit source-to-system migration only. Ordinary sync never changes another installation's comment. */
export async function transferLinuxUfwOwnership(sourcePlan: FirewallPlan, targetPlan: FirewallPlan, runner: FirewallCommandRunner, sourceContext: LinuxFirewallContext, targetContext: LinuxFirewallContext): Promise<LinuxUfwOwnershipTransfer> {
  const source: LinuxFirewallSession = { plan: sourcePlan, runner, backend: "ufw", changed: false, warnings: [], context: sourceContext };
  const target: LinuxFirewallSession = { plan: targetPlan, runner, backend: "ufw", changed: false, warnings: [], context: targetContext };
  const attempted: FirewallRule[] = [];
  const failure = (s: LinuxFirewallSession, error: unknown) => error instanceof LinuxFirewallFailure ? linuxFirewallResult(s, error.status, error.message) : linuxFirewallResult(s, /permission|EACCES|EPERM/i.test(String(error)) ? "permission-required" : "error", `UFW 规则归属迁移未完成：${String(error)}`);
  const rollback = async (): Promise<FirewallResult> => {
    if (!attempted.length) return linuxFirewallResult(source, "synced", "没有需要恢复归属的 UFW 规则。");
    let release: (() => void) | undefined;
    try {
      release = linuxFirewallAcquireLocks([sourceContext, targetContext]);
      source.journal = linuxFirewallReadJournal(sourcePlan, sourceContext);
      linuxFirewallReadJournal(targetPlan, targetContext);
      for (const rule of [...attempted].reverse()) {
        const entries = await linuxUfwSnapshot(target);
        const same = entries.filter(e => e.action === "ALLOW" && e.anySource && e.rule.key === rule.key);
        if (same.length === 1 && same[0]!.comment === linuxUfwComment(sourcePlan.scope, rule)) continue;
        if (same.length !== 1 || same[0]!.comment !== linuxUfwComment(targetPlan.scope, rule)) linuxFirewallFail("blocked", "迁移后的 UFW 规则已由其他操作更改，不能安全恢复归属，请检查该端口。");
        await linuxFirewallMutation(source, "ufw", linuxUfwSpec(sourcePlan.scope, rule));
        if (!(await linuxUfwSnapshot(source)).some(e => e.comment === linuxUfwComment(sourcePlan.scope, rule) && e.rule.key === rule.key)) linuxFirewallFail("error", "UFW 原归属恢复校验失败。");
      }
      attempted.length = 0;
      return linuxFirewallResult(source, "synced", "UFW 规则归属已恢复到原安装；放行的地址和端口未改变。");
    } catch (error) { return failure(source, error); }
    finally { release?.(); }
  };
  let release: (() => void) | undefined;
  try {
    linuxFirewallValidatePlan(sourcePlan); linuxFirewallValidatePlan(targetPlan);
    if (sourcePlan.rules.length !== targetPlan.rules.length || sourcePlan.rules.some(rule => !targetPlan.rules.some(r => r.key === rule.key))) linuxFirewallFail("blocked", "UFW 归属迁移要求源安装和目标安装的监听端口计划完全一致。");
    if (sourcePlan.scope === targetPlan.scope) return { result: linuxFirewallResult(target, "synced", "安装归属相同，无需迁移 UFW 规则。"), rollback };
    const detected = await linuxFirewallDetect(source, { linuxBackend: "auto", firewalldZone: "" });
    if (detected.backend !== "ufw") { target.backend = detected.backend; return { result: linuxFirewallResult(target, "synced", "当前后端无需 UFW 归属迁移。"), rollback }; }
    release = linuxFirewallAcquireLocks([sourceContext, targetContext]);
    source.journal = linuxFirewallReadJournal(sourcePlan, sourceContext); target.journal = linuxFirewallReadJournal(targetPlan, targetContext);
    for (const journal of [source.journal, target.journal]) if ((journal.backend && journal.backend !== "ufw") || journal.firewalld.some(c => c.runtime || c.permanent)) linuxFirewallFail("blocked", "安装目录仍记录其他防火墙后端，不能迁移 UFW 归属。");
    const entries = await linuxUfwSnapshot(source);
    linuxUfwParseStatus(linuxFirewallSuccess(await linuxFirewallRun(target, "ufw", ["status", "numbered"]), "校验目标 UFW 标记"), targetPlan.scope);
    const transfers: FirewallRule[] = [];
    for (const rule of targetPlan.rules) {
      const relevant = entries.filter(e => linuxUfwCovers(e, rule));
      if (relevant.some(e => /^NexusEdge:[0-9a-f]{20}:/.test(e.comment) && ![linuxUfwComment(sourcePlan.scope, rule), linuxUfwComment(targetPlan.scope, rule)].includes(e.comment))) linuxFirewallFail("blocked", "待迁移端口由其他规则或第三个安装覆盖；请先同步原安装规则并检查归属。");
      const owned = relevant.filter(e => e.comment === linuxUfwComment(sourcePlan.scope, rule));
      if (owned.length) {
        if (owned.length !== 1 || relevant.filter(e => e.rule.key === rule.key).length !== 1) linuxFirewallFail("blocked", "待迁移的 UFW 规则存在重复内容，无法安全更新归属。");
        transfers.push(rule);
      }
    }
    for (const rule of transfers) {
      const current = (await linuxUfwSnapshot(source)).filter(e => e.action === "ALLOW" && e.anySource && e.rule.key === rule.key);
      if (current.length !== 1 || current[0]!.comment !== linuxUfwComment(sourcePlan.scope, rule)) linuxFirewallFail("blocked", "UFW 规则在迁移过程中发生变化，已停止归属更新。");
      attempted.push(rule);
      // Deliberate, narrowly verified exception: only relabel this exact known source-owned rule.
      await linuxFirewallMutation(target, "ufw", linuxUfwSpec(targetPlan.scope, rule));
      if (!(await linuxUfwSnapshot(target)).some(e => e.rule.key === rule.key && e.comment === linuxUfwComment(targetPlan.scope, rule))) linuxFirewallFail("error", "UFW 新归属校验失败，请恢复原安装归属。");
    }
    return { result: linuxFirewallResult(target, "synced", "UFW 中原安装拥有的端口规则已迁移到目标安装，手动规则保持原归属。"), rollback };
  } catch (error) { return { result: failure(target, error), rollback }; }
  finally { release?.(); }
}

export const linuxFirewallInternals = { key: linuxFirewallKey, ufwComment: linuxUfwComment, ufwSpec: linuxUfwSpec, ufwParseStatus: linuxUfwParseStatus, richRule: linuxFirewalldRichRule, chain: linuxIptablesChain, iptablesRule: linuxIptablesRule, iptablesOwner: linuxIptablesOwner, iptablesJump: linuxIptablesJump, words: linuxFirewallWords };
