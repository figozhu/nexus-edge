import * as simpleNet from "node:net";
import * as simpleDgram from "node:dgram";
import * as simpleCrypto from "node:crypto";
import { type AppConfig, type AppPaths, type NodeConfig, NODE_PROTOCOLS, nodeListenNetworks, normalizeConnectAddress, normalizeDomain, validateNode, validateConfig, readConfig, writeConfig, generateShadowsocksPassword, errorMessage } from "./core.ts";
import { type PublicAddressResult, type LocalAddressCandidate, detectPublicAddresses, listLocalAddresses } from "./address.ts";
import { SIMPLE_PROTOCOL_LABELS, createSimpleNode, applySimpleTunnel } from "./presets.ts";
import { generateSelfSignedCertificate, generateVlessEncryption } from "./network.ts";
import { selectMenu, promptInput, uiValidatedInput, UserCancelledError, UiExitRequestedError } from "./ui.ts";
import { getFirewallSettings } from "./core.ts";
import { buildFirewallPlan } from "./firewall.ts";
import { firewallPortSummary } from "./firewall-panel.ts";

export interface SimplePanelServices {
  detectAddresses: () => Promise<PublicAddressResult>;
  localAddresses: () => LocalAddressCandidate[];
  availablePort: (node: NodeConfig, others: NodeConfig[]) => Promise<number>;
  certificate: typeof generateSelfSignedCertificate;
  encryption: typeof generateVlessEncryption;
}
export interface SimplePanelActions {
  /** Preflight before saving, then apply. A failed preflight must keep the previous config. */
  apply: (config: AppConfig) => Promise<void>;
  advanced: (node: NodeConfig) => Promise<void>;
}

function simpleService(overrides: Partial<SimplePanelServices> = {}): SimplePanelServices {
  return { detectAddresses: detectPublicAddresses, localAddresses: listLocalAddresses,
    availablePort: findAvailableNodePort, certificate: generateSelfSignedCertificate,
    encryption: generateVlessEncryption, ...overrides };
}

function simpleProbePort(node: NodeConfig, port: number, network: "tcp" | "udp"): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const failed = (error: NodeJS.ErrnoException) => {
      if (error.code === "EADDRINUSE") resolve(false);
      else reject(new Error(`无法检查本机端口 ${port}：${error.code || error.message}`));
    };
    if (network === "tcp") {
      const server = simpleNet.createServer();
      server.once("error", failed);
      server.listen({ host: node.listen, port, exclusive: true }, () => server.close(() => resolve(true)));
    } else {
      const socket = simpleDgram.createSocket(simpleNet.isIP(node.listen) === 6 ? "udp6" : "udp4");
      socket.once("error", error => { try { socket.close(); } catch {} failed(error); });
      socket.bind({ address: node.listen, port, exclusive: true }, () => socket.close(() => resolve(true)));
    }
  });
}

/** Check both configured reservations and the actual TCP/UDP sockets. This is not a permanent reservation. */
export async function findAvailableNodePort(node: NodeConfig, others: NodeConfig[]): Promise<number> {
  const networks = nodeListenNetworks(node);
  for (let offset = 0; offset < 128 && node.port + offset <= 65535; offset++) {
    const port = node.port + offset;
    if (others.some(other => other.id !== node.id && other.enabled && other.port === port && nodeListenNetworks(other).some(network => networks.includes(network)))) continue;
    let available = true;
    for (const network of networks) if (!await simpleProbePort(node, port, network)) { available = false; break; }
    if (available) return port;
  }
  throw new Error("附近的默认端口均被占用，请在“连接地址与端口”里指定另一个端口。");
}

export function normalizeClientAddress(value: string): string {
  const address = normalizeConnectAddress(value);
  if (!address || address === "0.0.0.0" || address === "::") {
    throw new Error("请填手机 / 电脑实际连接的服务器 IP 或域名。0.0.0.0 / :: 是本机监听范围，不能用于连接。");
  }
  return address;
}

export function directListenerNotice(node: NodeConfig): string {
  if (!node.direct || !node.address) return "";
  const family = simpleNet.isIP(node.address);
  if (["127.0.0.1", "::1"].includes(node.listen) && !["127.0.0.1", "::1", "localhost"].includes(node.address)) {
    return "当前只接收本机连接；若没有反向代理，请在地址设置中改为对外监听并应用配置。";
  }
  if (family === 6 && simpleNet.isIP(node.listen) === 4) return "连接地址是 IPv6，本机却只监听 IPv4；请在地址设置中调整监听范围并应用配置。";
  if (family === 4 && simpleNet.isIP(node.listen) === 6 && node.listen !== "::") return "连接地址是 IPv4，本机却只监听指定 IPv6；请检查地址设置中的监听范围。";
  return "";
}

/** Only a new draft may automatically change wildcard listener family. Existing deliberate bindings stay intact. */
export function applyDetectedAddress(node: NodeConfig, result: PublicAddressResult, newDraft = false): { node: NodeConfig; notice: string } {
  const next = structuredClone(node);
  if (result.cancelled) return { node: next, notice: "公网 IP 探测已取消，连接地址保持原值。" };
  const v6Listener = simpleNet.isIP(node.listen) === 6;
  const address = newDraft ? result.ipv4 || result.ipv6 : v6Listener ? result.ipv6 || (node.listen === "::" ? result.ipv4 : null) : result.ipv4;
  if (!address) {
    const mismatch = !newDraft && !v6Listener && result.ipv6;
    return { node: next, notice: mismatch
      ? "只检测到公网 IPv6，当前节点监听 IPv4。可手动填 IPv6 并调整监听范围，或填写可达的 IPv4 / 域名。"
      : "暂未探测到公网 IP；可重试、手动填写服务器 IP / 域名，或选择局域网地址。" };
  }
  next.address = normalizeClientAddress(address);
  if (newDraft && ["0.0.0.0", "::"].includes(next.listen)) next.listen = simpleNet.isIP(address) === 6 ? "::" : "0.0.0.0";
  const extra = result.warnings.filter(item => /WARP/i.test(item));
  if (simpleNet.isIP(address) === 6) extra.unshift("使用 IPv6 地址时，客户端所在网络也需要能访问 IPv6。");
  return { node: next, notice: [`已自动填写公网 ${simpleNet.isIP(address) === 6 ? "IPv6" : "IPv4"}。探测得到的是出口地址；有 NAT / 系统 VPN 时，请核对实际可达地址。`, ...extra].join("\n") };
}

async function simpleDetect(node: NodeConfig, service: SimplePanelServices, newDraft: boolean): Promise<{ node: NodeConfig; notice: string }> {
  console.log("正在自动获取公网 IP（优先 IPv4，最多约 3 秒）……");
  try { return applyDetectedAddress(node, await service.detectAddresses(), newDraft); }
  catch { return { node: structuredClone(node), notice: "公网 IP 探测暂时失败。可手动填写 VPS 的 IP / 域名，或选择局域网地址。" }; }
}

async function simplePort(label: string, current: number): Promise<number> {
  return Number(await uiValidatedInput(label, String(current), value => {
    if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error("请输入 1–65535 的整数端口。");
    return value;
  }));
}

function simpleAssignManual(node: NodeConfig, address: string, newDraft: boolean): void {
  node.address = normalizeClientAddress(address);
  if (newDraft && ["0.0.0.0", "::"].includes(node.listen) && simpleNet.isIP(node.address)) node.listen = simpleNet.isIP(node.address) === 6 ? "::" : "0.0.0.0";
}

async function simpleLocalAddress(node: NodeConfig, service: SimplePanelServices, newDraft: boolean): Promise<string> {
  // Scoped IPv6 link-local addresses need an interface zone, which this client model does not support.
  const addresses = service.localAddresses().filter(item => item.scope !== "link-local");
  if (!addresses.length) return "没有可用的本机网卡地址，请手动填写。";
  let page = 0;
  for (;;) {
    const start = page * 6, visible = addresses.slice(start, start + 6);
    const labels = visible.map(item => `${item.address} · ${item.interfaceName} · ${item.scope === "public" ? "网卡公网地址" : item.scope === "shared" ? "运营商共享地址" : "局域网"}`);
    const previous = page ? labels.push("上一页") - 1 : -1;
    const next = start + visible.length < addresses.length ? labels.push("下一页") - 1 : -1;
    const back = labels.push("返回") - 1;
    const selected = await selectMenu("选择本机网卡地址", "局域网地址通常只供同一网络使用。这里不会把它当成公网 IP。", labels);
    if (selected === back) return "连接地址保持不变。";
    if (selected === previous) { page--; continue; }
    if (selected === next) { page++; continue; }
    simpleAssignManual(node, visible[selected]!.address, newDraft);
    return "已选择本机网卡地址，请确认客户端处于能够访问它的网络。";
  }
}

/** This screen edits only address/ports, except an explicitly chosen listener repair. */
export async function editConnectionAddress(node: NodeConfig, overrides: Partial<SimplePanelServices> = {}, newDraft = false): Promise<NodeConfig> {
  const service = simpleService(overrides);
  let draft = structuredClone(node), notice = "";
  for (;;) {
    const warning = directListenerNotice(draft);
    const actions = ["重新自动探测公网 IP", "手动填写服务器 IP / 域名", "选择局域网 / 本机网卡地址", "修改本机端口", "设置对外映射端口（NAT）",
      ...(warning ? ["调整为匹配连接地址的对外监听（应用后生效）"] : []), "返回摘要"];
    const selected = await selectMenu("连接地址与端口", [
      `客户端连接：${draft.address ? draft.address.includes(":") ? `[${draft.address}]` : draft.address : "尚未填写"}:${draft.publicPort}`,
      `本机端口：${draft.port}；监听范围：${draft.listen}`,
      "服务器 / VPS 的 IP 是客户端连接地址；0.0.0.0 表示接收所有本机 IPv4 网卡的连接。",
      "一般只需修改第一项地址；没有端口映射时，对外端口与本机端口相同。", warning, notice,
    ].filter(Boolean).join("\n"), actions);
    if (selected === actions.length - 1) return draft;
    try {
      if (selected === 0) { const result = await simpleDetect(draft, service, newDraft); draft = result.node; notice = result.notice; }
      else if (selected === 1) { simpleAssignManual(draft, await uiValidatedInput("客户端实际连接的 IP / 域名", draft.address, normalizeClientAddress), newDraft); notice = "已使用手动地址，自动探测不会覆盖它。"; }
      else if (selected === 2) notice = await simpleLocalAddress(draft, service, newDraft);
      else if (selected === 3) {
        const previous = draft.port;
        draft.port = await simplePort("本机服务端口", draft.port);
        if (draft.publicPort === previous) draft.publicPort = draft.port;
        notice = "修改本机端口需要应用配置；已独立设置的 NAT 映射端口会保留。";
      } else if (selected === 4) { draft.publicPort = await simplePort("客户端连接的对外端口", draft.publicPort); notice = "仅更新链接中的端口；请与已有的端口映射一致。"; }
      else if (selected === 5 && warning) {
        draft.listen = simpleNet.isIP(draft.address) === 6 ? "::" : "0.0.0.0";
        notice = "已在草稿中改为接收对应网卡的连接。保存并应用后生效。";
      }
    } catch (error) { if (error instanceof UiExitRequestedError) throw error; if (error instanceof UserCancelledError) continue; notice = errorMessage(error); }
  }
}

/** Missing-address recovery is the only exceptional path with extra required input. */
async function simpleMissingAddress(node: NodeConfig, service: SimplePanelServices, newDraft: boolean, allowDeferred: boolean): Promise<NodeConfig> {
  let draft = structuredClone(node), notice = "";
  while (!draft.address) {
    const selected = await selectMenu("补齐客户端连接地址", [
      "自动探测尚未得到与此节点匹配的公网 IP。这里需要客户端能访问的 VPS IP / 域名。",
      "0.0.0.0 仅表示本机监听范围，不是服务器的公网地址。", notice,
    ].filter(Boolean).join("\n"), ["重新自动探测", "手动填写 IP / 域名", "选择局域网地址", ...(allowDeferred ? ["仍然保存，稍后填写地址"] : []), "返回"]);
    if (selected === (allowDeferred ? 4 : 3)) throw new UserCancelledError();
    if (selected === 3 && allowDeferred) return draft;
    if (selected === 0) { const result = await simpleDetect(draft, service, newDraft); draft = result.node; notice = result.notice; }
    else if (selected === 1) simpleAssignManual(draft, await uiValidatedInput("客户端实际连接的 IP / 域名", "", normalizeClientAddress), newDraft);
    else notice = await simpleLocalAddress(draft, service, newDraft);
  }
  return draft;
}

/** Export repair writes only a missing address. It never changes UUID, mapping port, SNI or listener. */
export async function repairNodeAddress(paths: AppPaths, nodeId: string, overrides: Partial<SimplePanelServices> = {}): Promise<NodeConfig> {
  const service = simpleService(overrides);
  const node = readConfig(paths).nodes.find(item => item.id === nodeId);
  if (!node) throw new Error("节点已删除，请重新选择。");
  if (!node.direct || node.address) return node;
  let draft = (await simpleDetect(node, service, false)).node;
  if (!draft.address) draft = await simpleMissingAddress(draft, service, false, false);
  const config = readConfig(paths), current = config.nodes.find(item => item.id === nodeId);
  if (!current) throw new Error("节点已删除，请重新选择。");
  if (current.address) return current;
  if (current.listen !== node.listen || current.direct !== node.direct) throw new Error("节点监听设置已在另一处修改，请重新导出。");
  current.address = draft.address;
  writeConfig(paths, config);
  console.log(`已补入客户端地址：${current.address}。UUID、SNI、端口和监听设置保持原值。`);
  return current;
}

async function simpleAuthentication(node: NodeConfig): Promise<void> {
  const hasUuid = ["vless", "vmess", "tuic"].includes(node.protocol);
  const hasUser = ["socks", "naive"].includes(node.protocol);
  const hasPassword = !["vless", "vmess"].includes(node.protocol);
  const items = ["name", ...(hasUuid ? ["uuid"] : []), ...(hasUser ? ["username"] : []), ...(hasPassword ? ["password"] : []), "back"];
  const labels: Record<string, string> = { name: "修改节点名称", uuid: "修改 / 重新生成 UUID", username: "修改用户名", password: "修改 / 重新生成密码", back: "返回摘要" };
  for (;;) {
    const selected = items[await selectMenu("名称与认证", "认证信息已自动生成。只有希望使用自己的账号时才需要修改；不会因为编辑而自动重置。", items.map(item => labels[item]!))]!;
    if (selected === "back") return;
    if (selected === "name") node.name = await uiValidatedInput("节点名称", node.name, value => { validateNode({ ...node, name: value }, { allowIncomplete: true, allowExpiredCertificate: true }); return value; });
    else if (selected === "uuid") node.uuid = await uiValidatedInput("UUID（回车保留；new 生成新值）", node.uuid, value => {
      const next = value === "new" ? simpleCrypto.randomUUID() : value;
      validateNode({ ...node, uuid: next }, { allowIncomplete: true, allowExpiredCertificate: true });
      if (!next) throw new Error("UUID 不能为空。"); return next.toLowerCase();
    });
    else if (selected === "username") node.username = await uiValidatedInput("用户名", node.username, value => { if (!value) throw new Error("用户名不能为空。"); validateNode({ ...node, username: value }, { allowIncomplete: true, allowExpiredCertificate: true }); return value; });
    else node.password = await uiValidatedInput("密码（回车保留；new 生成新值）", node.password, value => {
      const next = value === "new" ? node.protocol === "shadowsocks" ? generateShadowsocksPassword(node.method) : simpleCrypto.randomBytes(24).toString("base64url") : value;
      if (!next) throw new Error("密码不能为空。");
      validateNode({ ...node, password: next }, { allowIncomplete: true, allowExpiredCertificate: true }); return next;
    }, { secret: true });
  }
}

async function simpleTunnel(node: NodeConfig): Promise<{ node: NodeConfig; prepareEncryption: boolean; notice: string }> {
  const mode = node.tunnel.mode;
  const convert = node.protocol === "vless" && mode === "none";
  const selected = await selectMenu("可选隧道", [
    "关闭：使用服务器地址直连。临时：自动分配域名。固定：使用你已有的 Token 和公共主机名。",
    "开启隧道保留当前直连选项；也可在这里明确改为仅隧道。",
    ...(convert ? ["VLESS 开启隧道时会自动改为 WebSocket；保留直连时自动准备 ENC 加密，需重新导入新链接。"] : []),
    `当前：${mode === "none" ? "关闭" : mode === "quick" ? "临时" : "固定"}；${node.direct ? "保留直连" : "仅隧道"}`,
  ].join("\n"), ["关闭隧道", "开启临时隧道（无需域名 / Token）", "开启固定隧道（域名 + Token）", ...(mode !== "none" ? [node.direct ? "改为仅隧道接入" : "同时保留直连接入"] : []), "返回摘要"], mode === "none" ? 0 : mode === "quick" ? 1 : 2);
  if (selected === (mode === "none" ? 3 : 4)) return { node, prepareEncryption: false, notice: "" };
  let next = structuredClone(node);
  if (selected === 3) {
    next.direct = !next.direct;
    next.listen = next.direct ? simpleNet.isIP(next.address) === 6 ? "::" : "0.0.0.0" : simpleNet.isIP(next.listen) === 6 ? "::1" : "127.0.0.1";
  } else {
    next = applySimpleTunnel(node, (["none", "quick", "fixed"] as const)[selected]!);
    if (next.tunnel.mode === "fixed") {
      next.tunnel.domain = await uiValidatedInput("固定隧道公共主机名（例如 node.example.com）", next.tunnel.domain, normalizeDomain);
      next.tunnel.token = await uiValidatedInput("Cloudflare 提供的完整 Tunnel Token", next.tunnel.token, value => {
        if (!/^[A-Za-z0-9_+/=-]{16,16384}$/.test(value)) throw new Error("请输入完整 Tunnel Token；不是 Tunnel ID 或 API Key。"); return value;
      }, { secret: true });
    }
  }
  const prepareEncryption = next.protocol === "vless" && next.tunnel.mode !== "none" && next.direct && next.vlessEncryption === "none" && (mode === "none" || !node.direct);
  const restoreVmessEncryption = next.protocol === "vmess" && next.tunnel.mode !== "none" && next.direct
    && ["none", "zero"].includes(next.vmessSecurity) && ((mode === "none" && node.tls.mode !== "none") || !node.direct);
  if (restoreVmessEncryption) next.vmessSecurity = "auto";
  let notice = "隧道选项已更新；UUID 与已有凭据保留。";
  if (next.protocol === "vless" && mode !== next.tunnel.mode) notice = next.tunnel.mode === "none"
    ? "隧道已关闭，VLESS 恢复 TCP + REALITY + Vision；保存应用后请重新导入链接。"
    : "VLESS 使用 WebSocket 隧道方案；实际直连安全设置见摘要，保存应用后请重新导入链接。";
  if (prepareEncryption) notice = "保留直连时会自动准备 VLESS ENC 加密。直连与隧道客户端都需要重新导入新链接。";
  if (restoreVmessEncryption) notice = "已为直连恢复 VMess 协议加密（auto）。保存应用后，直连与隧道客户端都需要重新导入新链接。";
  return { node: next, prepareEncryption, notice };
}

function simpleSummary(paths: AppPaths, config: AppConfig, node: NodeConfig, existing: boolean, notice: string, prepareEncryption: boolean): string {
  const security = node.tls.mode === "reality" ? `REALITY（目标 ${node.tls.serverName}，密钥已准备）`
    : node.tls.mode === "tls" ? node.tls.certificatePem ? `TLS（已有证书，名称 ${node.tls.serverName}）` : "TLS（保存时自动生成独立证书，无需自备域名）"
    : node.protocol === "vless" ? prepareEncryption ? "ENC（保存时自动生成加密参数）" : node.vlessEncryption !== "none" ? "VLESS ENC" : "无附加 TLS / ENC"
    : node.protocol === "socks" ? "SOCKS5 用户名 / 密码认证" : node.protocol === "vmess" && ["none", "zero"].includes(node.vmessSecurity) ? "VMess 未开启协议加密 / TLS（已有高级配置）" : "协议自身加密";
  const endpoint = node.direct ? `${node.address ? node.address.includes(":") ? `[${node.address}]` : node.address : "尚未探测到 IP，可在下面补填"}:${node.publicPort}` : "仅隧道接入，无需填写 VPS IP";
  const tunnel = node.tunnel.mode === "none" ? "关闭（默认）" : node.tunnel.mode === "quick" ? "临时，启动后自动取得域名" : `固定，${node.tunnel.domain}`;
  const fixedOrigin = node.listen === "0.0.0.0" ? "127.0.0.1" : node.listen === "::" ? "::1" : node.listen;
  return [
    `${node.name} · ${node.protocol.toUpperCase()} / ${node.transport.type.toUpperCase()}`,
    `客户端连接：${endpoint}`, `认证：${existing ? "保留已有凭据" : "已自动生成，可自行修改"}`,
    `安全设置：${security}`, `隧道：${tunnel}；${node.direct ? "直连接入开启" : "直连接入关闭"}`,
    `节点状态：${node.enabled ? "启用" : "停用"}；出口：${node.egress === "direct" ? "本机网络" : "WARP"}`,
    getFirewallSettings(config).mode === "auto" ? `本机防火墙：应用时自动同步（${firewallPortSummary(buildFirewallPlan(paths, { ...config, nodes: [node] }).rules)}；需要时请求管理员授权）` : "本机防火墙：手动管理（可在主菜单开启自动放行）",
    ...(node.tunnel.mode === "fixed" ? [`Cloudflare 映射：${node.tunnel.domain} → http://${fixedOrigin.includes(":") ? `[${fixedOrigin}]` : fixedOrigin}:${node.port}`] : []),
    directListenerNotice(node), notice,
    "默认直接保存即可；只有自定义需求才需要高级配置。应用会重启当前后台，共享核心上的节点会短暂重连。",
  ].filter(Boolean).join("\n");
}

/** Default create path: protocol selection → summary → save/apply. Existing nodes open directly at the summary. */
export async function configureSimpleNode(paths: AppPaths, existing: NodeConfig | undefined, actions: SimplePanelActions, overrides: Partial<SimplePanelServices> = {}): Promise<void> {
  const service = simpleService(overrides), config = readConfig(paths);
  const original = existing ? config.nodes.find(item => item.id === existing.id) : undefined;
  let node: NodeConfig, notice = "", prepareEncryption = false;
  if (existing) node = structuredClone(original ?? existing);
  else {
    if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
    const protocol = NODE_PROTOCOLS[await selectMenu("选择节点协议 · 简易模式", "只选协议即可。IP、可用端口、UUID / 密码和必要的安全设置自动准备；隧道默认关闭。\n需要自己指定路径、SNI 等参数时，在下一页进入高级配置。", NODE_PROTOCOLS.map(item => SIMPLE_PROTOCOL_LABELS[item]))]!;
    node = createSimpleNode(protocol, config.nodes);
  }
  const newDraft = !original;
  if (node.direct && !node.address) { const detected = await simpleDetect(node, service, newDraft); node = detected.node; notice = detected.notice; }
  if (newDraft) {
    try { node.port = await service.availablePort(node, config.nodes); node.publicPort = node.port; }
    catch (error) { notice += `\n${errorMessage(error)}；可修改端口后重试。`; }
  }
  for (;;) {
    const items = ["apply", "save", ...(["vless", "vmess"].includes(node.protocol) ? ["tunnel"] : []), "address", "auth", "advanced", "cancel"];
    const labels: Record<string, string> = { apply: "保存并应用（准备核心 / 启动节点）", save: "仅保存，稍后启动", tunnel: "隧道设置（关闭 / 临时 / 固定）", address: "连接地址与端口", auth: "名称与 UUID / 密码", advanced: "高级配置（传输 / SNI / 证书 / 更多参数）", cancel: "取消，不保存" };
    const selected = items[await selectMenu("节点摘要 · 简易模式", simpleSummary(paths, config, node, Boolean(original), notice, prepareEncryption), items.map(item => labels[item]!))]!;
    if (selected === "cancel") throw new UserCancelledError();
    try {
      if (selected === "tunnel") {
        const changed = await simpleTunnel(node); node = changed.node; notice = changed.notice;
        prepareEncryption = (prepareEncryption || changed.prepareEncryption) && node.tunnel.mode !== "none" && node.direct && node.vlessEncryption === "none";
      } else if (selected === "address") node = await editConnectionAddress(node, service, newDraft);
      else if (selected === "auth") await simpleAuthentication(node);
      else if (selected === "advanced") {
        if (prepareEncryption) { console.log("先准备已选择的 VLESS ENC 加密参数……"); Object.assign(node, await service.encryption(paths)); prepareEncryption = false; }
        await actions.advanced(structuredClone(node)); return;
      }
      else if (selected === "save" || selected === "apply") {
        if (node.direct && !node.address) node = await simpleMissingAddress(node, service, newDraft, true);
        if (prepareEncryption) {
          console.log("正在为 VLESS WebSocket 直连自动准备 ENC 加密参数……");
          Object.assign(node, await service.encryption(paths)); prepareEncryption = false;
        }
        if (node.enabled && node.tls.mode === "tls" && (!node.tls.certificatePem || !node.tls.keyPem)) {
          if (existing || node.tls.certificatePem || node.tls.keyPem) throw new Error("此节点已有的 TLS 证书 / 私钥不完整，请进入高级配置补齐；简易保存不会覆盖现有密钥。");
          console.log("正在自动生成此节点的 TLS 证书（首次会准备对应核心）……");
          Object.assign(node.tls, await service.certificate(paths, node));
          node.tls.insecure = true;
        }
        // Merge into the current file, preserving unrelated nodes and rejecting a concurrent edit to this node.
        const latest = readConfig(paths), current = latest.nodes.find(item => item.id === node.id);
        if (JSON.stringify(current) !== JSON.stringify(original)) throw new Error("这个节点已在另一处修改，请退出后重新打开，避免覆盖新设置。");
        const validated = validateNode(node, { allowExpiredCertificate: selected === "save" });
        const nodes = current ? latest.nodes.map(item => item.id === validated.id ? validated : item) : [...latest.nodes, validated];
        const candidate = validateConfig({ ...latest, nodes }, { allowExpiredCertificate: selected === "save" });
        if (selected === "apply") await actions.apply(candidate);
        else { writeConfig(paths, candidate); console.log("节点已保存。需要启用时选择主菜单的“启动 / 重启全部节点”。"); }
        return;
      }
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      if (error instanceof UserCancelledError) continue;
      notice = `操作未完成：${errorMessage(error)}`;
    }
  }
}
