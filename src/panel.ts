import * as panelFs from "node:fs";
import * as panelPath from "node:path";
import * as panelCrypto from "node:crypto";
import { APP_VERSION, type AppConfig, type AppPaths, type DaemonStatus, type NodeConfig, type NodeProtocol, type NodeRoute, NODE_PROTOCOLS, SHADOWSOCKS_METHODS, createDefaultNode, validateNode, validateConfig, readConfig, writeConfig, normalizeDomain, normalizeConnectAddress, normalizeTransportHost, configFingerprint, runtimeConfigFingerprint, generateNodeLinks, generateClientConfig, generateRealityKeyPair, deriveRealityPublicKey, generateShadowsocksPassword, atomicWrite, errorMessage } from "./core.ts";
import { preflightCores, registerWarp, parseWarpProfile, generateSelfSignedCertificate, generateVlessEncryption, readCoreSelection, coreReleaseFingerprint, coreSelectionPath } from "./network.ts";
import { runCorePanel } from "./core-panel.ts";
import { getDaemonStatus, stopDaemonGracefully, startDetachedDaemon, waitForReady, tailLog } from "./daemon.ts";
import { type StartupStatus, isAdministrator, isSystemInstallation, discoverSystemInstallation, runElevated, getStartupStatus, enableStartup, disableStartup, startManaged, stopManaged } from "./platform.ts";
import { selectMenu, promptInput, uiPause, uiValidatedInput, UserCancelledError, UiExitRequestedError } from "./ui.ts";
import { configureSimpleNode, editConnectionAddress, repairNodeAddress, directListenerNotice, type SimplePanelServices } from "./simple.ts";

const panelProtocolLabels: Record<NodeProtocol, string> = {
  vless: "VLESS", vmess: "VMess", shadowsocks: "Shadowsocks / SS2022", trojan: "Trojan",
  hysteria2: "Hysteria2", tuic: "TUIC", anytls: "AnyTLS", socks: "SOCKS5", naive: "NaiveProxy",
};
function panelEndpoint(node: NodeConfig): string {
  const mode = node.tunnel.mode === "none" ? "无隧道" : node.tunnel.mode === "quick" ? "临时隧道" : "固定隧道";
  return `${node.enabled ? "启用" : "停用"} · ${panelProtocolLabels[node.protocol]} / ${node.transport.type} · ${node.listen}:${node.port} · ${node.direct ? "直连" : "仅隧道"} · ${mode} · ${node.egress}`;
}
function panelTunnelOrigin(node: NodeConfig): string {
  const host = node.listen === "0.0.0.0" ? "127.0.0.1" : node.listen === "::" ? "::1" : node.listen;
  return `http://${host.includes(":") ? `[${host}]` : host}:${node.port}`;
}
async function panelInteger(label: string, current: number, minimum = 1, maximum = 65535): Promise<number> {
  return Number(await uiValidatedInput(label, String(current), value => {
    if (!/^\d+$/.test(value) || Number(value) < minimum || Number(value) > maximum) throw new Error(`请输入 ${minimum}–${maximum} 的整数。`);
    return value;
  }));
}
async function panelEnum<T extends string>(label: string, help: string, values: readonly T[], current: T, labels: readonly string[] = values): Promise<T> {
  return values[await selectMenu(label, help, [...labels], Math.max(0, values.indexOf(current)))]!;
}
async function panelPassword(node: NodeConfig): Promise<string> {
  const value = await promptInput("密码（回车保留；输入 new 重新生成）", node.password, { secret: true });
  return value === "new" ? node.protocol === "shadowsocks" ? generateShadowsocksPassword(node.method) : panelCrypto.randomBytes(24).toString("base64url") : value;
}
function panelReadPem(filename: string): string {
  const path = filename.trim().replace(/^"(.*)"$/, "$1");
  const info = panelFs.statSync(path);
  if (!info.isFile() || info.size > 512 * 1024) throw new Error("证书 / 私钥应为不超过 512 KiB 的普通 PEM 文件。");
  return panelFs.readFileSync(path, "utf8").replace(/^\uFEFF/, "");
}

async function panelWarp(config: AppConfig): Promise<AppConfig> {
  const choices = [...(config.warp ? ["保留已保存的 WARP 配置"] : []), "导入 WireGuard .conf / WARP JSON", "自动申请 WARP 配置", "取消"];
  const selected = await selectMenu("WARP 配置", "此处保存供节点共享的 WireGuard 凭据；各节点仍独立选择 Direct 或 WARP 出口。\n自动申请使用客户端兼容接口，失败时可导入已有配置。", choices);
  const offset = config.warp ? 1 : 0;
  if (config.warp && selected === 0) return config;
  if (selected === choices.length - 1) throw new UserCancelledError();
  if (selected === offset) {
    const path = (await promptInput("已有 WireGuard / WARP 配置文件路径")).replace(/^"(.*)"$/, "$1");
    const info = panelFs.statSync(path);
    if (!info.isFile() || info.size > 256 * 1024) throw new Error("请选择不超过 256 KiB 的普通配置文件。");
    return { ...config, warp: parseWarpProfile(panelFs.readFileSync(path, "utf8")) };
  }
  const consent = await selectMenu("申请新的 WARP 设备配置", "将向 Cloudflare 注册设备，并在本机保存私钥。请确认你接受 WARP 使用条款：\nhttps://www.cloudflare.com/application/terms/", ["同意并申请", "取消"]);
  if (consent !== 0) throw new UserCancelledError();
  console.log("正在申请 WARP 配置……");
  return { ...config, warp: await registerWarp() };
}

async function panelSecurity(paths: AppPaths, node: NodeConfig): Promise<void> {
  const previousSecurity = node.tls.mode;
  const plainOnly = ["shadowsocks", "socks"].includes(node.protocol) || node.tunnel.mode !== "none";
  if (plainOnly) { node.tls.mode = "none"; node.flow = ""; return; }
  const allowed: NodeConfig["tls"]["mode"][] = node.protocol === "vless" ? node.transport.type === "ws" ? ["none", "tls"] : ["none", "tls", "reality"]
    : node.protocol === "anytls" ? ["tls", "reality"] : node.protocol === "vmess" ? ["none", "tls"] : ["tls"];
  node.tls.mode = await panelEnum("节点安全层", "TLS 可以导入证书或生成自签证书；REALITY 使用握手目标与密钥。", allowed, node.tls.mode,
    allowed.map(value => value === "none" ? "不附加 TLS" : value === "tls" ? "TLS 证书" : "REALITY"));
  if (node.tls.mode === "none") { node.flow = ""; return; }
  const suggestedName = node.tls.mode === "reality" ? node.tls.serverName || node.tls.reality.handshakeServer : node.tls.serverName || node.address || "nexus.local";
  console.log(node.tls.mode === "reality"
    ? "SNI 是 REALITY 目标网站的域名，需要与下面的握手目标匹配；不是 VPS 的 IP，也不要求你拥有这个域名。"
    : "SNI 是证书对应的名称，不是本机监听 IP。使用自动证书时保留已有名称即可；使用自己的证书时填证书覆盖的域名。"
  );
  node.tls.serverName = await uiValidatedInput("TLS / REALITY 服务器名称（SNI；通常保留）", suggestedName, value => {
    const result = node.tls.mode === "reality" ? normalizeDomain(value) : normalizeConnectAddress(value);
    if (!result) throw new Error("请填写服务器名称或证书 IP。"); return result;
  });
  if (node.tls.mode === "reality") {
    node.tls.insecure = false;
    node.tls.reality.handshakeServer = await uiValidatedInput("REALITY 握手目标主机（支持 TLS 1.3 的真实站点）", node.tls.reality.handshakeServer || node.tls.serverName, value => {
      const result = normalizeConnectAddress(value); if (!result) throw new Error("握手目标不能为空。"); return result;
    });
    node.tls.reality.handshakePort = await panelInteger("REALITY 握手目标端口", node.tls.reality.handshakePort);
    const hasKey = Boolean(node.tls.reality.privateKey);
    const choices = [...(hasKey ? ["保留已有 REALITY 密钥"] : []), "生成新的 REALITY 密钥对", "输入自己的 REALITY 私钥"];
    const action = await selectMenu("REALITY 密钥", "公钥会从私钥派生，用于生成客户端配置；私钥只保存在服务端配置中。", choices);
    const offset = hasKey ? 1 : 0;
    if (action === offset) Object.assign(node.tls.reality, generateRealityKeyPair());
    if (action === offset + 1) {
      node.tls.reality.privateKey = await uiValidatedInput("REALITY 私钥", node.tls.reality.privateKey, value => { deriveRealityPublicKey(value); return value; }, { secret: true });
      node.tls.reality.publicKey = deriveRealityPublicKey(node.tls.reality.privateKey);
    }
    node.tls.reality.shortId = await uiValidatedInput("REALITY Short ID（偶数位十六进制，最长 16 位；- 留空）", node.tls.reality.shortId || (hasKey ? "" : panelCrypto.randomBytes(8).toString("hex")), value => {
      if (!/^(?:[0-9a-fA-F]{2}){0,8}$/.test(value)) throw new Error("Short ID 须为 0–16 位偶数长度的十六进制。"); return value.toLowerCase();
    }, { clearable: true });
  } else {
    const hasCertificate = Boolean(node.tls.certificatePem && node.tls.keyPem);
    const selfSignedDescription = node.protocol === "vless" ? "生成自签证书（客户端固定证书指纹）" : node.protocol === "naive" ? "生成自签证书（客户端信任此证书）" : "生成自签证书（客户端跳过 CA 校验）";
    const choices = [...(hasCertificate ? ["保留已有证书与私钥"] : []), "导入 PEM 证书与私钥文件", selfSignedDescription];
    const action = await selectMenu("TLS 证书", "证书与私钥内容会随节点配置保存，系统安装迁移时会一并复制。", choices);
    const offset = hasCertificate ? 1 : 0;
    if (action === offset) {
      node.tls.certificatePem = panelReadPem(await promptInput("PEM 证书文件路径"));
      node.tls.keyPem = panelReadPem(await promptInput("PEM 私钥文件路径"));
      node.tls.insecure = false;
    }
    if (action === offset + 1) {
      console.log("使用对应官方核心生成自签证书……");
      Object.assign(node.tls, await generateSelfSignedCertificate(paths, node));
      node.tls.insecure = true;
    }
    const localTrust = node.protocol === "vless" ? "固定此证书的 SHA-256 指纹（自签证书）" : node.protocol === "naive" ? "将此证书加入客户端信任配置（自签证书）" : "跳过 CA 校验（自签证书）";
    const trustHelp = node.protocol === "vless" ? "Xray 使用当前证书指纹校验自签证书。更换证书后，需要重新导出客户端配置。" : node.protocol === "naive" ? "Naive 自签模式在客户端 JSON 中内嵌公开证书，私钥不会导出。证书名称仍须匹配 SNI。" : "受信任证书建议严格校验；自签证书可使用跳过 CA 校验的客户端配置。";
    node.tls.insecure = (await selectMenu("客户端证书校验", trustHelp, ["使用系统受信任的 CA 校验证书", localTrust], node.tls.insecure ? 1 : 0)) === 1;
  }
  const suggestedAlpn = node.protocol === "hysteria2" || node.protocol === "tuic" ? "h3" : node.transport.type === "ws" ? "http/1.1" : node.transport.type === "grpc" || node.protocol === "naive" ? "h2" : "h2,http/1.1";
  const alpn = await promptInput("ALPN（英文逗号分隔；输入 - 留空交给核心）", node.tls.alpn.join(",") || (previousSecurity === "none" ? suggestedAlpn : ""), { clearable: true });
  node.tls.alpn = alpn ? alpn.split(",").map(value => value.trim()).filter(Boolean) : [];
}

/** Public for the real terminal workflow regression; it only saves after a final summary. */
export async function configureNode(paths: AppPaths, existing?: NodeConfig): Promise<void> {
  let config = readConfig(paths);
  const protocol = await panelEnum("选择节点协议 · 高级模式", "这里逐项自定义配置。通常可返回节点管理使用简易模式；编辑时回车保留已有参数。", NODE_PROTOCOLS, existing?.protocol ?? "vless", NODE_PROTOCOLS.map(item => panelProtocolLabels[item]));
  let node = existing?.protocol === protocol ? structuredClone(existing) : createDefaultNode(protocol, config.nodes.filter(item => item.id !== existing?.id));
  if (existing && existing.protocol !== protocol) { node.id = existing.id; node.name = existing.name; }
  node.name = await promptInput("节点名称", node.name);
  if (["vless", "vmess", "trojan"].includes(protocol)) {
    const transports: NodeConfig["transport"]["type"][] = protocol === "vless" ? ["tcp", "ws", "grpc", "xhttp"] : ["tcp", "ws", "grpc"];
    node.transport.type = await panelEnum("传输方式", "Cloudflare HTTP 隧道只适用于 VLESS / VMess 的 WebSocket 传输。", transports, node.transport.type);
  } else node.transport.type = "tcp";
  if (node.transport.type === "ws" || node.transport.type === "xhttp") {
    node.transport.path = await uiValidatedInput("传输路径，例如 /nexus-ws", node.transport.path, value => {
      if (!/^\/[A-Za-z0-9/._~-]*$/.test(value) || value.includes("//") || value.split("/").some(item => item === "." || item === "..")) throw new Error("路径仅允许 /、英文字母、数字、-._~，不要预先做 URL 编码。"); return value;
    });
    node.transport.host = await uiValidatedInput("传输 Host（留空使用连接地址）", node.transport.host, normalizeTransportHost, { clearable: true });
    if (node.transport.type === "xhttp") node.transport.mode = await panelEnum("XHTTP 模式", "服务端与导出客户端将使用相同模式。", ["auto", "packet-up", "stream-up", "stream-one"] as const, node.transport.mode);
  }
  if (node.transport.type === "grpc") node.transport.serviceName = await promptInput("gRPC serviceName", node.transport.serviceName);
  if (["vless", "vmess"].includes(protocol) && node.transport.type === "ws") {
    node.tunnel.mode = await panelEnum("是否额外开启隧道", "关闭时按节点 IP / 域名和端口直连；隧道与节点协议是独立选项。", ["none", "quick", "fixed"] as const, node.tunnel.mode, ["关闭隧道", "临时隧道（自动分配域名）", "固定隧道（Token + 公共主机名）"]);
  } else node.tunnel.mode = "none";
  if (node.tunnel.mode !== "none") {
    node.direct = (await selectMenu("节点接入方式", "仅隧道将监听本机回环地址；同时直连会开放所选监听地址。\n此组合的本机 WS 不附加 TLS，隧道客户端由 Cloudflare 提供 TLS。", ["仅通过隧道接入", "保留直连接入，同时开启隧道"], existing?.direct ? 1 : 0)) === 1;
    if (!node.direct) node.listen = node.listen.includes(":") ? "::1" : "127.0.0.1";
    if (node.tunnel.mode === "fixed") {
      node.tunnel.token = await uiValidatedInput("完整 Tunnel Token", node.tunnel.token, value => {
        if (!/^[A-Za-z0-9_+/=-]{16,16384}$/.test(value)) throw new Error("请输入完整 Tunnel Token。"); return value;
      }, { secret: true });
      node.tunnel.domain = await uiValidatedInput("隧道公共主机名", node.tunnel.domain, normalizeDomain);
    }
    node.tunnel.connectAddress = await uiValidatedInput("隧道客户端连接 IP / 域名（默认跟随隧道域名）", node.tunnel.connectAddress, normalizeConnectAddress, { clearable: true });
    node.tunnel.protocol = await panelEnum("隧道连接传输", "所在网络不允许 UDP 时可选择 HTTP2。", ["auto", "http2", "quic"] as const, node.tunnel.protocol, ["自动", "HTTP2", "QUIC"]);
  } else node.direct = true;
  if (node.direct) {
    console.log("监听 IP 控制本机哪些网卡接收连接，通常保持 0.0.0.0；它与下面供客户端使用的 VPS IP 是两项不同设置。");
    node.listen = await promptInput("监听 IP（本机范围；0.0.0.0 为全部 IPv4，:: 为 IPv6）", existing?.direct === false ? existing.listen === "::1" ? "::" : "0.0.0.0" : node.listen);
  }
  const previousPort = node.port;
  node.port = await panelInteger("本地监听端口", node.port);
  if (node.publicPort === previousPort) node.publicPort = node.port;
  if (node.direct) {
    node.address = await uiValidatedInput("客户端连接的公网 / 局域网 IP 或域名（可留空，之后补填）", node.address, normalizeConnectAddress, { clearable: true });
    node.publicPort = await panelInteger("客户端连接端口（NAT 映射时可与监听端口不同）", node.publicPort);
  }
  if (["vless", "vmess", "tuic"].includes(protocol)) {
    node.uuid = await uiValidatedInput("节点 UUID（回车保留；输入 new 重新生成）", node.uuid, value => {
      if (value === "new") return panelCrypto.randomUUID();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error("UUID 格式无效。"); return value.toLowerCase();
    });
  }
  if (["socks", "naive"].includes(protocol)) node.username = await promptInput("认证用户名", node.username);
  if (protocol === "shadowsocks") {
    const method = await panelEnum("Shadowsocks 加密方法", "SS2022 需要对应长度的 Base64 密钥；更换算法后会生成匹配的新密码。", SHADOWSOCKS_METHODS, node.method as typeof SHADOWSOCKS_METHODS[number]);
    if (method !== node.method) node.password = generateShadowsocksPassword(method);
    node.method = method;
  }
  if (["shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"].includes(protocol)) node.password = await panelPassword(node);
  if (protocol === "vmess") node.vmessSecurity = await panelEnum("VMess 客户端加密方式", "AEAD 节点，alterId 固定为 0。", ["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"] as const, node.vmessSecurity);
  await panelSecurity(paths, node);
  if (protocol === "vless") {
    const encryption = await selectMenu("VLESS Encryption", "按客户端支持情况选择；ENC 会生成并保存配对的服务端解密参数和客户端加密参数。", ["不使用额外 VLESS ENC", "保留当前 ENC（如已设置）", "生成新的 ML-KEM-768 ENC 参数", "手动输入成对 ENC 参数"], node.vlessEncryption === "none" ? 0 : 1);
    if (encryption === 0) { node.vlessEncryption = "none"; node.vlessDecryption = "none"; }
    if (encryption === 2) {
      console.log("正在使用官方 Xray 生成 ENC 参数……");
      const pair = await generateVlessEncryption(paths);
      node.vlessEncryption = pair.vlessEncryption; node.vlessDecryption = pair.vlessDecryption;
    }
    if (encryption === 3) {
      node.vlessDecryption = await promptInput("服务端 decryption", node.vlessDecryption, { secret: true });
      node.vlessEncryption = await promptInput("客户端 encryption", node.vlessEncryption, { secret: true });
    }
    let supportsVision = true;
    try { validateNode({ ...node, flow: "xtls-rprx-vision" }, { allowIncomplete: true }); } catch { supportsVision = false; }
    node.flow = supportsVision ? await panelEnum("VLESS Flow", "客户端需支持所选组合。", ["", "xtls-rprx-vision"] as const, node.flow, ["普通 VLESS", "XTLS Vision"]) : "";
  }
  if (protocol === "hysteria2") {
    node.hy2.obfsPassword = await promptInput("Salamander 混淆密码（可留空）", node.hy2.obfsPassword, { secret: true, clearable: true });
    node.hy2.upMbps = await panelInteger("服务端上行 Mbps（客户端下载）", node.hy2.upMbps, 0, 100000);
    node.hy2.downMbps = await panelInteger("服务端下行 Mbps（客户端上传）", node.hy2.downMbps, 0, 100000);
  }
  if (protocol === "tuic") {
    node.tuic.congestionControl = await panelEnum("TUIC 拥塞控制", "服务端与导出客户端使用所选算法。", ["bbr", "cubic", "new_reno"] as const, node.tuic.congestionControl);
    node.tuic.zeroRttHandshake = (await selectMenu("TUIC 0-RTT", "默认关闭。", ["关闭", "开启"], node.tuic.zeroRttHandshake ? 1 : 0)) === 1;
  }
  node.egress = await panelEnum("此节点的出口", "仅影响这个节点代理出去的流量，其他节点可使用不同出口。", ["direct", "warp"] as const, node.egress, ["本机 Direct", "WARP WireGuard"]);
  if (node.egress === "warp" && !config.warp) config = await panelWarp(config);
  node.enabled = (await selectMenu("保存后的节点状态", "保存不会自动中断当前后台；选择“启动 / 重启全部节点”后应用。", ["启用此节点", "保存为停用节点"], node.enabled ? 0 : 1)) === 0;
  node = validateNode(node);
  const nodes = config.nodes.some(item => item.id === node.id) ? config.nodes.map(item => item.id === node.id ? node : item) : [...config.nodes, node];
  const candidate = validateConfig({ ...config, nodes }, { allowExpiredCertificate: true });
  const decision = await selectMenu("保存节点", `${node.name}\n${panelEndpoint(node)}\n客户端地址：${node.address || "未填写（暂不导出直连链接）"}:${node.publicPort}\nTLS：${node.tls.mode}${node.tls.serverName ? ` / ${node.tls.serverName}` : ""}\n${node.tunnel.mode === "fixed" ? `Cloudflare 需将 ${node.tunnel.domain} 映射到 ${panelTunnelOrigin(node)}` : ""}`, ["保存", "取消"]);
  if (decision !== 0) throw new UserCancelledError();
  writeConfig(paths, candidate);
  console.log("节点已保存。选择“启动 / 重启全部节点”应用配置。");
}

async function panelPickNode(config: AppConfig, title: string): Promise<NodeConfig | null> {
  if (!config.nodes.length) { console.log("还没有节点，请先添加节点。"); return null; }
  let page = 0;
  for (;;) {
    const start = page * 6, visible = config.nodes.slice(start, start + 6);
    const labels = visible.map(node => `${node.name} · ${node.enabled ? "启用" : "停用"} · ${node.protocol} :${node.port}`);
    const previous = page > 0 ? labels.push("上一页") - 1 : -1;
    const next = start + visible.length < config.nodes.length ? labels.push("下一页") - 1 : -1;
    const back = labels.push("返回") - 1;
    const selected = await selectMenu(title, `共 ${config.nodes.length} 个节点，第 ${page + 1} 页`, labels);
    if (selected === back) return null;
    if (selected === previous) { page--; continue; }
    if (selected === next) { page++; continue; }
    return visible[selected]!;
  }
}

async function panelManageNodes(paths: AppPaths): Promise<void> {
  for (;;) {
    const config = readConfig(paths);
    const choice = await selectMenu("节点管理", `已创建 ${config.nodes.length} / 32 个节点。默认使用简易模式，选协议后即可保存。`, ["新增节点（简易模式）", "编辑节点（简易模式）", "高级配置（逐项自定义）", "启用 / 停用节点", "复制节点", "删除节点", "返回"]);
    if (choice === 6) return;
    const simpleActions = { apply: (candidate: AppConfig) => panelApplyConfiguration(paths, candidate), advanced: (draft: NodeConfig) => configureNode(paths, draft) };
    try {
      if (choice === 0) {
        if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
        await configureSimpleNode(paths, undefined, simpleActions);
      } else {
        const node = await panelPickNode(config, "选择节点");
        if (!node) continue;
        if (choice === 1) await configureSimpleNode(paths, node, simpleActions);
        else if (choice === 2) await configureNode(paths, node);
        else if (choice === 3) {
          node.enabled = !node.enabled;
          writeConfig(paths, validateConfig(config, { allowExpiredCertificate: true }));
          console.log(`已${node.enabled ? "启用" : "停用"}；重启全部节点后应用。`);
        } else if (choice === 4) {
          if (config.nodes.length >= 32) throw new Error("已达到 32 个节点上限。");
          const fresh = createDefaultNode(node.protocol, config.nodes);
          const copy = { ...structuredClone(node), id: fresh.id, name: `${node.name}-副本`, port: fresh.port, publicPort: fresh.port };
          await configureSimpleNode(paths, copy, simpleActions);
        } else if (choice === 5) {
          if (await selectMenu("删除节点", `将删除配置中的 ${node.name}；重启全部节点后停止其监听。`, ["取消", "删除此节点"]) === 1) {
            writeConfig(paths, { ...config, nodes: config.nodes.filter(item => item.id !== node.id) });
            console.log("节点配置已删除。重启全部节点后应用；删除最后一个节点后请选择停止全部节点。");
          }
        }
      }
    } catch (e) {
      if (e instanceof UiExitRequestedError) throw e;
      if (e instanceof UserCancelledError) continue;
      console.log(errorMessage(e));
    }
    await uiPause();
  }
}

/** Address and NAT-port metadata can change without changing a running tunnel. Old workers retain the full-hash check. */
export function panelRuntimeMatches(status: DaemonStatus | null, config: AppConfig, paths?: AppPaths): boolean {
  if (!status || !(status.runtimeConfigHash ? status.runtimeConfigHash === runtimeConfigFingerprint(config) : status.configHash === configFingerprint(config))) return false;
  if (!paths) return true;
  // Older workers do not report their selected release set. Once a selection
  // exists, they must restart before the panel can claim it has been applied.
  if (!status.coreReleaseHash) return !panelFs.existsSync(coreSelectionPath(paths));
  try { return status.coreReleaseHash === coreReleaseFingerprint(readCoreSelection(paths).active); }
  catch { return false; }
}

export async function panelExport(paths: AppPaths, services: Partial<SimplePanelServices> = {}): Promise<void> {
  const selected = await panelPickNode(readConfig(paths), "选择要查看 / 导出的节点");
  if (!selected) return;
  let node = selected;
  const routes: NodeRoute[] = [...(node.direct ? ["direct" as const] : []), ...(node.tunnel.mode !== "none" ? ["tunnel" as const] : [])];
  let route = routes.length === 1 ? routes[0]! : await panelEnum("查看哪种接入链接", "直连使用服务器地址；隧道使用 Cloudflare 域名，不需要先填写 VPS IP。", routes, "direct", routes.map(item => item === "direct" ? "直连" : "隧道"));
  let notice = "";
  for (;;) {
    if (route === "direct" && !node.address) node = await repairNodeAddress(paths, node.id, services);
    const config = readConfig(paths);
    node = config.nodes.find(item => item.id === selected.id)!;
    if (!node) throw new Error("节点已删除，请重新选择。");
    const status = await getDaemonStatus(paths), running = status?.nodes?.find(item => item.id === node.id);
    const unchanged = panelRuntimeMatches(status, config, paths);
    // Never reuse a hostname with a different running UUID/path/TLS configuration.
    const assigned = unchanged ? running?.domain ?? undefined : undefined;
    const link = generateNodeLinks(node, assigned).find(item => item.via === route);
    let client: ReturnType<typeof generateClientConfig> | undefined;
    let failure = link?.error || "";
    try { client = generateClientConfig(node, route, assigned); } catch (error) { failure ||= errorMessage(error); }
    const items = ["back", ...(client ? ["saveJson", "showJson"] : []), ...(link?.uri ? ["saveLink"] : []), ...(route === "direct" ? ["address"] : []), ...(routes.length > 1 ? ["route"] : [])];
    const labels: Record<string, string> = { back: "返回（链接已显示在上方，可直接复制）", saveJson: "保存完整客户端 JSON", showJson: "显示完整客户端 JSON", saveLink: "保存节点链接到文本文件", address: "修改连接地址 / 端口", route: route === "direct" ? "查看隧道链接" : "查看直连链接" };
    const information = [
      `${node.name} · ${route === "direct" ? "直连" : "隧道"}`,
      !node.enabled ? "此节点已停用。以下为保存配置，启用并应用后才会监听。"
        : unchanged ? `运行状态：${running?.phase ?? "未运行"}；${running?.detail ?? ""}` : "以下为保存配置；当前后台尚未运行这份服务端配置。",
      route === "direct" ? directListenerNotice(node) : "",
      failure || link?.uri || "此组合使用完整客户端 JSON。请选择保存或显示。",
      ...(client ? [`客户端 JSON：${client.format} 格式，本地代理端口 1080。`] : []), notice,
    ].filter(Boolean).join("\n\n");
    const action = items[await selectMenu("节点链接与客户端配置", information, items.map(item => labels[item]!))]!;
    if (action === "back") return;
    if (action === "route") { route = route === "direct" ? "tunnel" : "direct"; notice = ""; continue; }
    if (action === "showJson" && client) { console.log(JSON.stringify(client.config, null, 2)); await uiPause(); }
    else if ((action === "saveJson" && client) || (action === "saveLink" && link?.uri)) {
      const extension = action === "saveLink" ? "txt" : "json";
      const filename = await promptInput("保存路径", panelPath.join(paths.data, "exports", `${node.id}-${route}.${extension}`));
      const destination = panelPath.resolve(filename.replace(/^"(.*)"$/, "$1"));
      atomicWrite(destination, action === "saveLink" ? link!.uri! + "\n" : JSON.stringify(client!.config, null, 2) + "\n");
      notice = `已保存：${destination}`;
    } else if (action === "address") {
      const changed = await editConnectionAddress(node, services);
      const latest = readConfig(paths), current = latest.nodes.find(item => item.id === node.id);
      if (JSON.stringify(current) !== JSON.stringify(node)) throw new Error("节点已在另一处修改，请重新打开导出界面。");
      writeConfig(paths, { ...latest, nodes: latest.nodes.map(item => item.id === node.id ? changed : item) });
      node = changed;
      notice = "连接设置已保存。只改 IP / 对外端口立即更新链接；修改本机端口或监听范围需在主菜单应用。";
    }
  }
}

async function panelSharedSettings(paths: AppPaths): Promise<void> {
  let config = readConfig(paths);
  const selected = await selectMenu("共享设置", "节点协议和出口在节点编辑器中设置；这里管理共享 WARP 凭据和可选通知。", ["导入 / 申请 WARP 配置", "通知设置", "返回"]);
  if (selected === 2) return;
  if (selected === 0) config = await panelWarp(config);
  if (selected === 1) {
    const kinds: AppConfig["webhook"]["kind"][] = ["none", "generic", "feishu", "wecom", "dingtalk", "bark"];
    const kind = await panelEnum("通知类型", "启用后，节点就绪通知会将完整链接发送到指定 HTTPS 接口。签名机器人需使用自己的适配器。", kinds, config.webhook.kind, ["关闭通知", "通用 JSON", "飞书", "企业微信", "钉钉", "Bark"]);
    const url = kind === "none" ? "" : await uiValidatedInput("HTTPS 通知接口", config.webhook.url, value => { validateConfig({ ...config, webhook: { kind, url: value } }, { allowExpiredCertificate: true }); return value; }, { secret: true });
    config.webhook = { kind, url };
  }
  writeConfig(paths, config);
  console.log("共享设置已保存，重启全部节点后应用。");
}

export async function prepareRuntime(paths: AppPaths, config = readConfig(paths)): Promise<AppConfig> {
  const validated = validateConfig(config);
  if (!validated.nodes.some(node => node.enabled)) throw new Error("没有启用的节点。请先进入节点管理添加或启用节点。");
  console.log("按已启用节点准备所需核心并校验配置……");
  await preflightCores(paths, validated);
  console.log("所需核心与配置预检通过。");
  return validated;
}

async function panelReadiness(paths: AppPaths): Promise<void> {
  console.log("等待已启用节点监听，以及所选隧道连接，最多 45 秒……");
  let last = "";
  const status = await waitForReady(paths, 45000, current => {
    const next = current ? Array.isArray(current.nodes) ? `${current.phase} · ${current.nodes.filter(node => node.phase === "ready").length}/${current.nodes.filter(node => node.enabled).length} 个节点就绪` : "旧版后台仍在运行，请从主菜单重启全部节点应用新版本" : "等待后台响应";
    if (next !== last) { console.log(next); last = next; }
  });
  if (!status) { console.log("未确认后台响应，请查看日志。"); console.log(tailLog(paths, 15)); return; }
  if (!Array.isArray(status.nodes)) { console.log("当前仍为旧版后台。请在新版面板选择“启动 / 重启全部节点”应用升级。"); return; }
  for (const node of status.nodes) {
    console.log(`\n${node.name}：${node.phase} · ${node.detail}`);
    for (const link of node.links) console.log(`${link.label}：${link.error || link.uri || "请从导出菜单取得客户端 JSON"}`);
    if (node.lastError) console.log(node.lastError);
  }
  console.log("\n就绪检查确认本机监听及所选隧道连接。直连的公网端口 / NAT / 防火墙和客户端实际访问仍需现场验证。");
  console.log("关闭面板后后台继续运行；部分节点未就绪时，其他已就绪节点可以继续使用。");
}

async function panelStop(paths: AppPaths, startup: StartupStatus): Promise<void> {
  if (startup.mode !== "none") await stopManaged(paths); else await stopDaemonGracefully(paths);
}

async function panelApplyConfiguration(paths: AppPaths, candidate: AppConfig): Promise<void> {
  const current = await getDaemonStatus(paths);
  if (panelRuntimeMatches(current, candidate, paths)) {
    writeConfig(paths, candidate);
    console.log("配置已保存。服务端参数保持一致，后台继续运行；链接地址会自动刷新。");
    return;
  }
  if (candidate.nodes.some(node => node.enabled)) await prepareRuntime(paths, candidate);
  writeConfig(paths, candidate);
  try {
    const startup = await getStartupStatus(paths);
    await panelStop(paths, startup);
    if (!candidate.nodes.some(node => node.enabled)) { console.log("已保存停用状态，并停止后台节点。"); return; }
    if (startup.mode !== "none") await startManaged(paths); else await startDetachedDaemon(paths);
    await panelReadiness(paths);
  } catch (error) {
    console.log(`配置已保存，但后台应用未完成：${errorMessage(error)}\n处理后可从主菜单选择“启动 / 重启全部节点”重试。`);
  }
}

async function panelStartup(paths: AppPaths, current: StartupStatus): Promise<boolean> {
  if (current.enabled) { await disableStartup(paths); console.log("自动启动已关闭，当前后台继续运行。需要停止时请选择停止全部节点。"); return false; }
  await prepareRuntime(paths);
  if (isSystemInstallation(paths)) {
    await enableStartup(paths, "system"); await startManaged(paths); await panelReadiness(paths); return false;
  }
  const mode = process.platform === "win32" ? await selectMenu("自动启动模式", "系统模式会安装到受保护目录，需要时请求 UAC。用户模式只在该用户登录后运行。", ["系统开机启动（SYSTEM，无需登录）", "当前用户登录后启动", "取消"]) : await selectMenu("启用系统自启", "需要 systemd，程序将安装到 /opt/nexus-edge；必要时请求 sudo。", ["启用系统自启", "取消"]);
  if ((process.platform === "win32" && mode === 2) || (process.platform !== "win32" && mode === 1)) return false;
  if (mode === 1 && process.platform === "win32") {
    await panelStop(paths, current); await enableStartup(paths, "user"); await startManaged(paths); await panelReadiness(paths); return false;
  }
  const requestId = panelCrypto.randomUUID();
  try { await runElevated(paths, ["--install-system", requestId]); }
  catch (e) {
    let result: { requestId?: string; message?: string } | undefined;
    try { result = JSON.parse(panelFs.readFileSync(panelPath.join(paths.data, "installation-result.json"), "utf8")); } catch {}
    if (result?.requestId === requestId && result.message) throw new Error(result.message);
    throw e;
  }
  if (!discoverSystemInstallation()) throw new Error("安装命令已退出，但未确认激活的系统副本。");
  return true;
}

export async function runPanel(paths: AppPaths): Promise<"exit" | "handoff"> {
  if (!process.stdin.isTTY) throw new Error("管理面板需要交互式 PowerShell / cmd / Windows Terminal / Linux 终端。");
  for (;;) {
    const config = readConfig(paths);
    const [status, admin, startup] = await Promise.all([getDaemonStatus(paths), isAdministrator(), getStartupStatus(paths)]);
    const dirty = Boolean(status && !panelRuntimeMatches(status, config, paths));
    const enabled = config.nodes.filter(node => node.enabled);
    const information = [
      `后台：${status?.phase ?? "未运行"}    权限：${admin ? "管理员 / root" : "普通用户"}`,
      `节点：${config.nodes.length} 个（${enabled.length} 个启用）    隧道：${enabled.filter(node => node.tunnel.mode !== "none").length} 个`,
      `自启：${startup.detail}`, `数据：${paths.data}`,
      ...(dirty ? ["已保存的配置或内核版本尚未应用。重启全部节点后生效。"] : []),
      ...(!config.nodes.length ? ["节点管理 → 新增节点：选协议 → 保存并应用。隧道默认关闭。"] : []),
    ].join("\n");
    const choice = await selectMenu(`NexusEdge ${APP_VERSION} 节点管理`, information, ["启动 / 重启全部节点", "停止全部节点", "节点管理（新增 / 编辑 / 启停 / 删除）", "查看链接 / 导出客户端配置", "WARP 与通知设置", "查看运行日志", startup.enabled ? "关闭自动启动" : "开启自动启动", "内核管理 / 更新", "退出面板（保留后台）"]);
    if (choice === 8) return "exit";
    try {
      if (choice === 0) { await prepareRuntime(paths); await panelStop(paths, startup); if (startup.mode !== "none") await startManaged(paths); else await startDetachedDaemon(paths); await panelReadiness(paths); }
      else if (choice === 1) { await panelStop(paths, startup); console.log("后台及各节点核心已停止，自动启动设置保持不变。"); }
      else if (choice === 2) { await panelManageNodes(paths); continue; }
      else if (choice === 3) { await panelExport(paths); continue; }
      else if (choice === 4) await panelSharedSettings(paths);
      else if (choice === 5) console.log(tailLog(paths));
      else if (choice === 6 && await panelStartup(paths, startup)) return "handoff";
      else if (choice === 7) { await runCorePanel(paths); continue; }
    } catch (e) {
      if (e instanceof UiExitRequestedError) throw e;
      if (e instanceof UserCancelledError) continue;
      console.log(`\n${errorMessage(e)}`);
    }
    await uiPause();
  }
}
