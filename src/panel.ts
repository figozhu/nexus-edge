import * as panelFs from "node:fs";
import * as panelPath from "node:path";
import * as panelCrypto from "node:crypto";
import * as panelNet from "node:net";
import { createSimpleNode } from "./presets.ts";
import { APP_VERSION, type AppConfig, type AppPaths, type DaemonStatus, type NodeConfig, type NodeProtocol, type NodeRoute, NODE_PROTOCOLS, SHADOWSOCKS_METHODS, createDefaultNode, validateNode, validateConfig, readConfig, writeConfig, normalizeDomain, normalizeConnectAddress, normalizeTransportHost, configFingerprint, runtimeConfigFingerprint, generateNodeLinks, generateClientConfig, generateRealityKeyPair, deriveRealityPublicKey, generateShadowsocksPassword, atomicWrite, errorMessage } from "./core.ts";
import { preflightCores, registerWarp, parseWarpProfile, generateSelfSignedCertificate, generateVlessEncryption, readCoreSelection, coreReleaseFingerprint, coreSelectionPath } from "./network.ts";
import { runCorePanel } from "./core-panel.ts";
import { getDaemonStatus, stopDaemonGracefully, startDetachedDaemon, waitForReady, tailLog } from "./daemon.ts";
import { type StartupStatus, isAdministrator, isSystemInstallation, discoverSystemInstallation, runElevated, getStartupStatus, enableStartup, disableStartup, startManaged, stopManaged } from "./platform.ts";
import { selectMenu, promptInput, uiPause, uiValidatedInput, UserCancelledError, UiExitRequestedError } from "./ui.ts";
import { configureSimpleNode, editNodeAuthentication, nodeAuthenticationLabel, editConnectionAddress, normalizeClientAddress, repairNodeAddress, directListenerNotice, type SimplePanelServices } from "./simple.ts";
import { getFirewallSettings } from "./core.ts";
import { syncFirewallInteractive } from "./firewall-control.ts";
import { firewallPanelSummary, printFirewallResult, requireFirewallApply, runFirewallPanel } from "./firewall-panel.ts";
import { isCoreIpv6Enabled } from "./core.ts";
import { runHostIpv6Panel } from "./ipv6-panel.ts";

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

/** 高级编辑依赖：正式使用官方核心；终端测试注入本地证书/ENC，避免下载与启动服务。 */
export interface PanelEditorServices {
  certificate: typeof generateSelfSignedCertificate;
  encryption: typeof generateVlessEncryption;
}

/** 返回握手目标与 SNI 摘要；node 是草稿，客户端名称不可误标为服务端连接目标。 */
export function panelRealitySummary(node: NodeConfig): string {
  const r = node.tls.reality;
  const host = r.handshakeServer.includes(":") ? `[${r.handshakeServer}]` : r.handshakeServer;
  return `握手目标：${host}:${r.handshakePort}\n客户端 SNI：${node.tls.serverName}${r.handshakeServer === node.tls.serverName ? "（与目标域名相同）" : "（独立设置）"}`;
}

/** 返回规范化的 REALITY 域名；拒绝空值和 IP，避免保存时才发现 SNI 输入错误。 */
function panelRealityDomain(value: string): string {
  const domain = normalizeDomain(value);
  if (!domain || panelNet.isIP(domain)) throw new Error("SNI 必须是目标站点证书支持的域名，不能填写 IP。");
  return domain;
}

/** 仅修改草稿 ALPN；空字符串交给核心协商，立即验证格式，返回值为 void。 */
async function panelAlpn(node: NodeConfig): Promise<void> {
  const value = await uiValidatedInput("ALPN（英文逗号分隔；- 交给核心协商）", node.tls.alpn.join(","), value => {
    const tokens = value ? value.split(",").map(item => item.trim()) : [];
    if (tokens.length > 8 || tokens.some(item => !/^[\x21-\x7e]{1,255}$/.test(item))) throw new Error("ALPN 最多 8 项，每项须为非空 ASCII 标识。");
    return tokens.join(",");
  }, { clearable: true });
  node.tls.alpn = value ? value.split(",") : [];
}

/**
 * 按需编辑 REALITY 草稿。常用入口只输入一次域名，同步握手目标与 SNI；
 * 独立入口保留目标 IP、自定义端口和不同 SNI。已有空 Short ID 和密钥不自动轮换。
 */
async function panelReality(node: NodeConfig): Promise<void> {
  const r = node.tls.reality;
  if (!r.handshakeServer) { r.handshakeServer = "apple.com"; node.tls.serverName = "apple.com"; }
  if (!node.tls.serverName && !panelNet.isIP(r.handshakeServer)) node.tls.serverName = r.handshakeServer;
  if (!r.privateKey) { Object.assign(r, generateRealityKeyPair()); r.shortId ||= panelCrypto.randomBytes(8).toString("hex"); }
  else if (!r.publicKey) r.publicKey = deriveRealityPublicKey(r.privateKey);
  node.tls.insecure = false;
  for (;;) {
    const selected = await selectMenu("REALITY 设置", `${panelRealitySummary(node)}\n握手目标是服务器实际连接的站点；SNI 是客户端握手时声明的证书域名。\n通常两者相同，修改一次即可；目标为 IP 或需要独立 SNI 时才分别设置。\n密钥已准备；Short ID：${r.shortId || "空（有效配置）"}；ALPN：${node.tls.alpn.join(",") || "核心自动协商"}`, [
      "完成，返回节点摘要", "修改目标域名（自动同步 SNI）", "分别设置握手目标 / 端口 / SNI", "密钥与 Short ID", "修改 ALPN",
    ]);
    if (selected === 0) return;
    if (selected === 1) {
      const domain = await uiValidatedInput("REALITY 目标域名（同时用作 SNI）", panelNet.isIP(r.handshakeServer) ? node.tls.serverName : r.handshakeServer, panelRealityDomain);
      r.handshakeServer = domain; node.tls.serverName = domain;
    } else if (selected === 2) {
      const target = await uiValidatedInput("服务器连接的握手目标（域名或 IP）", r.handshakeServer, value => {
        const host = normalizeConnectAddress(value); if (!host) throw new Error("握手目标不能为空。"); return host;
      });
      const port = await panelInteger("握手目标端口（不是节点监听端口）", r.handshakePort);
      const sni = await uiValidatedInput("客户端 SNI（目标证书支持的域名，可与连接目标不同）", node.tls.serverName, panelRealityDomain);
      // 三项输入完成后一起写入；输入中断时不留半组目标/SNI。
      r.handshakeServer = target; r.handshakePort = port; node.tls.serverName = sni;
    } else if (selected === 3) {
      const action = await selectMenu("REALITY 密钥", "公钥由私钥派生；私钥不会导出。更换密钥或 Short ID 后需重新导入客户端配置。", ["保留已有密钥", "生成新的 REALITY 密钥对", "输入自己的 REALITY 私钥"]);
      if (action === 1) Object.assign(r, generateRealityKeyPair());
      if (action === 2) {
        r.privateKey = await uiValidatedInput("REALITY 私钥", r.privateKey, value => { deriveRealityPublicKey(value); return value; }, { secret: true });
        r.publicKey = deriveRealityPublicKey(r.privateKey);
      }
      r.shortId = await uiValidatedInput("REALITY Short ID（偶数位十六进制，最长 16 位；- 留空）", r.shortId, value => {
        if (!/^(?:[0-9a-fA-F]{2}){0,8}$/.test(value)) throw new Error("Short ID 须为 0–16 位偶数长度的十六进制。"); return value.toLowerCase();
      }, { clearable: true });
    } else await panelAlpn(node);
  }
}

/** 按协议编辑草稿安全层；只有一种合法模式时跳过选择，已有证书与密钥默认保留。 */
async function panelSecurity(paths: AppPaths, node: NodeConfig, service: PanelEditorServices): Promise<void> {
  const allowed: NodeConfig["tls"]["mode"][] = node.protocol === "vless" ? node.transport.type === "ws" ? ["none", "tls"] : ["none", "tls", "reality"]
    : node.protocol === "anytls" ? ["tls", "reality"] : node.protocol === "vmess" ? ["none", "tls"] : ["tls"];
  node.tls.mode = allowed.length === 1 ? allowed[0]! : await panelEnum("节点安全层", "TLS 使用本节点证书；REALITY 使用真实站点的握手目标和密钥。", allowed, node.tls.mode,
    allowed.map(value => value === "none" ? "不附加 TLS" : value === "tls" ? "TLS 证书" : "REALITY"));
  if (node.tls.mode === "none") { node.flow = ""; return; }
  if (node.tls.mode === "reality") { await panelReality(node); return; }
  // 旧证书允许空 SNI（导出时使用连接地址）；仅为尚无证书的新安全层补自动证书名称。
  if (!node.tls.serverName && !node.tls.certificatePem && !node.tls.keyPem) node.tls.serverName = "nexus.local";
  for (;;) {
    const selected = await selectMenu("TLS 设置", `证书名称（SNI）：${node.tls.serverName || "跟随客户端连接地址"}\n证书：${node.tls.certificatePem && node.tls.keyPem ? "已有证书与私钥" : "尚未准备；新节点保存时自动生成"}\n客户端校验：${node.tls.insecure ? "自签证书模式" : "系统受信任 CA"}\nALPN：${node.tls.alpn.join(",") || "核心自动协商"}\nSNI 是证书覆盖的域名或 IP，不是本机监听地址。自动证书无需自备域名。\n修改 SNI 不会重签已有证书；新名称需由当前证书覆盖，必要时重新生成或导入。`, [
      "完成，返回节点摘要", "修改证书名称（TLS SNI）", "导入 PEM 证书与私钥", "生成新的自签证书", "客户端证书校验", "修改 ALPN",
    ]);
    if (selected === 0) return;
    if (selected === 1) node.tls.serverName = await uiValidatedInput("TLS 证书名称（SNI）", node.tls.serverName, value => {
      const result = normalizeConnectAddress(value); if (!result) throw new Error("请填写证书覆盖的域名或 IP。"); return result;
    });
    if (selected === 2) {
      const certificatePem = panelReadPem(await promptInput("PEM 证书文件路径"));
      const keyPem = panelReadPem(await promptInput("PEM 私钥文件路径"));
      validateNode({ ...node, tls: { ...node.tls, certificatePem, keyPem } }, { allowIncomplete: true });
      Object.assign(node.tls, { certificatePem, keyPem, insecure: false });
    }
    if (selected === 3) {
      console.log("正在生成此节点的自签证书……");
      Object.assign(node.tls, await service.certificate(paths, node), { insecure: true });
    }
    if (selected === 4) {
      const localTrust = node.protocol === "vless" ? "固定证书 SHA-256 指纹（自签）" : node.protocol === "naive" ? "将证书加入客户端信任配置（自签）" : "跳过 CA 校验（自签）";
      node.tls.insecure = (await selectMenu("客户端证书校验", "受信任证书使用系统 CA；自签证书使用对应的客户端信任方式。更换证书后需重新导出配置。", ["使用系统受信任的 CA 校验证书", localTrust], node.tls.insecure ? 1 : 0)) === 1;
    }
    if (selected === 5) await panelAlpn(node);
  }
}

/** 修改连接草稿：本机端口默认带动对外端口，已有 NAT 映射保留；仅隧道不问直连地址。 */
async function panelConnection(node: NodeConfig): Promise<void> {
  for (;;) {
    const items = ["back", ...(node.direct ? ["address"] : []), "port", ...(node.direct ? ["nat"] : []), "listen"];
    const labels: Record<string, string> = { back: "完成，返回节点摘要", address: "客户端连接地址", port: "本机监听端口", nat: "独立设置对外端口（NAT）", listen: "监听 IP / 网卡范围" };
    const selected = items[await selectMenu("连接设置", `本机监听：${node.listen}:${node.port}\n${node.direct ? `客户端连接：${node.address || "未填写"}:${node.publicPort}` : "仅隧道接入，无需直连地址"}\n通常只改本机端口，对外端口自动跟随；已有独立映射不会被覆盖。`, items.map(item => labels[item]!))];
    if (selected === "back") return;
    if (selected === "address") node.address = await uiValidatedInput("客户端连接的公网 / 局域网 IP 或域名（可留空）", node.address, value => value ? normalizeClientAddress(value) : "", { clearable: true });
    if (selected === "port") {
      const previous = node.port;
      node.port = await panelInteger("本地监听端口", previous);
      if (node.publicPort === previous) node.publicPort = node.port;
    }
    if (selected === "nat") node.publicPort = await panelInteger("客户端连接端口（NAT 映射）", node.publicPort);
    if (selected === "listen") node.listen = await uiValidatedInput("监听 IP（0.0.0.0 全部 IPv4；:: 全部 IPv6；仅隧道使用回环）", node.listen, value => {
      const host = normalizeConnectAddress(value);
      if (!panelNet.isIP(host)) throw new Error("监听范围必须是本机 IP，不能使用域名。");
      if (!node.direct && !["127.0.0.1", "::1"].includes(host)) throw new Error("仅隧道节点须监听 127.0.0.1 或 ::1。");
      return host;
    });
  }
}

/** 编辑传输和隧道草稿；保留凭据，切换接入方式时同步回环/对外监听。取消由上层丢弃本组副本。 */
async function panelTransport(node: NodeConfig): Promise<void> {
  const protocol = node.protocol, previousDirect = node.direct;
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
    node.direct = (await selectMenu("节点接入方式", "仅隧道将监听本机回环地址；同时直连会开放所选监听地址。\n此组合的本机 WS 不附加 TLS，隧道客户端由 Cloudflare 提供 TLS。\nVLESS 从 TLS / REALITY 切换并保留直连时，保存会自动准备 ENC，需重新导入客户端配置。", ["仅通过隧道接入", "保留直连接入，同时开启隧道"], previousDirect ? 1 : 0)) === 1;
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

  if (!previousDirect && node.direct) node.listen = node.listen === "::1" ? "::" : "0.0.0.0";
  if (node.tunnel.mode !== "none") { node.tls.mode = "none"; node.flow = ""; }
  else if (node.transport.type === "ws" && node.tls.mode === "reality") { node.tls.mode = "tls"; node.flow = ""; }
}

/** 只显示当前协议专属参数；node 为分组草稿，service 提供可替换的 ENC 生成器。 */
async function panelProtocolOptions(paths: AppPaths, node: NodeConfig, service: PanelEditorServices): Promise<void> {
  const protocol = node.protocol;
  if (protocol === "shadowsocks") {
    const method = await panelEnum("Shadowsocks 加密方法", "SS2022 需要对应长度的 Base64 密钥；更换算法后会生成匹配的新密码。", SHADOWSOCKS_METHODS, node.method as typeof SHADOWSOCKS_METHODS[number]);
    if (method !== node.method) node.password = generateShadowsocksPassword(method);
    node.method = method;
  }
  if (protocol === "vmess") node.vmessSecurity = await panelEnum("VMess 客户端加密方式", "AEAD 节点，alterId 固定为 0。", ["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"] as const, node.vmessSecurity);
  if (protocol === "vless") {
    const hasEncryption = node.vlessEncryption !== "none";
    const encryptionItems = [...(hasEncryption ? ["keep"] : []), "none", "generate", "manual"];
    const encryptionLabels: Record<string, string> = { keep: "保留当前 ENC", none: "不使用额外 VLESS ENC", generate: "生成新的 ML-KEM-768 ENC 参数", manual: "手动输入成对 ENC 参数" };
    const encryption = encryptionItems[await selectMenu("VLESS Encryption", "按客户端支持情况选择；ENC 会生成并保存配对的服务端解密参数和客户端加密参数。", encryptionItems.map(item => encryptionLabels[item]!))];
    if (encryption === "none") { node.vlessEncryption = "none"; node.vlessDecryption = "none"; }
    if (encryption === "generate") {
      console.log("正在使用官方 Xray 生成 ENC 参数……");
      const pair = await service.encryption(paths);
      node.vlessEncryption = pair.vlessEncryption; node.vlessDecryption = pair.vlessDecryption;
    }
    if (encryption === "manual") {
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
}

/**
 * 按分组编辑节点草稿；paths 是隔离或正式路径，existing 是已有节点或未保存草稿。
 * overrides 只替换证书/ENC 生成器。返回 Promise<void>；仅选择保存时写入磁盘。
 * 每组使用副本，Esc 丢弃本组修改；保存前检查并发变更，保留其他节点。
 */
export async function configureNode(paths: AppPaths, existing?: NodeConfig, overrides: Partial<PanelEditorServices> = {}): Promise<void> {
  const service = { certificate: generateSelfSignedCertificate, encryption: generateVlessEncryption, ...overrides };
  const initial = readConfig(paths), original = existing ? initial.nodes.find(item => item.id === existing.id) : undefined;
  let config = structuredClone(initial), notice = "", prepareEncryption = false;
  const protocol = existing?.protocol ?? await panelEnum("选择节点协议 · 高级模式", "选好协议后只修改需要的分组；默认值已自动准备。", NODE_PROTOCOLS, "vless", NODE_PROTOCOLS.map(item => panelProtocolLabels[item]));
  let node = existing ? structuredClone(existing) : createSimpleNode(protocol, config.nodes);
  for (;;) {
    const secure = !["shadowsocks", "socks"].includes(node.protocol) && node.tunnel.mode === "none";
    const items = ["save", ...(secure ? ["security"] : []), ...(["vless", "vmess", "trojan"].includes(node.protocol) ? ["transport"] : []),
      "address", "auth", ...(["vless", "vmess", "shadowsocks", "hysteria2", "tuic"].includes(node.protocol) ? ["options"] : []), "status", "protocol", "cancel"];
    const labels: Record<string, string> = { save: "保存节点（稍后启动 / 重启应用）", security: ["vless", "anytls"].includes(node.protocol) ? "安全设置（TLS / REALITY / SNI）" : "安全设置（TLS / 证书 / SNI）", transport: "传输与隧道",
      address: "连接地址与端口", auth: nodeAuthenticationLabel(node), options: "协议专属选项", status: "出口与启停", protocol: "更换节点协议", cancel: "取消，不保存" };
    const summary: string = [node.name, panelEndpoint(node), node.direct ? `客户端连接：${node.address || "未填写（暂不导出直连链接）"}:${node.publicPort}` : "仅隧道接入，无需填写 VPS IP",
      node.tls.mode === "reality" ? panelRealitySummary(node) : `安全层：${node.tls.mode}${node.tls.mode === "tls" ? `；证书名称：${node.tls.serverName}` : ""}`,
      node.tunnel.mode === "fixed" ? `Cloudflare 映射：${node.tunnel.domain} → ${panelTunnelOrigin(node)}` : "",
      prepareEncryption ? "直连加密：保存时自动准备 VLESS ENC，客户端需要重新导入。" : node.protocol === "vless" && node.tls.mode === "none" ? `直连加密：${node.vlessEncryption === "none" ? "无附加 TLS / ENC" : "VLESS ENC"}` : "",
      "只编辑需要的分组。菜单内 Esc 撤销本组；文本输入时 Ctrl+C 退出面板。保存前不改变已有节点。", notice].filter(Boolean).join("\n");
    const selected = items[await selectMenu("节点摘要 · 高级模式", summary, items.map(item => labels[item]!))]!;
    if (selected === "cancel") throw new UserCancelledError();
    try {
      if (selected === "save") {
        const ready = structuredClone(node);
        if (prepareEncryption) {
          console.log("正在为 VLESS 直连自动准备 ENC 加密参数……");
          Object.assign(ready, await service.encryption(paths));
        }
        if (ready.enabled && ready.tls.mode === "tls" && (!ready.tls.certificatePem || !ready.tls.keyPem)) {
          if (original?.protocol === ready.protocol || ready.tls.certificatePem || ready.tls.keyPem) throw new Error("已有节点的证书 / 私钥不完整，请在安全设置中导入或明确生成；不会自动覆盖已有材料。");
          console.log("正在自动生成此节点的 TLS 证书……");
          Object.assign(ready.tls, await service.certificate(paths, ready), { insecure: true });
        }
        const latest = readConfig(paths), current = latest.nodes.find(item => item.id === ready.id);
        if (JSON.stringify(current) !== JSON.stringify(original)) throw new Error("这个节点已在另一处修改或删除，请取消后重新打开，避免覆盖新设置。");
        const changedWarp = JSON.stringify(config.warp) !== JSON.stringify(initial.warp);
        if (changedWarp && JSON.stringify(latest.warp) !== JSON.stringify(initial.warp)) throw new Error("共享 WARP 配置已在另一处修改，请取消后重新打开。");
        const validated = validateNode(ready, { allowExpiredCertificate: true });
        const nodes = current ? latest.nodes.map(item => item.id === ready.id ? validated : item) : [...latest.nodes, validated];
        writeConfig(paths, validateConfig({ ...latest, ...(changedWarp ? { warp: config.warp } : {}), nodes }, { allowExpiredCertificate: true }));
        console.log("节点已保存。选择“启动 / 重启全部节点”应用配置。");
        return;
      }
      let draft = structuredClone(node);
      let nextConfig = structuredClone(config);
      if (selected === "security") await panelSecurity(paths, draft, service);
      if (selected === "transport") await panelTransport(draft);
      if (selected === "address") await panelConnection(draft);
      if (selected === "auth") await editNodeAuthentication(draft);
      if (selected === "options") await panelProtocolOptions(paths, draft, service);
      if (selected === "status") {
        draft.egress = await panelEnum("此节点的出口", "仅影响这个节点；其他节点可以使用不同出口。", ["direct", "warp"] as const, draft.egress, ["本机 Direct", "WARP WireGuard"]);
        if (draft.egress === "warp" && !nextConfig.warp) nextConfig = await panelWarp(nextConfig);
        draft.enabled = (await selectMenu("保存后的节点状态", "保存不重启后台；下次应用时生效。", ["启用此节点", "保存为停用节点"], draft.enabled ? 0 : 1)) === 0;
      }
      if (selected === "protocol") {
        const changed = await panelEnum("更换节点协议", "选择相同协议保留参数；切换协议会重置协议参数与凭据，保存后需要重新导入客户端配置。", NODE_PROTOCOLS, draft.protocol, NODE_PROTOCOLS.map(item => panelProtocolLabels[item]));
        if (changed !== draft.protocol) {
          if (await selectMenu("确认更换协议", `${panelProtocolLabels[draft.protocol]} → ${panelProtocolLabels[changed]}，将生成新的协议凭据。原节点在保存前保持不变。`, ["返回，保留当前协议", "更换协议并重新配置"]) !== 1) continue;
          draft = { ...createSimpleNode(changed, config.nodes.filter(item => item.id !== node.id)), id: node.id, name: node.name, enabled: node.enabled };
        }
      }
      // 改传输/安全层后，Vision 仅在组合不再支持时关闭，不重置其他无关字段。
      if (draft.flow && draft.vlessEncryption === "none" && (draft.transport.type !== "tcp" || draft.tls.mode === "none")) draft.flow = "";
      // TLS / REALITY 改为 WS 隧道或由仅隧道恢复直连时，延后准备 ENC，避免降级为明文直连。
      const lostProtection: boolean = selected === "transport" && (node.tls.mode !== "none" || !node.direct);
      prepareEncryption = (prepareEncryption || lostProtection) && draft.protocol === "vless" && draft.direct && draft.tls.mode === "none" && draft.vlessEncryption === "none";
      if (selected === "protocol" && draft.protocol !== node.protocol) prepareEncryption = false;
      if (selected === "transport" && draft.protocol === "vmess" && draft.direct && draft.tunnel.mode !== "none" && ["none", "zero"].includes(draft.vmessSecurity) && (node.tls.mode !== "none" || !node.direct)) draft.vmessSecurity = "auto";
      node = draft; config = nextConfig; notice = "草稿已更新；选择保存节点后写入。";
    } catch (error) {
      if (error instanceof UiExitRequestedError) throw error;
      notice = error instanceof UserCancelledError ? "已撤销当前分组的修改，其余草稿保留。" : `操作未完成：${errorMessage(error)}`;
    }
  }
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
    const choice = await selectMenu("节点管理", `已创建 ${config.nodes.length} / 32 个节点。默认使用简易模式，选协议后即可保存。`, ["新增节点（简易模式）", "编辑节点（简易模式）", "高级配置（按需编辑）", "启用 / 停用节点", "复制节点", "删除节点", "返回"]);
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
  if (status.firewall) {
    console.log(`\n后台防火墙检查（${status.firewall.backend} / ${status.firewall.status}）：${status.firewall.detail}`);
    for (const warning of status.firewall.warnings) console.log(`防火墙提示：${warning}`);
  }
  console.log("\n就绪检查确认本机监听及所选隧道连接。云安全组、路由器 NAT、第三方安全软件和客户端实际访问仍需现场验证。");
  console.log("关闭面板后后台继续运行；部分节点未就绪时，其他已就绪节点可以继续使用。");
}

async function panelStop(paths: AppPaths, startup: StartupStatus): Promise<void> {
  if (startup.mode !== "none") await stopManaged(paths); else await stopDaemonGracefully(paths);
}

export interface PanelRuntimeOperations {
  getStatus: typeof getDaemonStatus;
  prepare: typeof prepareRuntime;
  syncFirewall: typeof syncFirewallInteractive;
  getStartup: typeof getStartupStatus;
  stop: typeof panelStop;
  start: (paths: AppPaths, startup: StartupStatus) => Promise<void>;
  readiness: typeof panelReadiness;
  save: typeof writeConfig;
}

const panelRuntimeDefaults: PanelRuntimeOperations = {
  getStatus: getDaemonStatus, prepare: prepareRuntime, syncFirewall: syncFirewallInteractive,
  getStartup: getStartupStatus, stop: panelStop, readiness: panelReadiness, save: writeConfig,
  start: async (paths, startup) => { if (startup.mode !== "none") await startManaged(paths); else await startDetachedDaemon(paths); },
};

/** Preflight and UAC run before the saved configuration or existing worker changes. */
export async function panelApplyConfiguration(paths: AppPaths, input: AppConfig, options: { forceRestart?: boolean } = {}, overrides: Partial<PanelRuntimeOperations> = {}): Promise<void> {
  const operations = { ...panelRuntimeDefaults, ...overrides };
  const candidate = validateConfig(input, { allowExpiredCertificate: true });
  const previous = readConfig(paths), expected = configFingerprint(previous);
  const current = await operations.getStatus(paths);
  const unchanged = !options.forceRestart && panelRuntimeMatches(current, candidate, paths);
  if (!unchanged && candidate.nodes.some(node => node.enabled)) await operations.prepare(paths, candidate);
  const firewall = await operations.syncFirewall(paths, candidate, { expectedConfigHash: expected, report: printFirewallResult });
  requireFirewallApply(firewall);
  if (configFingerprint(readConfig(paths)) !== expected) throw new Error("配置在准备过程中被修改，未覆盖新配置或停止原后台。请重新打开节点后应用。");
  try { operations.save(paths, candidate); }
  catch (error) {
    if (firewall?.changed) {
      try {
        const restored = await operations.syncFirewall(paths, previous, { force: true, expectedConfigHash: expected, report: printFirewallResult });
        if (restored && !["synced", "inactive"].includes(restored.status)) console.log("旧端口规则未完全恢复，请从防火墙菜单重新同步。");
      } catch (restoreError) { console.log(`旧端口规则恢复未完成：${errorMessage(restoreError)}`); }
    }
    throw error;
  }
  if (unchanged) {
    console.log("配置已保存。服务端参数保持一致，后台继续运行；链接地址会自动刷新。");
    return;
  }
  try {
    const startup = await operations.getStartup(paths);
    await operations.stop(paths, startup);
    if (!candidate.nodes.some(node => node.enabled)) { console.log("已保存停用状态，并停止后台节点。"); return; }
    await operations.start(paths, startup);
    await operations.readiness(paths);
  } catch (error) {
    console.log(`配置已保存，但后台应用未完成：${errorMessage(error)}\n处理后可从主菜单选择“启动 / 重启全部节点”重试。`);
  }
}

/** Explicit stop removes owned rules after the worker stops; restart/update use panelStop directly. */
export async function panelStopAll(paths: AppPaths, startup: StartupStatus, overrides: Partial<PanelRuntimeOperations> = {}): Promise<void> {
  const operations = { ...panelRuntimeDefaults, ...overrides }, config = readConfig(paths);
  await operations.stop(paths, startup);
  console.log("后台及各节点核心已停止，自动启动设置保持不变。");
  if (getFirewallSettings(config).mode === "auto") {
    try { await operations.syncFirewall(paths, config, { remove: true, expectedConfigHash: configFingerprint(config), report: printFirewallResult }); }
    catch (error) { console.log(`后台已停止；防火墙规则清理未完成：${errorMessage(error)}\n可从防火墙菜单重新清理。`); }
  }
}

async function panelStartup(paths: AppPaths, current: StartupStatus): Promise<boolean> {
  if (current.enabled) { await disableStartup(paths); console.log("自动启动已关闭，当前后台继续运行。需要停止时请选择停止全部节点。"); return false; }
  await prepareRuntime(paths);
  if (isSystemInstallation(paths)) {
    requireFirewallApply(await syncFirewallInteractive(paths, readConfig(paths), { report: printFirewallResult }));
    await enableStartup(paths, "system"); await startManaged(paths); await panelReadiness(paths); return false;
  }
  const mode = process.platform === "win32" ? await selectMenu("自动启动模式", "系统模式会安装到受保护目录，需要时请求 UAC。用户模式只在该用户登录后运行。", ["系统开机启动（SYSTEM，无需登录）", "当前用户登录后启动", "取消"]) : await selectMenu("启用系统自启", "需要 systemd，程序将安装到 /opt/nexus-edge；必要时请求 sudo。", ["启用系统自启", "取消"]);
  if ((process.platform === "win32" && mode === 2) || (process.platform !== "win32" && mode === 1)) return false;
  if (mode === 1 && process.platform === "win32") {
    requireFirewallApply(await syncFirewallInteractive(paths, readConfig(paths), { report: printFirewallResult }));
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

/**
 * 编辑核心出站 IPv6 策略，参数 paths 为当前安装路径，无返回值。
 * 保存前核对配置指纹；立即应用复用核心预检流程，失败时保留旧配置和后台。
 */
async function panelCoreIpv6Settings(paths: AppPaths): Promise<void> {
  const config = readConfig(paths), expected = configFingerprint(config);
  const enabled = isCoreIpv6Enabled(config);
  const choice = await selectMenu("核心出站 IPv6", `当前：${enabled ? "已开启（双栈）" : "已禁用（仅 IPv4，默认）"}。\n控制 sing-box / Xray 的 DNS、直连与 WARP 出站，以及 cloudflared 边缘连接。\n已有节点监听地址保持原值；本机网卡 IPv6 在独立菜单设置。`, ["禁用 IPv6（仅 IPv4）", "开启 IPv6（双栈）", "返回"], enabled ? 1 : 0);
  if (choice === 2 || (choice === 1) === enabled) return;
  const action = await selectMenu("应用核心 IPv6 设置", "立即应用会先检查核心配置，再重启节点；仅保存则在下次启动 / 重启时生效。", ["保存并应用", "仅保存，稍后重启", "取消"]);
  if (action === 2) return;
  if (configFingerprint(readConfig(paths)) !== expected) throw new Error("配置已在另一处修改，请重新打开核心 IPv6 设置。");
  const candidate = { ...config, coreIpv6: choice === 1 };
  if (action === 0 && candidate.nodes.some(node => node.enabled)) await panelApplyConfiguration(paths, candidate);
  else {
    writeConfig(paths, candidate);
    console.log("核心 IPv6 设置已保存，下次启动 / 重启节点时生效。");
  }
}

/** 网络设置子菜单；paths 指向当前安装，无返回值，系统接口操作独立于核心策略。 */
async function panelNetworkSettings(paths: AppPaths): Promise<void> {
  for (;;) {
    const choice = await selectMenu("IPv6 / 防火墙设置", `核心出站 IPv6：${isCoreIpv6Enabled(readConfig(paths)) ? "已开启" : "已禁用（默认）"}`, ["核心出站 IPv6（开启 / 禁用）", "本机 IPv6 网络接口（开启 / 禁用）", "防火墙 / 端口放行", "返回"]);
    if (choice === 3) return;
    if (choice === 0) { await panelCoreIpv6Settings(paths); await uiPause(); }
    else if (choice === 1) await runHostIpv6Panel(paths);
    else await runFirewallPanel(paths);
  }
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
      firewallPanelSummary(paths, config),
      `核心出站 IPv6：${isCoreIpv6Enabled(config) ? "已开启" : "已禁用（默认）"}`,
      ...(dirty ? ["已保存的配置或内核版本尚未应用。重启全部节点后生效。"] : []),
      ...(!config.nodes.length ? ["节点管理 → 新增节点：选协议 → 保存并应用。隧道默认关闭。"] : []),
    ].join("\n");
    const choice = await selectMenu(`NexusEdge ${APP_VERSION} 节点管理`, information, ["启动 / 重启全部节点", "停止全部节点", "节点管理（新增 / 编辑 / 启停 / 删除）", "查看链接 / 导出客户端配置", "WARP 与通知设置", "查看运行日志", startup.enabled ? "关闭自动启动" : "开启自动启动", "内核管理 / 更新", "IPv6 / 防火墙设置", "退出面板（保留后台）"]);
    if (choice === 9) return "exit";
    try {
      if (choice === 0) {
        if (!enabled.length) throw new Error("没有启用的节点。请先进入节点管理添加或启用节点。");
        await panelApplyConfiguration(paths, config, { forceRestart: true });
      }
      else if (choice === 1) await panelStopAll(paths, startup);
      else if (choice === 2) { await panelManageNodes(paths); continue; }
      else if (choice === 3) { await panelExport(paths); continue; }
      else if (choice === 4) await panelSharedSettings(paths);
      else if (choice === 5) console.log(tailLog(paths));
      else if (choice === 6 && await panelStartup(paths, startup)) return "handoff";
      else if (choice === 7) { await runCorePanel(paths); continue; }
      else if (choice === 8) { await panelNetworkSettings(paths); continue; }
    } catch (e) {
      if (e instanceof UiExitRequestedError) throw e;
      if (e instanceof UserCancelledError) continue;
      console.log(`\n${errorMessage(e)}`);
    }
    await uiPause();
  }
}
