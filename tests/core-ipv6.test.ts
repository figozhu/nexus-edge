import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import { createDefaultNode, createPaths, defaultConfig, isCoreIpv6Enabled, runtimeConfigFingerprint, validateConfig, type AppConfig } from "../src/core.ts";
import { buildCloudflaredArgs, buildSingBoxConfig, buildXrayConfig } from "../src/network.ts";

/** 构造隔离的双核心配置，参数 warp 选择是否使用测试 WARP 凭据；不写文件或建立连接。 */
function ipv6Config(warp = false): AppConfig {
  const config = defaultConfig();
  config.nodes.push(createDefaultNode("vless"));
  config.nodes.push(createDefaultNode("vmess", config.nodes));
  if (warp) {
    config.warp = { privateKey: Buffer.alloc(32, 7).toString("base64"), peerPublicKey: Buffer.alloc(32, 9).toString("base64"), addresses: ["172.16.0.2/32", "2606:4700:110::2/128"], endpointHost: "engage.cloudflareclient.com", endpointPort: 2408, reserved: [1, 2, 3] };
    for (const node of config.nodes) node.egress = "warp";
  }
  return config;
}

describe("核心 IPv6 策略", () => {
  test("新配置和旧 schema-2 配置默认禁用，拒绝非布尔开关", () => {
    expect(isCoreIpv6Enabled(defaultConfig())).toBe(false);
    expect(isCoreIpv6Enabled(validateConfig(ipv6Config()))).toBe(false);
    for (const value of [null, "false", 0, {}, []]) expect(() => validateConfig({ ...ipv6Config(), coreIpv6: value })).toThrow("IPv6");
    expect(isCoreIpv6Enabled(validateConfig({ ...ipv6Config(), coreIpv6: true }))).toBe(true);
  });

  test("默认直连只解析IPv4并拦截客户端显式IPv6目标，开启后恢复双栈", () => {
    const config = ipv6Config();
    const sing = buildSingBoxConfig(config) as any, xray = buildXrayConfig(config) as any;
    expect(sing.route.default_domain_resolver).toEqual({ server: "dns-local", strategy: "ipv4_only" });
    expect(sing.route.rules[0]).toEqual({ ip_version: 6, action: "reject" });
    expect(xray.outbounds[0].settings.domainStrategy).toBe("ForceIPv4");
    expect(xray.dns.queryStrategy).toBe("UseIPv4");
    expect(xray.routing.rules[0]).toEqual({ type: "field", ip: ["::/0"], outboundTag: "block-ipv6" });
    expect(xray.outbounds.find((item: any) => item.tag === "block-ipv6").protocol).toBe("blackhole");
    config.coreIpv6 = true;
    expect((buildSingBoxConfig(config) as any).route).toEqual({ final: "direct", default_domain_resolver: "dns-local", rules: [] });
    expect((buildXrayConfig(config) as any).outbounds).toEqual([{ tag: "direct", protocol: "freedom", settings: { domainStrategy: "AsIs" } }]);
  });

  test("WARP IPv4策略覆盖地址、允许网段、对端解析及代理DNS，保留原始凭据", () => {
    const config = ipv6Config(true), before = structuredClone(config);
    const sing = buildSingBoxConfig(config) as any, xray = buildXrayConfig(config) as any;
    expect(sing.endpoints[0].address).toEqual(["172.16.0.2/32"]);
    expect(sing.endpoints[0].peers[0].allowed_ips).toEqual(["0.0.0.0/0"]);
    expect(sing.endpoints[0].domain_resolver.strategy).toBe("ipv4_only");
    expect(sing.route.rules[1].strategy).toBe("ipv4_only");
    expect(xray.outbounds[1].settings.address).toEqual(["172.16.0.2/32"]);
    expect(xray.outbounds[1].settings.peers[0].allowedIPs).toEqual(["0.0.0.0/0"]);
    expect(xray.outbounds[1].settings.domainStrategy).toBe("ForceIPv4");
    expect(xray.dns.queryStrategy).toBe("UseIPv4");
    expect(config).toEqual(before);
    config.coreIpv6 = true;
    expect((buildSingBoxConfig(config) as any).endpoints[0].address).toEqual(config.warp!.addresses);
    expect((buildXrayConfig(config) as any).outbounds[1].settings.peers[0].allowedIPs).toContain("::/0");
  });

  test("IPv6专用WARP对端/地址需显式开启，闲置配置不阻止直连", () => {
    for (const builder of [buildSingBoxConfig, buildXrayConfig]) {
      const config = ipv6Config(true);
      config.warp!.endpointHost = "2606:4700:d0::1";
      expect(() => builder(config)).toThrow("WARP 对端为 IPv6");
      config.coreIpv6 = true;
      expect(() => builder(config)).not.toThrow();
      config.coreIpv6 = false;
      config.warp!.endpointHost = "engage.cloudflareclient.com";
      config.warp!.addresses = ["2606:4700:110::2/128"];
      expect(() => builder(config)).toThrow("缺少 IPv4");
      for (const node of config.nodes) node.egress = "direct";
      expect(() => builder(config)).not.toThrow();
    }
  });

  test("cloudflared缺省使用IPv4边缘，开关可恢复auto，origin与凭据保持原值", () => {
    const config = ipv6Config(), node = config.nodes[1]!;
    node.transport.type = "ws"; node.tunnel.mode = "quick"; node.listen = "::1"; node.direct = false;
    const paths = createPaths("nexus-edge.ts");
    for (const enabled of [false, true]) {
      const args = buildCloudflaredArgs(node, paths, 2099, enabled);
      expect(args[args.indexOf("--edge-ip-version") + 1]).toBe(enabled ? "auto" : "4");
      expect(args[args.indexOf("--url") + 1]).toBe(`http://[::1]:${node.port}`);
    }
    const args = buildCloudflaredArgs(node, paths, 2099);
    expect(args[args.indexOf("--edge-ip-version") + 1]).toBe("4");
  });

  test("开关进入运行指纹且往返保留节点配置，已有IPv6入站不被重写", () => {
    const config = ipv6Config(), before = structuredClone(config.nodes);
    config.nodes[0]!.listen = "::";
    expect((buildXrayConfig(config) as any).inbounds[0].listen).toBe("::");
    const disabled = runtimeConfigFingerprint(config);
    const enabled = validateConfig({ ...config, coreIpv6: true });
    expect(runtimeConfigFingerprint(enabled)).not.toBe(disabled);
    expect(enabled.nodes[1]).toEqual(before[1]);
    expect(enabled.nodes).toEqual(config.nodes);
    expect(runtimeConfigFingerprint({ ...config, coreIpv6: false })).toBe(disabled);
    // 模拟 2.3.0 worker 的指纹算法；升级后必须提示尚未应用。
    const { firewall: _firewall, ...legacy } = validateConfig(config);
    const oldHash = crypto.createHash("sha256").update(JSON.stringify({ ...legacy, nodes: legacy.nodes.map(({ address: _address, publicPort: _port, ...node }) => node) })).digest("hex");
    expect(disabled).not.toBe(oldHash);
  });
});
