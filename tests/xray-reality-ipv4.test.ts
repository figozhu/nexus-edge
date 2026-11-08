import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createDefaultNode, createPaths, defaultConfig, generateRealityKeyPair, type AppConfig } from "../src/core.ts";
import { buildRuntimeXrayConfig, buildXrayConfig, preflightCores, type NetworkIpv4Lookup } from "../src/network.ts";

/** 创建一个有效的 REALITY 测试节点；protocol 指定核心，host 指定目标，不进行网络操作。 */
function realityConfig(protocol: "vless" | "anytls" = "vless", host = "dual-stack.test"): AppConfig {
  const node = createDefaultNode(protocol);
  node.tls.mode = "reality"; node.tls.serverName = "sni.test";
  node.tls.reality = { ...generateRealityKeyPair(), shortId: "12ab", handshakeServer: host, handshakePort: 443 };
  return { ...defaultConfig(), nodes: [node] };
}

/** 读取生成对象内第一个 REALITY 配置，仅用于测试断言，不修改对象。 */
function realitySettings(config: object | null): { target: string; serverNames: string[] } {
  return (config as any).inbounds[0].streamSettings.realitySettings;
}

describe("Xray REALITY IPv4 运行目标", () => {
  test("默认及显式关闭只查询IPv4，替换运行目标但保留保存域名、端口和SNI", async () => {
    for (const enabled of [undefined, false]) {
      const config = realityConfig(); if (enabled !== undefined) config.coreIpv6 = enabled;
      const before = structuredClone(config), calls: unknown[] = [];
      const lookup: NetworkIpv4Lookup = async (host, options) => { calls.push([host, options]); return { address: "192.0.2.7", family: 4 }; };
      const generated = await buildRuntimeXrayConfig(config, { lookup });
      expect(calls).toEqual([["dual-stack.test", { family: 4 }]]);
      expect(realitySettings(generated).target).toBe("192.0.2.7:443");
      expect(realitySettings(generated).serverNames).toEqual(["sni.test"]);
      expect(config).toEqual(before);
      expect(realitySettings(buildXrayConfig(config)).target).toBe("dual-stack.test:443");
      expect((generated as any).inbounds[0].streamSettings.sockopt).toBeUndefined();
    }
  });

  test("启用双栈保留域名且不查询，IPv4字面量直接保留", async () => {
    const lookup: NetworkIpv4Lookup = async () => { throw new Error("不应该查询DNS"); };
    const config = realityConfig(); config.coreIpv6 = true;
    expect(realitySettings(await buildRuntimeXrayConfig(config, { lookup })).target).toBe("dual-stack.test:443");
    expect(realitySettings(await buildRuntimeXrayConfig(realityConfig("vless", "127.0.0.1"), { lookup })).target).toBe("127.0.0.1:443");
  });

  test("停用节点、sing-box节点及无REALITY的Xray不查询", async () => {
    const lookup: NetworkIpv4Lookup = async () => { throw new Error("不应该查询DNS"); };
    const disabled = realityConfig(); disabled.nodes[0]!.enabled = false;
    expect(await buildRuntimeXrayConfig(disabled, { lookup })).toBeNull();
    expect(await buildRuntimeXrayConfig(realityConfig("anytls"), { lookup })).toBeNull();
    const plain = { ...defaultConfig(), nodes: [createDefaultNode("vless")] };
    expect(await buildRuntimeXrayConfig(plain, { lookup })).toEqual(buildXrayConfig(plain));
  });

  test("多个启用节点共享域名时只查询一次，不修改同域名的停用或sing-box节点", async () => {
    const config = realityConfig(), first = config.nodes[0]!;
    const second = { ...structuredClone(first), id: "second", port: first.port + 1 };
    const disabled = { ...structuredClone(first), id: "disabled", enabled: false, port: first.port + 2 };
    const sing = realityConfig("anytls").nodes[0]!; sing.port = first.port + 3;
    config.nodes.push(second, disabled, sing);
    const before = structuredClone(config); let calls = 0;
    const generated = await buildRuntimeXrayConfig(config, { lookup: async () => { calls++; return { address: "192.0.2.8", family: 4 }; } });
    expect(calls).toBe(1); expect(config).toEqual(before);
    expect((generated as any).inbounds.map((inbound: any) => inbound.streamSettings.realitySettings.target)).toEqual(["192.0.2.8:443", "192.0.2.8:443"]);
  });

  test("无A记录、异常、错误地址族或超时都明确失败，不退回IPv6", async () => {
    const config = realityConfig();
    await expect(buildRuntimeXrayConfig(config, { lookup: async () => { throw new Error("ENOTFOUND"); } })).rejects.toThrow("无法解析为 IPv4");
    for (const answer of [{ address: "::1", family: 6 }, { address: "192.0.2.7", family: 6 }, { address: "not-an-ip", family: 4 }]) {
      await expect(buildRuntimeXrayConfig(config, { lookup: async () => answer })).rejects.toThrow("未返回 IPv4");
    }
    await expect(buildRuntimeXrayConfig(config, { lookup: async () => new Promise(() => {}), timeoutMs: 10 })).rejects.toThrow("解析超时");
    expect(config.nodes[0]!.tls.reality.handshakeServer).toBe("dual-stack.test");
  });

  test("生产预检先解析再接触安装和候选文件，解析失败完整保留旧配置文件", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-reality-preflight-"));
    const paths = createPaths(path.join(root, "nexus-edge.ts")), config = realityConfig();
    fs.mkdirSync(paths.data); fs.writeFileSync(paths.config, JSON.stringify(config));
    fs.writeFileSync(paths.xrayConfig, "old-xray-runtime\n"); fs.writeFileSync(paths.singConfig, "old-sing-runtime\n");
    fs.writeFileSync(paths.runtimeState, "old-worker-state\n");
    const before = fs.readdirSync(paths.data).sort().map(name => [name, fs.readFileSync(path.join(paths.data, name), "utf8")]);
    const originalFetch = globalThis.fetch; let fetchCalls = 0;
    globalThis.fetch = (async () => { fetchCalls++; throw new Error("此测试禁止下载"); }) as unknown as typeof fetch;
    try {
      await expect(preflightCores(paths, config, { realityDns: { lookup: async () => { throw new Error("无 A 记录"); } } })).rejects.toThrow("REALITY 目标 dual-stack.test 无法解析为 IPv4");
      expect(fetchCalls).toBe(0);
      expect(fs.readdirSync(paths.data).sort().map(name => [name, fs.readFileSync(path.join(paths.data, name), "utf8")])).toEqual(before);
      expect(fs.existsSync(paths.bin)).toBe(false);
    } finally { globalThis.fetch = originalFetch; fs.rmSync(root, { recursive: true, force: true }); }
  });
});
