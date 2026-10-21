import { afterEach, describe, expect, test } from "bun:test";
import * as networkTestFs from "node:fs";
import * as networkTestOs from "node:os";
import * as networkTestPath from "node:path";
import * as networkTestCrypto from "node:crypto";
import { buildCloudflaredArgs, buildSingBoxConfig, buildXrayConfig, cloudflaredConfigPath, cloudflaredTokenPath, ensureBinaries, requiredBinaries, NETWORK_RELEASES, readCoreSelection, parseWarpProfile, preflightCores, generateSelfSignedCertificate, generateVlessEncryption, registerWarp } from "../src/network";
import { createPaths, createDefaultNode, defaultConfig, runCommand } from "../src/core";
import type { WarpProfile } from "../src/core";

const networkTestPrivateKey = Buffer.alloc(32, 7).toString("base64");
const networkTestPeerKey = Buffer.alloc(32, 9).toString("base64");
const networkTestProfile: WarpProfile = {
  privateKey: networkTestPrivateKey, peerPublicKey: networkTestPeerKey,
  addresses: ["172.16.0.2/32", "2606:4700:110:8123::2/128"],
  endpointHost: "engage.cloudflareclient.com", endpointPort: 2408, reserved: [1, 2, 255],
};
const networkTestConf = `[Interface]
PrivateKey = ${networkTestPrivateKey}
Address = 172.16.0.2/32, 2606:4700:110:8123::2/128
DNS = 1.1.1.1

[Peer]
PublicKey = ${networkTestPeerKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`;

function networkTestConfig(...protocols: ("vless" | "vmess" | "shadowsocks")[]) {
  const config = defaultConfig();
  for (const protocol of protocols) config.nodes.push(createDefaultNode(protocol, config.nodes));
  return config;
}

describe("independent multi-node engines and routing", () => {
  test("empty collection produces no engine config and needs no binaries", async () => {
    const config = defaultConfig();
    expect(buildSingBoxConfig(config)).toBeNull(); expect(buildXrayConfig(config)).toBeNull();
    expect(requiredBinaries(config)).toEqual([]);
    const paths = createPaths(networkTestPath.join(networkTestOs.tmpdir(), "unused-nexus-empty.ts"));
    await expect(preflightCores(paths, config)).rejects.toThrow("没有启用的节点");
  });
  test("VLESS defaults to direct TCP without sing-box/cloudflared", () => {
    const config = networkTestConfig("vless");
    expect(requiredBinaries(config)).toEqual(["xray"]);
    expect(buildSingBoxConfig(config)).toBeNull();
    const generated = buildXrayConfig(config) as any;
    expect(generated.inbounds[0].listen).toBe("0.0.0.0");
    expect(generated.inbounds[0].streamSettings.network).toBe("tcp");
    expect(generated.inbounds[0].settings.clients[0].id).toBe(config.nodes[0]!.uuid);
    expect(generated.outbounds[0].protocol).toBe("freedom");
  });
  test("all nodes keep distinct protocols, authentication and ports", () => {
    const config = networkTestConfig("vless", "vmess", "shadowsocks");
    const generated = buildSingBoxConfig(config) as any;
    expect(generated.inbounds.map((n: any) => n.type)).toEqual(["vmess", "shadowsocks"]);
    expect(generated.inbounds[0].users[0].uuid).toBe(config.nodes[1]!.uuid);
    expect(generated.inbounds[1].password).toBe(config.nodes[2]!.password);
    expect(generated.inbounds[1].method).toBe("2022-blake3-aes-128-gcm");
    expect(requiredBinaries(config)).toEqual(["singBox", "xray"]);
  });
  test("disabled incomplete TLS drafts do not select another core", () => {
    const config = networkTestConfig("vless");
    const draft = createDefaultNode("hysteria2"); draft.enabled = false;
    config.nodes.push(draft);
    expect(requiredBinaries(config)).toEqual(["xray"]);
    expect(buildSingBoxConfig(config)).toBeNull();
  });
  test("WARP selection is per-node, user-mode, and has separate target/peer DNS", () => {
    const config = networkTestConfig("vless", "vmess", "shadowsocks"); config.warp = networkTestProfile;
    config.nodes[0]!.egress = "warp"; config.nodes[1]!.egress = "warp";
    const sing = buildSingBoxConfig(config) as any, xray = buildXrayConfig(config) as any;
    expect(sing.endpoints[0].system).toBe(false);
    expect(sing.endpoints[0].peers[0].reserved).toEqual([1, 2, 255]);
    expect(sing.endpoints[0].domain_resolver).toBe("dns-local");
    expect(sing.route.final).toBe("direct");
    expect(sing.route.rules[0]).toEqual({ inbound: [`node:${config.nodes[1]!.id}`], action: "resolve", server: "dns-warp" });
    expect(sing.dns.servers.find((s: any) => s.tag === "dns-warp").detour).toBe("warp-out");
    expect(xray.outbounds[1].settings.noKernelTun).toBe(true);
    expect(xray.outbounds[1].settings.reserved).toEqual([1, 2, 255]);
    expect(xray.dns.servers[0]).toEqual({ address: "localhost", domains: ["full:engage.cloudflareclient.com"], skipFallback: true });
    expect(xray.dns.disableFallbackIfMatch).toBe(true);
    expect(xray.routing.rules[0].inboundTag).toEqual(["warp-dns"]);
    expect(xray.routing.rules[1].inboundTag).toEqual([`node:${config.nodes[0]!.id}`]);
    expect(JSON.stringify(xray)).not.toContain("remoteDNS");
  });
  test("missing WARP credentials are rejected rather than falling back", () => {
    const config = networkTestConfig("vmess"); config.nodes[0]!.egress = "warp";
    expect(() => buildSingBoxConfig(config)).toThrow("WARP");
  });
});

describe("optional per-node cloudflared invocation", () => {
  const paths = createPaths(networkTestPath.resolve("test folder/Nexus Edge.ts"));
  test("none is rejected; quick explicitly enables transport fallback and isolated config", () => {
    const node = createDefaultNode("vless"); node.transport.type = "ws";
    expect(() => buildCloudflaredArgs(node, paths, 2099)).toThrow("没有启用隧道");
    node.tunnel.mode = "quick";
    const args = buildCloudflaredArgs(node, paths, 2099);
    expect(args[args.indexOf("--protocol") + 1]).toBe("auto");
    expect(args[args.indexOf("--config") + 1]).toBe(cloudflaredConfigPath(paths, node.id));
    expect(args[args.indexOf("--url") + 1]).toBe(`http://127.0.0.1:${node.port}`);
    expect(args[args.indexOf("--metrics") + 1]).toBe("127.0.0.1:2099");
    expect(args).toContain("--no-autoupdate"); expect(args).not.toContain("run");
  });
  test("IPv6 tunnel-only origin uses bracketed loopback", () => {
    const node = createDefaultNode("vmess"); node.transport.type = "ws"; node.direct = false; node.listen = "::1"; node.tunnel.mode = "quick";
    const args = buildCloudflaredArgs(node, paths, 2099);
    expect(args[args.indexOf("--url") + 1]).toBe(`http://[::1]:${node.port}`);
  });
  test("fixed keeps token out of argv and isolated by node ID", () => {
    const node = createDefaultNode("vmess"); node.transport.type = "ws";
    node.tunnel = { ...node.tunnel, mode: "fixed", domain: "node.example.com", token: "dummyToken1234567890", protocol: "http2" };
    const args = buildCloudflaredArgs(node, paths, 2099);
    expect(args).toContain("run"); expect(args[args.indexOf("--token-file") + 1]).toBe(cloudflaredTokenPath(paths, node.id));
    expect(args.join(" ")).not.toContain(node.tunnel.token); expect(args).not.toContain("--url");
    expect(args[args.indexOf("--protocol") + 1]).toBe("http2");
    expect(cloudflaredTokenPath(paths, node.id)).not.toBe(cloudflaredTokenPath(paths, "another-node"));
    expect(() => cloudflaredTokenPath(paths, "../escape")).toThrow();
    expect(requiredBinaries({ ...defaultConfig(), nodes: [node] })).toEqual(["singBox", "cloudflared"]);
  });
});

describe("WireGuard/WARP imports", () => {
  test("standard profile plus Reserved roundtrips", () => {
    expect(parseWarpProfile(networkTestConf + "Reserved = 1, 2, 255\n")).toEqual(networkTestProfile);
  });
  test("IPv6 endpoint brackets and a non-default port are preserved", () => {
    const profile = parseWarpProfile(networkTestConf.replace("engage.cloudflareclient.com:2408", "[2606:4700:d0::a29f:c001]:4500") + "Reserved = [1,2,255]");
    expect(profile.endpointHost).toBe("2606:4700:d0::a29f:c001");
    expect(profile.endpointPort).toBe(4500);
  });
  test("plain wgcf supports its ordinary zero Reserved value", () => {
    expect(parseWarpProfile(networkTestConf).reserved).toEqual([0, 0, 0]);
  });
  test("trailing JSON carries either Reserved or client_id", () => {
    expect(parseWarpProfile(networkTestConf + '\n{"reserved":[1,2,255]}')).toEqual(networkTestProfile);
    expect(parseWarpProfile(networkTestConf + '\n{"config":{"client_id":"AQL/"}}')).toEqual(networkTestProfile);
  });
  test("NexusEdge JSON and current sing-box endpoint JSON are importable", () => {
    expect(parseWarpProfile(JSON.stringify(networkTestProfile))).toEqual(networkTestProfile);
    expect(parseWarpProfile(JSON.stringify({
      type: "wireguard", address: networkTestProfile.addresses, private_key: networkTestPrivateKey,
      peers: [{ address: networkTestProfile.endpointHost, port: 2408, public_key: networkTestPeerKey, reserved: [1, 2, 255] }],
    }))).toEqual(networkTestProfile);
  });
  test("raw registration export respects endpoint ports and adds only missing CIDRs", () => {
    const profile = parseWarpProfile(JSON.stringify({
      private_key: networkTestPrivateKey, tunnel_type: "wireguard", config: {
        client_id: "AQL/", interface: { addresses: { v4: "172.16.0.2", v6: "2606:4700:110:8123::2/128" } },
        peers: [{ public_key: networkTestPeerKey, endpoint: { v6: "2606:4700:d0::a29f:c001", ports: [500] } }],
      },
    }));
    expect(profile.addresses).toEqual(networkTestProfile.addresses);
    expect(profile.endpointHost).toBe("2606:4700:d0::a29f:c001");
    expect(profile.endpointPort).toBe(500);
    expect(profile.reserved).toEqual([1, 2, 255]);
    const v4Profile = parseWarpProfile(JSON.stringify({
      private_key: networkTestPrivateKey, config: {
        client_id: "AQL/", interface: { addresses: { v4: "172.16.0.2" } },
        peers: [{ public_key: networkTestPeerKey, endpoint: { v4: "162.159.192.1:2408", ports: [500] } }],
      },
    }));
    expect(v4Profile.endpointHost).toBe("162.159.192.1");
    expect(v4Profile.endpointPort).toBe(500);
  });
  test("malformed bytes, duplicate keys and extra peers are rejected", () => {
    expect(() => parseWarpProfile(networkTestConf + '\n{"client_id":"AQIDBA=="}')).toThrow("client_id");
    expect(() => parseWarpProfile(networkTestConf + "Reserved = 1,2,256")).toThrow("Reserved");
    expect(() => parseWarpProfile(networkTestConf + "Reserved = 1,,2")).toThrow("Reserved");
    expect(() => parseWarpProfile(networkTestConf + "[Peer]\n")).toThrow("单 peer");
    expect(() => parseWarpProfile(networkTestConf + "PublicKey = " + networkTestPeerKey)).toThrow("重复字段");
    expect(() => parseWarpProfile(networkTestConf.replace(":2408", ":invalid"))).toThrow("Endpoint");
  });
  test("profile hooks are data and are never executed", () => {
    const profile = parseWarpProfile(networkTestConf.replace("DNS = 1.1.1.1", "PostUp = $(this_must_never_run)\nDNS = 1.1.1.1"));
    expect(profile.privateKey).toBe(networkTestPrivateKey);
  });
});

describe("explicit WARP registration with a mocked service only", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => { globalThis.fetch = originalFetch; });
  test("registered public key matches the saved X25519 private key", async () => {
    let requestBody: any;
    globalThis.fetch = (async (input: any, init: any) => {
      expect(String(input)).toBe("https://api.cloudflareclient.com/v0a5641/reg");
      requestBody = JSON.parse(init.body);
      expect(init.method).toBe("POST");
      expect(requestBody.key_type).toBe("curve25519");
      expect(requestBody.tunnel_type).toBe("wireguard");
      return Response.json({ key: requestBody.key, tunnel_type: "wireguard", config: {
        client_id: "AQL/", interface: { addresses: { v4: "172.16.0.2", v6: "2606:4700:110:8123::2" } },
        peers: [{ public_key: networkTestPeerKey, endpoint: { host: "engage.cloudflareclient.com:4500" } }],
      } });
    }) as unknown as typeof fetch;
    const profile = await registerWarp();
    const key = networkTestCrypto.createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(profile.privateKey, "base64")]),
      format: "der", type: "pkcs8",
    });
    const derived = networkTestCrypto.createPublicKey(key).export({ format: "jwk" });
    expect(Buffer.from(derived.x!, "base64url").toString("base64")).toBe(requestBody.key);
    expect(profile.endpointPort).toBe(4500);
    expect(profile.reserved).toEqual([1, 2, 255]);
  });
  test("upstream failures do not expose token-bearing response bodies", async () => {
    globalThis.fetch = (async () => new Response('{"token":"must-not-be-logged"}', { status: 403 })) as unknown as typeof fetch;
    try { await registerWarp(); throw new Error("expected failure"); }
    catch (error) {
      expect(String(error)).toContain("403");
      expect(String(error)).not.toContain("must-not-be-logged");
    }
  });
  test("incomplete success responses never produce fabricated credentials", async () => {
    globalThis.fetch = (async () => Response.json({ config: {} })) as unknown as typeof fetch;
    await expect(registerWarp()).rejects.toThrow("未保存也未启用");
  });
});

test("release matrix has pinned archive and extracted-file hashes", () => {
  for (const release of Object.values(NETWORK_RELEASES)) {
    expect(Object.keys(release.assets).sort()).toEqual(["linux-arm64", "linux-x64", "win32-x64"]);
    expect(release.base).not.toContain("latest");
    for (const asset of Object.values(release.assets)) {
      expect(asset.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(asset.files[asset.executable]).toMatch(/^[a-f0-9]{64}$/);
    }
  }
});

test("untrusted downloads are rejected before installation and staging is removed", async () => {
  const dir = networkTestFs.mkdtempSync(networkTestPath.join(networkTestOs.tmpdir(), "nexus-bad-download-"));
  const paths = createPaths(networkTestPath.join(dir, "nexus-edge.ts"));
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = (async () => { requests++; return new Response("This is not an official core."); }) as unknown as typeof fetch;
  try {
    await expect(ensureBinaries(paths, networkTestConfig("vless", "vmess"))).rejects.toThrow("SHA-256");
    expect(requests).toBe(2);
    expect(networkTestFs.readdirSync(paths.bin)).toEqual(["core-versions.json"]);
  } finally {
    globalThis.fetch = originalFetch;
    networkTestFs.rmSync(dir, { recursive: true, force: true });
  }
});

const networkTestCorePath = process.env.NEXUS_EDGE_SINGBOX_TEST_BINARY;
const networkTestXray = process.env.NEXUS_EDGE_XRAY_TEST_BINARY;
(networkTestCorePath && networkTestXray ? test : test.skip)("real pinned cores check Direct and per-node WARP without starting services", async () => {
  const dir = networkTestFs.mkdtempSync(networkTestPath.join(networkTestOs.tmpdir(), "nexus-network-test-"));
  try {
    for (const useWarp of [false, true]) {
      const config = networkTestConfig("vless", "vmess", "shadowsocks");
      if (useWarp) { config.warp = networkTestProfile; config.nodes[0]!.egress = "warp"; config.nodes[1]!.egress = "warp"; }
      for (const [binary, generated, args] of [
        [networkTestCorePath!, buildSingBoxConfig(config), ["check", "-c"]], [networkTestXray!, buildXrayConfig(config), ["run", "-test", "-config"]],
      ] as const) {
        const file = networkTestPath.join(dir, "candidate.json"); networkTestFs.writeFileSync(file, JSON.stringify(generated), { mode: 0o600 });
        const result = await runCommand(binary, [...args, file], { timeoutMs: 15_000, cwd: networkTestPath.dirname(binary) });
        expect(result.stderr || result.stdout).not.toContain("FATAL"); expect(result.code).toBe(0);
      }
    }
  } finally { networkTestFs.rmSync(dir, { recursive: true, force: true }); }
});

const networkTestArchive = process.env.NEXUS_EDGE_TEST_SINGBOX_ARCHIVE;
const networkTestXrayArchive = process.env.NEXUS_EDGE_TEST_XRAY_ARCHIVE;
const networkTestCloudflared = process.env.NEXUS_EDGE_TEST_CLOUDFLARED_BINARY;
const networkTestRealInstall = networkTestArchive && networkTestXrayArchive && networkTestCloudflared ? test : test.skip;
networkTestRealInstall("official fixtures install only requested cores, normalize TLS, reuse cache and repair corruption", async () => {
  const dir = networkTestFs.mkdtempSync(networkTestPath.join(networkTestOs.tmpdir(), "nexus-install-test-"));
  const paths = createPaths(networkTestPath.join(dir, "nexus-edge.ts")); const originalFetch = globalThis.fetch;
  const requests: string[] = [];
  globalThis.fetch = (async (input: any) => {
    const url = String(input); requests.push(url);
    for (const [tool, fixture] of [["singBox", networkTestArchive], ["xray", networkTestXrayArchive], ["cloudflared", networkTestCloudflared]] as const) {
      const release = NETWORK_RELEASES[tool], asset = release.assets[`${process.platform}-${process.arch}`]!;
      if (url === release.base + asset.asset) return new Response(Bun.file(fixture!));
    }
    throw new Error("This test must not contact an external service.");
  }) as unknown as typeof fetch;
  try {
    const config = networkTestConfig("vless");
    const installed = await ensureBinaries(paths, config); expect(Object.keys(installed)).toEqual(["xray"]); expect(requests.length).toBe(1);
    expect(await ensureBinaries(paths, config)).toEqual(installed); expect(requests.length).toBe(1);
    const draft = config.nodes[0]!; draft.tls.mode = "tls"; draft.tls.serverName = "example.com";
    const tls = await generateSelfSignedCertificate(paths, draft); Object.assign(draft.tls, tls);
    expect(tls.keyPem).toContain("BEGIN PRIVATE KEY");
    expect(new networkTestCrypto.X509Certificate(tls.certificatePem).checkPrivateKey(networkTestCrypto.createPrivateKey(tls.keyPem))).toBe(true);
    Object.assign(draft, await generateVlessEncryption(paths)); expect(draft.vlessEncryption).not.toBe("none");
    expect(requests.length).toBe(1); await preflightCores(paths, config);
    networkTestFs.writeFileSync(networkTestPath.join(networkTestPath.dirname(installed.xray!), "README.md"), "corrupt");
    expect(await ensureBinaries(paths, config)).toEqual(installed); expect(requests.length).toBe(2);
    const second = createDefaultNode("vmess", config.nodes); second.transport.type = "ws";
    second.tunnel = { ...second.tunnel, mode: "fixed", domain: "local-only.invalid", token: "dummyToken1234567890" }; config.nodes.push(second);
    const both = await preflightCores(paths, config); expect(Object.keys(both)).toEqual(["singBox", "xray", "cloudflared"]); expect(requests.length).toBe(4);
    const singTls = await generateSelfSignedCertificate(paths, createDefaultNode("trojan"));
    expect(new networkTestCrypto.X509Certificate(singTls.certificatePem).checkPrivateKey(networkTestCrypto.createPrivateKey(singTls.keyPem))).toBe(true);
    expect(networkTestFs.readFileSync(cloudflaredConfigPath(paths, second.id), "utf8")).toBe("{}\n");
    expect(networkTestFs.readFileSync(cloudflaredTokenPath(paths, second.id), "utf8")).toBe(second.tunnel.token + "\n");
    expect(JSON.parse(networkTestFs.readFileSync(paths.xrayConfig, "utf8")).inbounds).toHaveLength(1);
    expect(JSON.parse(networkTestFs.readFileSync(paths.singConfig, "utf8")).inbounds).toHaveLength(1);
    expect(networkTestFs.readdirSync(paths.bin).some(name => name.startsWith(".install") || name.includes(".old-"))).toBe(false);
    expect(networkTestFs.readdirSync(paths.data).some(name => name.endsWith(".candidate.json"))).toBe(false);
  } finally { globalThis.fetch = originalFetch; networkTestFs.rmSync(dir, { recursive: true, force: true }); }
}, 120_000);

const networkTestWindowsSing = process.env.NEXUS_EDGE_TEST_SINGBOX_WINDOWS_ARCHIVE;
const networkTestWindowsXray = process.env.NEXUS_EDGE_TEST_XRAY_WINDOWS_ARCHIVE;
(networkTestWindowsSing && networkTestWindowsXray ? test : test.skip)("official Windows ZIP layouts extract and authenticate without executing Windows binaries", async () => {
  const dir = networkTestFs.mkdtempSync(networkTestPath.join(networkTestOs.tmpdir(), "nexus-windows-zip-test-"));
  const paths = createPaths(networkTestPath.join(dir, "nexus-edge.ts"));
  const platform = `${process.platform}-${process.arch}`;
  const originalFetch = globalThis.fetch;
  try {
    for (const [tool, fixture, protocol] of [["singBox", networkTestWindowsSing, "vmess"], ["xray", networkTestWindowsXray, "vless"]] as const) {
      const release = NETWORK_RELEASES[tool], originalAsset = release.assets[platform]!, windowsAsset = release.assets["win32-x64"]!;
      // Exercise the same installer/parser on this OS, selecting only a Windows
      // archive fixture. This is archive validation, not a Windows runtime test.
      release.assets[platform] = windowsAsset;
      globalThis.fetch = (async (input: any) => {
        expect(String(input)).toBe(release.base + windowsAsset.asset);
        return new Response(Bun.file(fixture!));
      }) as unknown as typeof fetch;
      try {
        const installed = await ensureBinaries(paths, networkTestConfig(protocol), undefined, readCoreSelection(paths).active);
        expect(networkTestPath.basename(installed[tool]!)).toBe(windowsAsset.executable);
        const destination = networkTestPath.dirname(installed[tool]!);
        expect(networkTestFs.readdirSync(destination).sort()).toEqual(Object.keys(windowsAsset.files).sort());
        for (const [name, expectedHash] of Object.entries(windowsAsset.files)) expect(networkTestCrypto.createHash("sha256").update(networkTestFs.readFileSync(networkTestPath.join(destination, name))).digest("hex")).toBe(expectedHash);
      } finally { release.assets[platform] = originalAsset; }
    }
  } finally { globalThis.fetch = originalFetch; networkTestFs.rmSync(dir, { recursive: true, force: true }); }
}, 120_000);
