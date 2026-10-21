import { afterEach, describe, expect, test } from "bun:test";
import * as releaseTestFs from "node:fs";
import * as releaseTestOs from "node:os";
import * as releaseTestPath from "node:path";
import * as releaseTestCrypto from "node:crypto";
import * as releaseTestZlib from "node:zlib";
import { type BinaryKind, type NetworkAsset, type CoreRelease, type CoreReleaseCandidate, NETWORK_RELEASES, checkCoreUpdates, fetchCoreRelease, compareCoreVersions, readCoreSelection, writeCoreSelection, initializeCoreSelection, acquireCoreSelectionLock, coreSelectionPath, coreReleaseFingerprint, coreBinaryPath, prepareCoreRelease, ensureSingleCore, ensureBinaries, preflightCores, generateSelfSignedCertificate, generateVlessEncryption, cloudflaredConfigPath, cloudflaredTokenPath } from "../src/network.ts";
import { createPaths, createDefaultNode, defaultConfig, ensureDataDir } from "../src/core.ts";

const releaseTestFetch = globalThis.fetch;
const releaseTestRoots: string[] = [];
const releaseTestKinds: BinaryKind[] = ["singBox", "xray", "cloudflared"];
const releaseTestRepos: Record<BinaryKind, string> = { singBox: "SagerNet/sing-box", xray: "XTLS/Xray-core", cloudflared: "cloudflare/cloudflared" };
const releaseTestPlatform = `${process.platform}-${process.arch}`;
afterEach(() => { globalThis.fetch = releaseTestFetch; for (const root of releaseTestRoots.splice(0)) releaseTestFs.rmSync(root, { recursive: true, force: true }); });

function releaseTestPaths() {
  const root = releaseTestFs.mkdtempSync(releaseTestPath.join(releaseTestOs.tmpdir(), "nexus-core-release-")); releaseTestRoots.push(root);
  return createPaths(releaseTestPath.join(root, "nexus-edge.ts"));
}

function releaseTestMetadata(tool: BinaryKind, version = NETWORK_RELEASES[tool].version as string, prerelease = NETWORK_RELEASES[tool].prerelease as boolean) {
  const bundled = NETWORK_RELEASES[tool], tag = tool === "cloudflared" ? version : `v${version}`;
  const asset = bundled.assets[releaseTestPlatform]!;
  const name = tool === "singBox" ? asset.asset.replace(bundled.version, version) : asset.asset;
  return { draft: false, prerelease, tag_name: tag, html_url: `https://github.com/${releaseTestRepos[tool]}/releases/tag/${tag}`,
    assets: [{ name, digest: `sha256:${asset.sha256}`, size: 100, state: "uploaded", browser_download_url: `https://github.com/${releaseTestRepos[tool]}/releases/download/${tag}/${name}` }] };
}

function releaseTestMockMetadata(factory: (tool: BinaryKind, url: string) => unknown): string[] {
  const requests: string[] = [];
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input); requests.push(url);
    expect(new URL(url).origin).toBe("https://api.github.com");
    expect(init?.redirect).toBe("error");
    const tool = releaseTestKinds.find(kind => url.startsWith(`https://api.github.com/repos/${releaseTestRepos[kind]}/releases`));
    if (!tool) throw new Error("Unexpected external request");
    const value = factory(tool, url); return value instanceof Response ? value : Response.json(value);
  }) as unknown as typeof fetch;
  return requests;
}

function releaseTestCandidate(paths: ReturnType<typeof createPaths>, tool: BinaryKind, bytes?: Uint8Array): CoreReleaseCandidate {
  const original = readCoreSelection(paths).active[tool];
  const { files: _files, ...asset } = original.asset;
  return { ...original, source: "github", asset: { ...asset, ...(bytes ? { sha256: releaseTestCrypto.createHash("sha256").update(bytes).digest("hex") } : {}) } };
}

// Former 2.2.0 bundled manifest: verifies that saved selections survive the stable-default correction.
const releaseTestLegacyXrayAssets: Record<string, NetworkAsset> = {
  "linux-x64": {
    "asset": "Xray-linux-64.zip",
    "archive": "zip",
    "directory": "",
    "executable": "xray",
    "sha256": "ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158",
    "files": {
      "geosite.dat": "8474140bc89940897ee2b629be8fc92f34a496bd32e45829605d17715f4340d6",
      "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
      "geoip.dat": "010bfc2e353c5e34e23156004944444ca260bae999e73171bdd7974056557959",
      "README.md": "0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde",
      "xray": "6771b2b2700dee175357024738ad579de1c3f2c49eec0257e737d5aa38d12fed"
    }
  },
  "linux-arm64": {
    "asset": "Xray-linux-arm64-v8a.zip",
    "archive": "zip",
    "directory": "",
    "executable": "xray",
    "sha256": "4ebdad86048fa499e65334f88a120b1ed17e662f1c222afd3514afdf8820cdb1",
    "files": {
      "geosite.dat": "8474140bc89940897ee2b629be8fc92f34a496bd32e45829605d17715f4340d6",
      "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
      "geoip.dat": "010bfc2e353c5e34e23156004944444ca260bae999e73171bdd7974056557959",
      "README.md": "0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde",
      "xray": "1ce8c2d27b22e4eb510223ad8e0f6c844994e84a5d4e982a51c447da1710f415"
    }
  },
  "win32-x64": {
    "asset": "Xray-windows-64.zip",
    "archive": "zip",
    "directory": "",
    "executable": "xray.exe",
    "sha256": "c10a532a9271964f2aa2f4b4c0757605ff529222cb1d5d7ab88f8ecc52e67fb0",
    "files": {
      "geosite.dat": "8474140bc89940897ee2b629be8fc92f34a496bd32e45829605d17715f4340d6",
      "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
      "geoip.dat": "010bfc2e353c5e34e23156004944444ca260bae999e73171bdd7974056557959",
      "README.md": "0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde",
      "wintun.dll": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
      "xray.exe": "a743b8c2ce49cb33d6c1cf764c780bf1a475d746ad7485e7c3fcfe6458511c92",
      "LICENSE-Wintun": "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"
    }
  }
};

function releaseTestSaveLegacyXray(paths: ReturnType<typeof createPaths>): CoreRelease {
  const state = readCoreSelection(paths);
  const release: CoreRelease = {
    tool: "xray", version: "26.10.17", tag: "v26.10.17", platform: releaseTestPlatform, prerelease: true, source: "bundled",
    downloadUrl: `https://github.com/XTLS/Xray-core/releases/download/v26.10.17/${releaseTestLegacyXrayAssets[releaseTestPlatform]!.asset}`,
    releaseUrl: "https://github.com/XTLS/Xray-core/releases/tag/v26.10.17", asset: structuredClone(releaseTestLegacyXrayAssets[releaseTestPlatform]!),
  };
  state.active.xray = release; writeCoreSelection(paths, state); return release;
}

describe("official core release checks", () => {
  test("stable lookup never downgrades an explicitly saved newer Xray prerelease", async () => {
    const paths = releaseTestPaths(); releaseTestSaveLegacyXray(paths);
    const before = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8");
    const requests = releaseTestMockMetadata(tool => releaseTestMetadata(tool, tool === "singBox" ? "1.14.4" : tool === "xray" ? "26.3.27" : undefined, false));
    const checks = await checkCoreUpdates(paths);
    expect(checks.map(check => [check.tool, check.updateAvailable])).toEqual([["singBox", true], ["xray", false], ["cloudflared", false]]);
    expect(checks[1]!.current.version).toBe("26.10.17"); expect(checks[1]!.latest?.version).toBe("26.3.27");
    expect(checks.every(check => !check.error)).toBe(true); expect(requests).toHaveLength(3);
    expect(requests.every(url => url.endsWith("/latest"))).toBe(true);
    expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(before);
  });

  test("preview lookup numerically orders alpha versions and ignores draft/unrelated tags", async () => {
    const paths = releaseTestPaths();
    releaseTestMockMetadata(tool => tool === "singBox" ? [
      releaseTestMetadata(tool, "1.15.0-alpha.2", true), releaseTestMetadata(tool, "1.14.4", false),
      { ...releaseTestMetadata(tool, "9.0.0", true), draft: true }, { ...releaseTestMetadata(tool), tag_name: "continuous" },
      releaseTestMetadata(tool, "1.15.0-alpha.12", true),
    ] : [releaseTestMetadata(tool)]);
    const checks = await checkCoreUpdates(paths, "preview");
    expect(checks[0]!.latest?.version).toBe("1.15.0-alpha.12"); expect(checks[0]!.latest?.prerelease).toBe(true);
    expect(checks[0]!.updateAvailable).toBe(true); expect(checks.slice(1).every(check => !check.updateAvailable)).toBe(true);
  });

  test("an explicit version is normalized to its official repository tag", async () => {
    const requests = releaseTestMockMetadata((tool, url) => releaseTestMetadata(tool, url.split("/").at(-1)!.replace(/^v/, ""), true));
    const release = await fetchCoreRelease("singBox", " v1.15.0-alpha.12 ");
    expect(release.version).toBe("1.15.0-alpha.12"); expect(release.tag).toBe("v1.15.0-alpha.12");
    expect(release.source).toBe("github"); expect(release.asset.files).toBeUndefined();
    expect(requests).toEqual(["https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.15.0-alpha.12"]);
  });

  test("explicit unsafe versions are refused without network requests", async () => {
    const requests = releaseTestMockMetadata(tool => releaseTestMetadata(tool));
    for (const version of ["../latest", "1.0.0/../../evil", "https://evil.invalid", "v1.0.0?download=1", "1.2"]) await expect(fetchCoreRelease("singBox", version)).rejects.toThrow("版本号");
    expect(requests).toHaveLength(0);
  });

  test("explicit version response must match the requested tag", async () => {
    releaseTestMockMetadata(tool => releaseTestMetadata(tool, "1.14.3", false));
    await expect(fetchCoreRelease("singBox", "1.14.4")).rejects.toThrow("与所选版本不一致");
  });

  for (const bad of ["digest", "url", "release-url", "duplicate", "missing", "draft"] as const) {
    test(`invalid official metadata (${bad}) does not affect another core or write selections`, async () => {
      const paths = releaseTestPaths();
      releaseTestMockMetadata(tool => {
        const value: any = releaseTestMetadata(tool, undefined, false);
        if (tool !== "singBox") return value;
        if (bad === "digest") value.assets[0].digest = null;
        if (bad === "url") value.assets[0].browser_download_url = "https://evil.invalid/core";
        if (bad === "release-url") value.html_url = "https://github.com/other/sing-box/releases/tag/v1.14.3";
        if (bad === "duplicate") value.assets.push(value.assets[0]);
        if (bad === "missing") value.assets = [];
        if (bad === "draft") value.draft = true;
        return value;
      });
      const checks = await checkCoreUpdates(paths);
      expect(checks[0]!.error).toBeTruthy(); expect(checks[0]!.latest).toBeUndefined(); expect(checks[0]!.updateAvailable).toBe(false);
      expect(checks.slice(1).every(check => !check.error)).toBe(true); expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false);
    });
  }

  test("rate limiting and oversized metadata leave current selections intact", async () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths); writeCoreSelection(paths, state);
    const before = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8");
    releaseTestMockMetadata(tool => tool === "singBox" ? new Response("secret provider response", { status: 403 }) : tool === "xray" ? new Response("{}", { headers: { "content-length": String(17 * 1024 * 1024) } }) : releaseTestMetadata(tool, undefined, false));
    const checks = await checkCoreUpdates(paths);
    expect(checks[0]!.error).toContain("GitHub 暂时限制"); expect(checks[0]!.error).not.toContain("secret");
    expect(checks[1]!.error).toContain("大小限制"); expect(checks[2]!.error).toBeUndefined();
    expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(before);
  });

  test("a stable endpoint returning a prerelease is not silently accepted", async () => {
    const paths = releaseTestPaths(); releaseTestMockMetadata(tool => releaseTestMetadata(tool, undefined, true));
    const checks = await checkCoreUpdates(paths); expect(checks.every(check => Boolean(check.error) && !check.updateAvailable)).toBe(true);
  });
});

describe("version ordering and durable selection", () => {
  test("version ordering handles dates, alpha numbers, and final releases", () => {
    for (const [a, b] of [["26.10.17", "26.3.27"], ["2026.10.2", "2026.9.99"], ["1.15.0-alpha.12", "1.15.0-alpha.2"], ["1.15.0", "1.15.0-rc.2"], ["1.15.0-alpha.2", "1.15.0-alpha"], ["1.15.0-beta", "1.15.0-alpha.10"]]) {
      expect(compareCoreVersions(a!, b!)).toBeGreaterThan(0); expect(compareCoreVersions(b!, a!)).toBeLessThan(0);
    }
    expect(compareCoreVersions("1.14.3", "1.14.3")).toBe(0);
    expect(() => compareCoreVersions("1.14", "1.14.3")).toThrow("版本号");
  });

  test("all bundled defaults are the current verified official stable releases", () => {
    const defaults = readCoreSelection(releaseTestPaths()).active;
    expect(Object.fromEntries(releaseTestKinds.map(tool => [tool, defaults[tool].version]))).toEqual({ singBox: "1.14.3", xray: "26.3.27", cloudflared: "2026.10.2" });
    for (const tool of releaseTestKinds) {
      expect(NETWORK_RELEASES[tool].prerelease).toBe(false); expect(defaults[tool].prerelease).toBe(false);
      expect(defaults[tool].source).toBe("bundled");
    }
  });

  test("missing selections use bundled defaults without creating files", () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths);
    expect(state.schema).toBe(1); expect(Object.keys(state.active)).toEqual(releaseTestKinds); expect(state.previous).toBeUndefined();
    for (const tool of releaseTestKinds) {
      const release = state.active[tool]; expect(release.source).toBe("bundled"); expect(release.version).toBe(NETWORK_RELEASES[tool].version);
      expect(coreBinaryPath(paths, release)).toBe(releaseTestPath.join(paths.bin, `${tool}-${release.version}-${releaseTestPlatform}`, release.asset.executable));
    }
    expect(releaseTestFs.existsSync(paths.bin)).toBe(false);
  });

  test("first use pins versions once, with the same lock used by updates", () => {
    const paths = releaseTestPaths(), release = acquireCoreSelectionLock(paths);
    try { expect(() => initializeCoreSelection(paths)).toThrow("已有内核更新或回退"); expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false); }
    finally { release(); }
    const initial = initializeCoreSelection(paths), bytes = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8");
    expect(initial.active.singBox.version).toBe(NETWORK_RELEASES.singBox.version);
    expect(initializeCoreSelection(paths)).toEqual(initial); expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(bytes);
  });

  test("a saved first-use pin survives a later script changing its bundled default", () => {
    const paths = releaseTestPaths(), initial = initializeCoreSelection(paths), bundled = NETWORK_RELEASES.singBox as { version: string };
    const originalVersion = bundled.version;
    try {
      bundled.version = "1.14.4";
      expect(readCoreSelection(paths).active.singBox.version).toBe(originalVersion);
      expect(initializeCoreSelection(paths)).toEqual(initial);
    } finally { bundled.version = originalVersion; }
  });

  test("an empty collection and an explicit candidate preflight do not initialize defaults", async () => {
    const paths = releaseTestPaths(); expect(await ensureBinaries(paths, defaultConfig())).toEqual({});
    expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false);
    await expect(preflightCores(paths, defaultConfig(), { releases: readCoreSelection(paths).active, publish: false })).rejects.toThrow("没有启用的节点");
    expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false);
  });

  test("current bundled versions cannot replace pinned archive or file hashes with other valid hashes", () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths);
    for (const kind of ["archive", "file"] as const) {
      const changed = structuredClone(state);
      if (kind === "archive") changed.active.singBox.asset.sha256 = "a".repeat(64);
      else changed.active.singBox.asset.files[changed.active.singBox.asset.executable] = "b".repeat(64);
      expect(() => writeCoreSelection(paths, changed)).toThrow("内置版本的 SHA-256");
    }
    expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false);
  });

  test("active/previous manifests roundtrip and hashed cache locations coexist", () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths), previous = structuredClone(state.active);
    state.active.singBox.source = "github"; state.previous = previous; state.updatedAt = "2026-10-21T10:00:00.000Z";
    writeCoreSelection(paths, state); expect(readCoreSelection(paths)).toEqual(state);
    expect(coreBinaryPath(paths, state.active.singBox)).not.toBe(coreBinaryPath(paths, previous.singBox));
    expect(coreBinaryPath(paths, state.active.singBox)).toContain(state.active.singBox.asset.sha256.slice(0, 16));
    if (process.platform !== "win32") expect(releaseTestFs.statSync(coreSelectionPath(paths)).mode & 0o777).toBe(0o600);
  });

  test("fingerprint is independent of map/file order and includes executable identity", () => {
    const state = readCoreSelection(releaseTestPaths()), base = coreReleaseFingerprint(state.active), reordered = structuredClone(state.active);
    reordered.singBox.asset.files = Object.fromEntries(Object.entries(reordered.singBox.asset.files).reverse());
    expect(coreReleaseFingerprint(reordered)).toBe(base);
    reordered.singBox.source = "github"; expect(coreReleaseFingerprint(reordered)).not.toBe(base);
    const changed = structuredClone(state.active); changed.singBox.asset.sha256 = "a".repeat(64); expect(coreReleaseFingerprint(changed)).not.toBe(base);
    const files = structuredClone(state.active); files.singBox.asset.files[files.singBox.asset.executable] = "b".repeat(64); expect(coreReleaseFingerprint(files)).not.toBe(base);
  });

  for (const bad of ["schema", "platform", "url", "filename", "digest", "missing-exe", "missing-core", "binary-extra"] as const) {
    test(`selection validation (${bad}) preserves the previous complete file`, () => {
      const paths = releaseTestPaths(), state = readCoreSelection(paths); writeCoreSelection(paths, state);
      const before = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8"), changed: any = structuredClone(state);
      if (bad === "schema") changed.schema = 2;
      if (bad === "platform") changed.active.singBox.platform = "win32-arm64";
      if (bad === "url") changed.active.singBox.downloadUrl += "?mirror=evil";
      if (bad === "filename") changed.active.singBox.asset.files["../escape"] = "a".repeat(64);
      if (bad === "digest") changed.active.singBox.asset.sha256 = "";
      if (bad === "missing-exe") delete changed.active.singBox.asset.files[changed.active.singBox.asset.executable];
      if (bad === "missing-core") delete changed.active.xray;
      if (bad === "binary-extra") changed.active.cloudflared.asset.files["rogue.dll"] = "b".repeat(64);
      expect(() => writeCoreSelection(paths, changed)).toThrow(); expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(before);
    });
  }

  test("malformed on-disk selection never silently falls back to bundled versions", () => {
    const paths = releaseTestPaths(); ensureDataDir(paths); releaseTestFs.writeFileSync(coreSelectionPath(paths), '{"schema":1,"active":');
    expect(() => readCoreSelection(paths)).toThrow("内核版本记录无效");
  });

  (process.platform !== "win32" ? test : test.skip)("selection symlinks are refused for both reads and writes", () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths); ensureDataDir(paths);
    const target = releaseTestPath.join(paths.root, "untouched.json"); releaseTestFs.writeFileSync(target, "untouched");
    releaseTestFs.symlinkSync(target, coreSelectionPath(paths));
    expect(() => readCoreSelection(paths)).toThrow("普通文件"); expect(() => writeCoreSelection(paths, state)).toThrow();
    expect(releaseTestFs.readFileSync(target, "utf8")).toBe("untouched");
  });
});

function releaseTestZip(entries: { name: string; data: string; unixType?: number }[]): Buffer {
  const locals: Buffer[] = [], centrals: Buffer[] = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name), data = Buffer.from(entry.data), local = Buffer.alloc(30), central = Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26);
    central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x0314, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt32LE(((entry.unixType ?? 0o100644) << 16) >>> 0, 38); central.writeUInt32LE(offset, 42);
    locals.push(local, name, data); centrals.push(central, name); offset += local.length + name.length + data.length;
  }
  const directory = Buffer.concat(centrals), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

function releaseTestTar(name: string, type = "0"): Buffer {
  const data = Buffer.from("test"), header = Buffer.alloc(512); header.write(name, 0, 100); header.write("0000644\0", 100); header.write("0000000\0", 108); header.write("0000000\0", 116); header.write(data.length.toString(8).padStart(11, "0") + "\0", 124); header.write("00000000000\0", 136); header.fill(32, 148, 156); header.write(type, 156); header.write("ustar\0", 257);
  const checksum = header.reduce((sum, byte) => sum + byte, 0); header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148);
  return releaseTestZlib.gzipSync(Buffer.concat([header, data, Buffer.alloc(512 - data.length + 1024)]));
}

describe("core update downloads and archive boundaries", () => {
  test("an incorrect archive hash changes neither selected versions nor existing cache", async () => {
    const paths = releaseTestPaths(), state = readCoreSelection(paths); writeCoreSelection(paths, state);
    const before = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8");
    globalThis.fetch = (async () => new Response("not an official archive")) as unknown as typeof fetch;
    await expect(prepareCoreRelease(paths, releaseTestCandidate(paths, "xray"))).rejects.toThrow("SHA-256");
    expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(before);
    expect(releaseTestFs.readdirSync(paths.bin)).toEqual(["core-versions.json"]);
  });

  for (const entry of [{ name: "../escape", data: "bad" }, { name: "/tmp/escape", data: "bad" }, { name: "xray", data: "target", unixType: 0o120777 }, { name: "subdir/payload", data: "bad" }]) {
    test(`verified archive still cannot extract unsafe ZIP entry ${entry.name}`, async () => {
      const paths = releaseTestPaths(), archive = releaseTestZip([entry]);
      globalThis.fetch = (async () => new Response(new Uint8Array(archive))) as unknown as typeof fetch;
      await expect(prepareCoreRelease(paths, releaseTestCandidate(paths, "xray", archive))).rejects.toThrow();
      expect(releaseTestFs.readdirSync(paths.bin)).toEqual([]); expect(releaseTestFs.existsSync(releaseTestPath.join(paths.root, "escape"))).toBe(false);
      expect(releaseTestFs.existsSync(coreSelectionPath(paths))).toBe(false);
    });
  }

  test("case-colliding ZIP files are refused before executing a candidate", async () => {
    const paths = releaseTestPaths(), archive = releaseTestZip([{ name: "LICENSE", data: "license" }, { name: "license", data: "collision" }]);
    globalThis.fetch = (async () => new Response(new Uint8Array(archive))) as unknown as typeof fetch;
    await expect(prepareCoreRelease(paths, releaseTestCandidate(paths, "xray", archive))).rejects.toThrow("重复文件名");
    expect(releaseTestFs.readdirSync(paths.bin)).toEqual([]);
  });

  (process.platform === "linux" ? test : test.skip)("TAR symlinks and traversal entries are refused", async () => {
    const paths = releaseTestPaths(), directory = NETWORK_RELEASES.singBox.assets[releaseTestPlatform]!.directory!;
    for (const archive of [releaseTestTar(`${directory}/../escape`), releaseTestTar(`${directory}/sing-box`, "2")]) {
      globalThis.fetch = (async () => new Response(new Uint8Array(archive))) as unknown as typeof fetch;
      await expect(prepareCoreRelease(paths, releaseTestCandidate(paths, "singBox", archive))).rejects.toThrow();
      expect(releaseTestFs.readdirSync(paths.bin)).toEqual([]);
    }
  });

  (process.platform === "linux" ? test : test.skip)("verified bytes reporting the wrong executable version never become active", async () => {
    const paths = releaseTestPaths(), bytes = Buffer.from('#!/bin/sh\nprintf "cloudflared version 0.0.1\\n"\n');
    globalThis.fetch = (async () => new Response(bytes)) as unknown as typeof fetch;
    await expect(prepareCoreRelease(paths, releaseTestCandidate(paths, "cloudflared", bytes))).rejects.toThrow("实际版本与所选");
    expect(releaseTestFs.readdirSync(paths.bin)).toEqual([]); expect(readCoreSelection(paths).active.cloudflared.source).toBe("bundled");
  });
});

const releaseTestFixtures: Partial<Record<BinaryKind, string>> = {
  singBox: process.env.NEXUS_EDGE_TEST_SINGBOX_ARCHIVE, xray: process.env.NEXUS_EDGE_TEST_XRAY_ARCHIVE, cloudflared: process.env.NEXUS_EDGE_TEST_CLOUDFLARED_BINARY,
};
const releaseTestHaveFixtures = releaseTestKinds.every(tool => Boolean(releaseTestFixtures[tool]));
(releaseTestHaveFixtures ? test : test.skip)("real official updates preserve dependencies, honor selected cores, preflight without publication, and repair cache", async () => {
  const paths = releaseTestPaths(), before = readCoreSelection(paths), selected = structuredClone(before.active), requests: string[] = [];
  globalThis.fetch = (async (input: any) => {
    const url = String(input); requests.push(url);
    const tool = releaseTestKinds.find(kind => url === before.active[kind].downloadUrl);
    if (!tool) throw new Error("This fixture test must not contact the network");
    return new Response(Bun.file(releaseTestFixtures[tool]!));
  }) as unknown as typeof fetch;
  for (const tool of releaseTestKinds) {
    selected[tool] = await prepareCoreRelease(paths, releaseTestCandidate(paths, tool));
    expect(selected[tool].asset.files).toEqual(before.active[tool].asset.files);
    expect(releaseTestFs.existsSync(coreBinaryPath(paths, selected[tool]))).toBe(true);
    expect(readCoreSelection(paths).active[tool].source).toBe("bundled");
  }
  expect(requests).toHaveLength(3);
  const config = defaultConfig(), vless = createDefaultNode("vless"), vmess = createDefaultNode("vmess", [vless]);
  vmess.transport.type = "ws"; vmess.tunnel = { ...vmess.tunnel, mode: "fixed", domain: "local-only.invalid", token: "dummyToken1234567890" };
  config.nodes = [vless, vmess];
  releaseTestFs.writeFileSync(paths.singConfig, "original sing config"); releaseTestFs.writeFileSync(paths.xrayConfig, "original xray config");
  releaseTestFs.writeFileSync(cloudflaredConfigPath(paths, vmess.id), "original cloud config"); releaseTestFs.writeFileSync(cloudflaredTokenPath(paths, vmess.id), "original token");
  const binaries = await preflightCores(paths, config, { releases: selected, publish: false });
  for (const tool of releaseTestKinds) expect(binaries[tool]).toBe(coreBinaryPath(paths, selected[tool]));
  expect(releaseTestFs.readFileSync(paths.singConfig, "utf8")).toBe("original sing config"); expect(releaseTestFs.readFileSync(paths.xrayConfig, "utf8")).toBe("original xray config");
  expect(releaseTestFs.readFileSync(cloudflaredConfigPath(paths, vmess.id), "utf8")).toBe("original cloud config"); expect(releaseTestFs.readFileSync(cloudflaredTokenPath(paths, vmess.id), "utf8")).toBe("original token");
  expect(releaseTestFs.readdirSync(paths.data).some(name => name.endsWith(".candidate.json"))).toBe(false);
  writeCoreSelection(paths, { schema: 1, active: selected, previous: before.active });
  expect(await ensureBinaries(paths, config)).toEqual(binaries); expect(requests).toHaveLength(3);
  const tls = await generateSelfSignedCertificate(paths, { ...vless, tls: { ...vless.tls, serverName: "local-only.invalid" } });
  expect(new releaseTestCrypto.X509Certificate(tls.certificatePem).checkPrivateKey(releaseTestCrypto.createPrivateKey(tls.keyPem))).toBe(true);
  expect((await generateVlessEncryption(paths)).vlessEncryption).not.toBe("none"); expect(requests).toHaveLength(3);
  releaseTestFs.writeFileSync(releaseTestPath.join(releaseTestPath.dirname(binaries.xray!), "README.md"), "corrupt");
  expect(await ensureSingleCore(paths, selected.xray)).toBe(binaries.xray!); expect(requests).toHaveLength(4);
  expect(releaseTestFs.readFileSync(releaseTestPath.join(releaseTestPath.dirname(binaries.xray!), "README.md"), "utf8")).not.toBe("corrupt");
  expect(releaseTestFs.readdirSync(paths.bin).some(name => name.startsWith(".install") || name.includes(".old-"))).toBe(false);
  expect(readCoreSelection(paths).previous).toEqual(before.active);
}, 120_000);

const releaseTestLegacyXrayArchive = process.env.NEXUS_EDGE_TEST_LEGACY_XRAY_ARCHIVE;
(releaseTestLegacyXrayArchive ? test : test.skip)("saved historical bundled Xray prerelease remains usable after stable defaults change", async () => {
  const paths = releaseTestPaths(), legacy = releaseTestSaveLegacyXray(paths), before = releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8");
  let requests = 0;
  globalThis.fetch = (async (input: any) => {
    expect(String(input)).toBe(legacy.downloadUrl); requests++;
    return new Response(Bun.file(releaseTestLegacyXrayArchive!));
  }) as unknown as typeof fetch;
  const config = defaultConfig(); config.nodes.push(createDefaultNode("vless"));
  const binaries = await ensureBinaries(paths, config);
  expect(binaries.xray).toBe(coreBinaryPath(paths, legacy)); expect(binaries.xray).toContain("26.10.17");
  expect(requests).toBe(1); expect(await ensureBinaries(paths, config)).toEqual(binaries); expect(requests).toBe(1);
  await preflightCores(paths, config, { publish: false });
  expect(readCoreSelection(paths).active.xray).toEqual(legacy); expect(initializeCoreSelection(paths).active.xray).toEqual(legacy);
  expect(releaseTestFs.readFileSync(coreSelectionPath(paths), "utf8")).toBe(before);
  expect(readCoreSelection(releaseTestPaths()).active.xray.version).toBe("26.3.27");
}, 60_000);
