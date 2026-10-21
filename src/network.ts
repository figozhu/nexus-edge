import * as networkFs from "node:fs";
import * as networkPath from "node:path";
import * as networkCrypto from "node:crypto";
import * as networkNet from "node:net";
import * as networkZlib from "node:zlib";
import * as networkSqlite from "bun:sqlite";
import { assertSupportedPlatform, atomicWrite, ensureDataDir, runCommand, validateConfig, validateNode, validateWarpProfile, nodeEngine, normalizeConnectAddress, collectConfigSecrets, redact } from "./core";
import type { AppConfig, AppPaths, WarpProfile, NodeConfig } from "./core";

export interface NetworkAsset {
  asset: string;
  archive: "tar.gz" | "zip" | "binary";
  sha256: string;
  directory?: string;
  executable: string;
  files: Record<string, string>;
}

// Official release archive hashes were checked against GitHub's release asset digest.
// File hashes below were computed ONLY after verifying those fixed archive hashes.
// Keeping the extracted hashes here also authenticates the installed cache without
// trusting a mutable receipt next to the executable. Preserve upstream LICENSEs.
export const NETWORK_RELEASES = {
  singBox: {
    version: "1.14.3",
    prerelease: false,
    release: "https://github.com/SagerNet/sing-box/releases/tag/v1.14.3",
    base: "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/",
    assets: {
      "linux-x64": {
        asset: "sing-box-1.14.3-linux-amd64.tar.gz", archive: "tar.gz",
        sha256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
        directory: "sing-box-1.14.3-linux-amd64", executable: "sing-box",
        files: {
          "sing-box": "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93",
          "libcronet.so": "23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294",
          LICENSE: "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
        },
      },
      "linux-arm64": {
        asset: "sing-box-1.14.3-linux-arm64.tar.gz", archive: "tar.gz",
        sha256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
        directory: "sing-box-1.14.3-linux-arm64", executable: "sing-box",
        files: {
          "sing-box": "299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689",
          "libcronet.so": "3c1fcfcb56261a4b318ffb6d2227b9726782edb5a894e74db2b534406db62498",
          LICENSE: "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
        },
      },
      "win32-x64": {
        asset: "sing-box-1.14.3-windows-amd64.zip", archive: "zip",
        sha256: "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
        directory: "sing-box-1.14.3-windows-amd64", executable: "sing-box.exe",
        files: {
          "sing-box.exe": "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf",
          "libcronet.dll": "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928",
          LICENSE: "bb3805862b583aee73ad6f7805ec634747a37257a637a3069857843f05ea589c",
        },
      },
    } as Record<string, NetworkAsset>,
  },
  xray: {
    "version": "26.3.27",
    "prerelease": false,
    "release": "https://github.com/XTLS/Xray-core/releases/tag/v26.3.27",
    "base": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/",
    "assets": {
      "linux-x64": {
        "asset": "Xray-linux-64.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray",
        "sha256": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        "files": {
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "xray": "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      },
      "linux-arm64": {
        "asset": "Xray-linux-arm64-v8a.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray",
        "sha256": "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
        "files": {
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "xray": "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      },
      "win32-x64": {
        "asset": "Xray-windows-64.zip",
        "archive": "zip",
        "directory": "",
        "executable": "xray.exe",
        "sha256": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
        "files": {
          "xray_no_window.ps1": "82f62d3edaea84dc1abc395f71815781a4b9b934b2ecefd9f9f7ec7f770651eb",
          "xray.exe": "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1",
          "geoip.dat": "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
          "wintun.dll": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
          "xray_no_window.vbs": "141814ac8083e9dc53c1cc3c3b13160476f2fb9585dfa63c4010ed8c2926bd95",
          "geosite.dat": "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
          "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
          "LICENSE-wintun.txt": "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2",
          "README.md": "d83daf86fd411e33762c42cb2e49a0b114de44604e26c126cc72b60e63646d2f"
        }
      }
    } as Record<string, NetworkAsset>
  },
  cloudflared: {
    version: "2026.10.2",
    prerelease: false,
    release: "https://github.com/cloudflare/cloudflared/releases/tag/2026.10.2",
    base: "https://github.com/cloudflare/cloudflared/releases/download/2026.10.2/",
    assets: {
      "linux-x64": {
        asset: "cloudflared-linux-amd64", archive: "binary", executable: "cloudflared",
        sha256: "35fbdd2beb378436c7da377d7358cea8e33f9c94a6705d1d8036bf9b0d6d8005",
        files: { cloudflared: "35fbdd2beb378436c7da377d7358cea8e33f9c94a6705d1d8036bf9b0d6d8005" },
      },
      "linux-arm64": {
        asset: "cloudflared-linux-arm64", archive: "binary", executable: "cloudflared",
        sha256: "b7e55b4d9702c2ab5f8348f780bb1db044527fc555367714c78e0595750a4665",
        files: { cloudflared: "b7e55b4d9702c2ab5f8348f780bb1db044527fc555367714c78e0595750a4665" },
      },
      "win32-x64": {
        asset: "cloudflared-windows-amd64.exe", archive: "binary", executable: "cloudflared.exe",
        sha256: "12c7c887f8aaab779aef1dfa9b60673530a5adb88ecc55dd6df8f56e0b70f199",
        files: { "cloudflared.exe": "12c7c887f8aaab779aef1dfa9b60673530a5adb88ecc55dd6df8f56e0b70f199" },
      },
    } as Record<string, NetworkAsset>,
  },
} as const;

export type BinaryKind = "singBox" | "xray" | "cloudflared";
export type Binaries = Partial<Record<BinaryKind, string>>;
export type CoreUpdateChannel = "stable" | "preview";
export interface CoreRelease {
  tool: BinaryKind;
  version: string;
  tag: string;
  platform: string;
  prerelease: boolean;
  source: "bundled" | "github";
  downloadUrl: string;
  releaseUrl: string;
  asset: NetworkAsset;
}
export type CoreReleaseCandidate = Omit<CoreRelease, "asset"> & {
  asset: Omit<NetworkAsset, "files"> & { files?: Record<string, string> };
};
export type CoreReleaseMap = Record<BinaryKind, CoreRelease>;
export interface CoreSelectionState {
  schema: 1;
  active: CoreReleaseMap;
  previous?: CoreReleaseMap;
  updatedAt?: string;
}
export interface CoreUpdateCheck {
  tool: BinaryKind;
  current: CoreRelease;
  latest?: CoreReleaseCandidate;
  updateAvailable: boolean;
  error?: string;
}

const networkCoreKinds: readonly BinaryKind[] = ["singBox", "xray", "cloudflared"];
const networkCoreRepositories: Record<BinaryKind, string> = {
  singBox: "SagerNet/sing-box", xray: "XTLS/Xray-core", cloudflared: "cloudflare/cloudflared",
};
const networkCorePlatforms = ["linux-x64", "linux-arm64", "win32-x64"];
const networkVersionPattern = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const networkSha256Pattern = /^[a-f0-9]{64}$/;

export function coreReleaseLabel(tool: BinaryKind): string {
  return tool === "singBox" ? "sing-box" : tool === "xray" ? "Xray" : "cloudflared";
}

function networkVersion(value: unknown): string {
  if (typeof value !== "string" || value.length > 80 || !networkVersionPattern.test(value)) throw new Error("内核版本号格式无效。");
  return value;
}

/** Numeric release ordering, including SemVer prerelease identifiers. Never lexically sort dates. */
export function compareCoreVersions(left: string, right: string): number {
  const parse = (value: string): { core: number[]; suffix: string[] } => {
    const checked = networkVersion(value), dash = checked.indexOf("-");
    return { core: (dash < 0 ? checked : checked.slice(0, dash)).split(".").map(Number), suffix: dash < 0 ? [] : checked.slice(dash + 1).split(".") };
  };
  const a = parse(left), b = parse(right);
  for (let i = 0; i < 3; i++) if (a.core[i] !== b.core[i]) return a.core[i]! > b.core[i]! ? 1 : -1;
  if (!a.suffix.length || !b.suffix.length) return a.suffix.length ? -1 : b.suffix.length ? 1 : 0;
  for (let i = 0; i < Math.max(a.suffix.length, b.suffix.length); i++) {
    const aa = a.suffix[i], bb = b.suffix[i];
    if (aa === undefined || bb === undefined) return aa === undefined ? -1 : 1;
    if (aa === bb) continue;
    const an = /^\d+$/.test(aa), bn = /^\d+$/.test(bb);
    if (an && bn) { const ai = BigInt(aa), bi = BigInt(bb); if (ai !== bi) return ai > bi ? 1 : -1; }
    else if (an !== bn) return an ? -1 : 1;
    else return aa > bb ? 1 : -1;
  }
  return 0;
}

function networkCoreTag(tool: BinaryKind, version: string): string { return tool === "cloudflared" ? version : `v${version}`; }

function networkCoreLayout(tool: BinaryKind, version: string, platform: string): Omit<NetworkAsset, "sha256" | "files"> {
  if (!networkCorePlatforms.includes(platform)) throw new Error(`没有适配 ${platform} 的官方内核发行包。`);
  const windows = platform === "win32-x64", arch = platform === "linux-arm64" ? "arm64" : "amd64";
  if (tool === "singBox") {
    const directory = `sing-box-${version}-${windows ? "windows" : "linux"}-${arch}`;
    return { asset: `${directory}.${windows ? "zip" : "tar.gz"}`, archive: windows ? "zip" : "tar.gz", directory, executable: windows ? "sing-box.exe" : "sing-box" };
  }
  if (tool === "xray") return { asset: windows ? "Xray-windows-64.zip" : platform === "linux-arm64" ? "Xray-linux-arm64-v8a.zip" : "Xray-linux-64.zip", archive: "zip", directory: "", executable: windows ? "xray.exe" : "xray" };
  return { asset: `cloudflared-${windows ? "windows" : "linux"}-${arch}${windows ? ".exe" : ""}`, archive: "binary", executable: windows ? "cloudflared.exe" : "cloudflared" };
}

function networkSafeReleaseFile(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name) && !name.endsWith(".") && !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(name);
}

function networkValidateFiles(value: unknown, executable: string, archive: NetworkAsset["archive"]): Record<string, string> {
  const object = networkObject(value, "内核文件校验清单"), entries = Object.entries(object);
  if (!entries.length || entries.length > 128) throw new Error("内核文件校验清单为空或过大。");
  const seen = new Set<string>();
  const files: Record<string, string> = {};
  for (const [name, hash] of entries) {
    if (!networkSafeReleaseFile(name) || seen.has(name.toLowerCase()) || typeof hash !== "string" || !networkSha256Pattern.test(hash)) throw new Error("内核文件名或 SHA-256 校验值无效。");
    seen.add(name.toLowerCase()); files[name] = hash;
  }
  if (!Object.hasOwn(files, executable) || (archive !== "binary" && !Object.hasOwn(files, "LICENSE"))) throw new Error("内核文件清单缺少可执行文件或许可证。");
  if (archive === "binary" && entries.length !== 1) throw new Error("单文件发行包的校验清单无效。");
  return files;
}

function networkValidateCandidate(value: unknown, requireFiles = false): CoreReleaseCandidate {
  const object = networkObject(value, "内核版本"), tool = object.tool as BinaryKind;
  if (!networkCoreKinds.includes(tool)) throw new Error("内核名称无效。");
  const version = networkVersion(object.version), tag = networkCoreTag(tool, version);
  const platform = object.platform;
  if (typeof platform !== "string" || !networkCorePlatforms.includes(platform)) throw new Error("内核平台无效。");
  if (object.source !== "bundled" && object.source !== "github") throw new Error("内核版本来源无效。");
  if (object.tag !== tag || typeof object.prerelease !== "boolean") throw new Error("内核发行标签无效。");
  const releaseUrl = `https://github.com/${networkCoreRepositories[tool]}/releases/tag/${tag}`;
  let layout = networkCoreLayout(tool, version, platform);
  // The bundled manifest is also a public fixture seam used to validate Windows ZIPs on Linux.
  // Actual user-selected GitHub releases always use the canonical platform layout above.
  const bundled = NETWORK_RELEASES[tool];
  if (object.source === "bundled" && version === bundled.version && bundled.assets[platform]) {
    const { sha256: _hash, files: _files, ...bundledLayout } = bundled.assets[platform]!;
    layout = bundledLayout;
  }
  const assetObject = networkObject(object.asset, "内核发行文件");
  for (const key of ["asset", "archive", "directory", "executable"] as const) if (assetObject[key] !== layout[key]) throw new Error("内核发行文件不符合官方平台目录布局。");
  const downloadUrl = `https://github.com/${networkCoreRepositories[tool]}/releases/download/${tag}/${layout.asset}`;
  if (object.downloadUrl !== downloadUrl || object.releaseUrl !== releaseUrl) throw new Error("内核下载地址必须是对应官方仓库的固定发行文件。");
  if (typeof assetObject.sha256 !== "string" || !networkSha256Pattern.test(assetObject.sha256)) throw new Error("内核发行包缺少有效 SHA-256 校验值。");
  const files = assetObject.files === undefined && !requireFiles ? undefined : networkValidateFiles(assetObject.files, layout.executable, layout.archive);
  if (object.source === "bundled" && version === bundled.version) {
    const pinned = bundled.assets[platform]!;
    if (assetObject.sha256 !== pinned.sha256 || (files && (Object.keys(files).length !== Object.keys(pinned.files).length || Object.entries(pinned.files).some(([name, hash]) => files[name] !== hash)))) throw new Error("内置版本的 SHA-256 必须与脚本中已验证的官方清单一致。");
  }
  return { tool, version, tag, platform, prerelease: object.prerelease, source: object.source, downloadUrl, releaseUrl, asset: { ...layout, sha256: assetObject.sha256, ...(files ? { files } : {}) } };
}

function networkBundledCoreMap(): CoreReleaseMap {
  const platform = `${process.platform}-${process.arch}`;
  return Object.fromEntries(networkCoreKinds.map(tool => {
    const release = NETWORK_RELEASES[tool], asset = release.assets[platform];
    if (!asset) throw new Error(`没有适配 ${platform} 的固定官方 ${tool} 发行包。`);
    return [tool, { tool, version: release.version, tag: networkCoreTag(tool, release.version), platform,
      prerelease: release.prerelease, source: "bundled", downloadUrl: release.base + asset.asset, releaseUrl: release.release,
      asset: { ...asset, files: { ...asset.files } } } satisfies CoreRelease];
  })) as CoreReleaseMap;
}

function networkValidateCoreMap(value: unknown): CoreReleaseMap {
  const object = networkObject(value, "内核版本集合");
  if (Object.keys(object).length !== networkCoreKinds.length) throw new Error("内核版本集合必须包含三种内核。");
  const platform = `${process.platform}-${process.arch}`;
  return Object.fromEntries(networkCoreKinds.map(tool => {
    const release = networkValidateCandidate(object[tool], true) as CoreRelease;
    if (release.tool !== tool || release.platform !== platform) throw new Error("内核版本集合与本机平台或内核名称不一致。");
    return [tool, release];
  })) as CoreReleaseMap;
}

function networkValidateSelection(value: unknown): CoreSelectionState {
  const object = networkObject(value, "内核版本记录");
  if (object.schema !== 1) throw new Error("不支持此内核版本记录格式。");
  if (object.updatedAt !== undefined && (typeof object.updatedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(object.updatedAt) || !Number.isFinite(Date.parse(object.updatedAt)))) throw new Error("内核更新时间无效。");
  return { schema: 1, active: networkValidateCoreMap(object.active), ...(object.previous === undefined ? {} : { previous: networkValidateCoreMap(object.previous) }), ...(object.updatedAt === undefined ? {} : { updatedAt: object.updatedAt as string }) };
}

export function coreSelectionPath(paths: AppPaths): string { return networkPath.join(paths.bin, "core-versions.json"); }

/** Local selection is protected like node configuration. Archive hashes come from the official API;
 * extracted file hashes are recorded only after those archive hashes have been verified. */
export function readCoreSelection(paths: AppPaths): CoreSelectionState {
  const file = coreSelectionPath(paths);
  let stat: networkFs.Stats;
  try { stat = networkFs.lstatSync(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { schema: 1, active: networkBundledCoreMap() }; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 256 * 1024) throw new Error("内核版本记录不是普通文件或大小异常，已停止读取。");
  try { return networkValidateSelection(JSON.parse(networkFs.readFileSync(file, "utf8"))); }
  catch (error) { throw new Error(`内核版本记录无效，请从备份恢复 ${file}：${error instanceof Error ? error.message : String(error)}`); }
}

export function writeCoreSelection(paths: AppPaths, state: CoreSelectionState): void {
  const checked = networkValidateSelection(state);
  ensureDataDir(paths);
  const file = coreSelectionPath(paths);
  try { const stat = networkFs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("拒绝覆盖异常内核版本记录。"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  atomicWrite(file, JSON.stringify(checked, null, 2) + "\n");
}

/** Shared by initial pin snapshots and explicit upgrade/rollback transactions. */
export function acquireCoreSelectionLock(paths: AppPaths): () => void {
  ensureDataDir(paths);
  const file = networkPath.join(paths.data, "core-update-lock.sqlite");
  for (const name of [file, `${file}-journal`, `${file}-wal`, `${file}-shm`]) {
    try {
      const stat = networkFs.lstatSync(name);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("内核更新锁不能是链接或特殊文件。");
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  const db = new networkSqlite.Database(file, { create: true });
  try {
    db.exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;");
    if (process.platform !== "win32") networkFs.chmodSync(file, 0o600);
  } catch (error) {
    db.close();
    if (/busy|locked/i.test(error instanceof Error ? error.message : String(error))) throw new Error("同一数据目录已有内核更新或回退正在进行，请等待其结束。");
    throw error;
  }
  let released = false;
  return () => { if (released) return; released = true; try { db.exec("ROLLBACK;"); } finally { db.close(); } };
}

/** Freeze first-use defaults so a later script update cannot silently switch core versions.
 * Read-only menus and explicit candidate preparation do not call this initializer. */
export function initializeCoreSelection(paths: AppPaths): CoreSelectionState {
  const file = coreSelectionPath(paths);
  const exists = (): boolean => { try { networkFs.lstatSync(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; } };
  if (exists()) return readCoreSelection(paths);
  const release = acquireCoreSelectionLock(paths);
  try {
    if (exists()) return readCoreSelection(paths);
    const initial = readCoreSelection(paths); writeCoreSelection(paths, initial); return initial;
  } finally { release(); }
}

export function coreReleaseFingerprint(releases: CoreReleaseMap): string {
  const values = networkCoreKinds.map(tool => {
    const release = releases[tool];
    return [tool, release.version, release.tag, release.platform, release.source, release.prerelease, release.downloadUrl, release.releaseUrl,
      release.asset.asset, release.asset.archive, release.asset.directory ?? null, release.asset.executable, release.asset.sha256,
      Object.entries(release.asset.files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)];
  });
  return networkCrypto.createHash("sha256").update(JSON.stringify(values)).digest("hex");
}

export function coreBinaryPath(paths: AppPaths, release: CoreRelease): string {
  const checked = networkValidateCandidate(release, true) as CoreRelease;
  const suffix = checked.source === "github" ? `-${checked.asset.sha256.slice(0, 16)}` : "";
  return networkPath.join(paths.bin, `${checked.tool}-${checked.version}-${checked.platform}${suffix}`, checked.asset.executable);
}

async function networkGitHubJson(apiPath: string): Promise<unknown> {
  const response = await fetch(`https://api.github.com/${apiPath}`, {
    headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "NexusEdge-core-updater" },
    signal: AbortSignal.timeout(25_000), redirect: "error",
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel().catch(() => {});
    if (response.status === 403 || response.status === 429) throw new Error("GitHub 暂时限制更新查询，请稍后重试；现有版本不受影响。");
    throw new Error(`官方版本查询失败：HTTP ${response.status}。`);
  }
  const limit = 16 * 1024 * 1024;
  if (Number(response.headers.get("content-length")) > limit) { await response.body.cancel(); throw new Error("官方版本列表超过大小限制。"); }
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > limit) throw new Error("官方版本列表超过大小限制。");
      chunks.push(value);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new Error("官方版本查询没有返回有效 JSON。"); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

function networkReleaseVersion(metadata: unknown): string | null {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
  const object = metadata as Record<string, unknown>;
  if (object.draft !== false || typeof object.prerelease !== "boolean" || typeof object.tag_name !== "string") return null;
  const version = object.tag_name.replace(/^v/, "");
  return version.length <= 80 && networkVersionPattern.test(version) ? version : null;
}

function networkCandidateFromMetadata(tool: BinaryKind, metadata: unknown): CoreReleaseCandidate {
  const object = networkObject(metadata, "官方发行信息"), version = networkReleaseVersion(object);
  if (!version) throw new Error("官方发行尚未公开或版本标签不受支持。");
  const platform = `${process.platform}-${process.arch}`, tag = networkCoreTag(tool, version), layout = networkCoreLayout(tool, version, platform);
  if (object.tag_name !== tag || !Array.isArray(object.assets)) throw new Error("官方发行标签或资产列表无效。");
  const matches = object.assets.filter(asset => asset && typeof asset === "object" && (asset as Record<string, unknown>).name === layout.asset) as Record<string, unknown>[];
  if (matches.length !== 1) throw new Error(`官方 ${version} 没有唯一的 ${platform} 发行包（${layout.asset}）。`);
  const asset = matches[0]!, digest = asset.digest;
  if (typeof digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("官方发行包未提供可验证的 SHA-256 digest，已拒绝无校验更新。");
  if (typeof asset.size === "number" && (asset.size <= 0 || asset.size > 160 * 1024 * 1024)) throw new Error("官方发行包大小异常或超过限制。");
  return networkValidateCandidate({ tool, version, tag, platform, prerelease: object.prerelease === true || version.includes("-"), source: "github",
    downloadUrl: asset.browser_download_url, releaseUrl: object.html_url,
    asset: { ...layout, sha256: digest.slice(7) } });
}

/** Advanced explicit version selection; only canonical tags in the three official repositories. */
export async function fetchCoreRelease(tool: BinaryKind, versionOrTag: string): Promise<CoreReleaseCandidate> {
  if (!networkCoreKinds.includes(tool)) throw new Error("内核名称无效。");
  const version = networkVersion(versionOrTag.trim().replace(/^v/, "")), tag = networkCoreTag(tool, version);
  const candidate = networkCandidateFromMetadata(tool, await networkGitHubJson(`repos/${networkCoreRepositories[tool]}/releases/tags/${tag}`));
  if (candidate.tag !== tag) throw new Error("官方返回的发行版本与所选版本不一致。");
  return candidate;
}

/** Version checks are opt-in. Failed or older channels never replace the selected version. */
export async function checkCoreUpdates(paths: AppPaths, channel: CoreUpdateChannel = "stable"): Promise<CoreUpdateCheck[]> {
  if (channel !== "stable" && channel !== "preview") throw new Error("更新通道无效。");
  const selected = readCoreSelection(paths).active;
  return await Promise.all(networkCoreKinds.map(async tool => {
    const current = selected[tool];
    try {
      const metadata = await networkGitHubJson(`repos/${networkCoreRepositories[tool]}/releases${channel === "stable" ? "/latest" : "?per_page=30"}`);
      let chosen: unknown = metadata;
      if (channel === "preview") {
        if (!Array.isArray(metadata)) throw new Error("官方预览版本列表格式无效。");
        const candidates = metadata.map(value => ({ value, version: networkReleaseVersion(value) })).filter(item => item.version !== null);
        candidates.sort((a, b) => compareCoreVersions(b.version!, a.version!));
        if (!candidates.length) throw new Error("官方仓库暂未提供可用发行版本。");
        chosen = candidates[0]!.value;
      }
      const latest = networkCandidateFromMetadata(tool, chosen);
      if (channel === "stable" && latest.prerelease) throw new Error("官方稳定通道返回预览版本，已停止自动选择。");
      return { tool, current, latest, updateAvailable: compareCoreVersions(latest.version, current.version) > 0 };
    } catch (error) { return { tool, current, updateAvailable: false, error: error instanceof Error ? error.message : String(error) }; }
  }));
}

async function networkFileHash(path: string): Promise<string> {
  const digest = networkCrypto.createHash("sha256");
  for await (const chunk of networkFs.createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

async function networkCacheMatches(directory: string, asset: NetworkAsset): Promise<boolean> {
  try {
    const dir = networkFs.lstatSync(directory);
    if (!dir.isDirectory() || dir.isSymbolicLink()) return false;
    const actualNames = networkFs.readdirSync(directory).sort();
    const expectedNames = Object.keys(asset.files).sort();
    if (actualNames.length !== expectedNames.length || actualNames.some((name, index) => name !== expectedNames[index])) return false;
    for (const [name, expected] of Object.entries(asset.files)) {
      const path = networkPath.join(directory, name);
      const file = networkFs.lstatSync(path);
      if (!file.isFile() || file.isSymbolicLink() || await networkFileHash(path) !== expected) return false;
    }
    return true;
  } catch { return false; }
}

async function networkDownload(url: string, path: string, expectedHash: string): Promise<void> {
  const response = await fetch(url, { signal: AbortSignal.timeout(120_000), redirect: "follow" });
  if (!response.ok || !response.body) throw new Error(`官方下载失败：HTTP ${response.status}`);
  const maxBytes = 160 * 1024 * 1024;
  if (Number(response.headers.get("content-length")) > maxBytes) {
    await response.body.cancel();
    throw new Error("下载文件超过本版本的大小限制。");
  }
  const fd = networkFs.openSync(path, "wx", 0o600);
  const reader = response.body.getReader();
  const digest = networkCrypto.createHash("sha256");
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error("下载文件超过本版本的大小限制。");
      digest.update(value);
      let offset = 0;
      while (offset < value.byteLength) offset += networkFs.writeSync(fd, value, offset, value.byteLength - offset);
    }
    networkFs.fsyncSync(fd);
    if (digest.digest("hex") !== expectedHash) throw new Error("下载文件 SHA-256 与官方发行包不符，已拒绝安装。");
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
    networkFs.closeSync(fd);
  }
}

/** Official archives are flat under a known root. Reject new/ambiguous layouts instead of
 * extracting paths, links, devices, or undeclared executable dependencies outside that root. */
function networkArchiveTarget(sourceName: string, directory: string | undefined, isDirectory: boolean): string | null {
  const source = sourceName.startsWith("./") ? sourceName.slice(2) : sourceName;
  if (source.includes("\\") || source.includes("\0") || source.startsWith("/")) throw new Error("发行包包含不安全的路径。");
  if (isDirectory) {
    const root = source.replace(/\/$/, "");
    if (!root || root === "." || root === (directory ?? "")) return null;
    throw new Error("发行包目录布局已变化，暂不支持此版本。");
  }
  const prefix = directory ? `${directory}/` : "";
  if (!source.startsWith(prefix)) throw new Error("发行包文件位于预期目录之外。");
  const target = source.slice(prefix.length);
  if (!networkSafeReleaseFile(target)) throw new Error("发行包包含不安全或不支持的文件路径。");
  return target;
}

interface NetworkArchiveCollector {
  files: Record<string, string>;
  write(target: string, content: Uint8Array): void;
  finish(): Record<string, string>;
}

function networkArchiveCollector(destination: string, asset: CoreReleaseCandidate["asset"]): NetworkArchiveCollector {
  const files: Record<string, string> = {}, seen = new Set<string>();
  let total = 0;
  return {
    files,
    write(target, content) {
      if (seen.has(target.toLowerCase())) throw new Error("发行包包含重复文件名。");
      seen.add(target.toLowerCase());
      if (seen.size > 128 || content.byteLength > 256 * 1024 * 1024 || (total += content.byteLength) > 512 * 1024 * 1024) throw new Error("解压文件数量或大小超过限制。");
      // Bundled/previous selections authenticate an exact manifest. Unselected
      // files in a known pinned archive are ignored, never placed beside the core.
      if (asset.files && !Object.hasOwn(asset.files, target)) return;
      const hash = networkCrypto.createHash("sha256").update(content).digest("hex");
      if (asset.files && hash !== asset.files[target]) throw new Error("解压文件 SHA-256 不匹配。");
      atomicWrite(networkPath.join(destination, target), content);
      files[target] = hash;
    },
    finish() {
      if (asset.files && Object.keys(files).length !== Object.keys(asset.files).length) throw new Error("发行包未包含完整的官方文件清单。");
      return networkValidateFiles(files, asset.executable, asset.archive);
    },
  };
}

/** No unzip command dependency on Windows. Only flat, regular, bounded files are written. */
function networkExtractZip(archive: string, destination: string, asset: CoreReleaseCandidate["asset"]): Record<string, string> {
  const data = networkFs.readFileSync(archive), collector = networkArchiveCollector(destination, asset);
  let end = -1;
  for (let at = data.length - 22; at >= Math.max(0, data.length - 65557); at--) {
    if (data.readUInt32LE(at) === 0x06054b50 && at + 22 + data.readUInt16LE(at + 20) === data.length) { end = at; break; }
  }
  if (end < 0 || data.readUInt16LE(end + 4) || data.readUInt16LE(end + 6)) throw new Error("不支持此 ZIP 分卷或目录格式。");
  const count = data.readUInt16LE(end + 10);
  if (count === 65535 || count !== data.readUInt16LE(end + 8)) throw new Error("不支持 ZIP64 / 分卷发行包。");
  const centralSize = data.readUInt32LE(end + 12);
  let at = data.readUInt32LE(end + 16);
  const centralEnd = at + centralSize;
  if (centralEnd > end || count > 256) throw new Error("ZIP 中央目录范围或文件数量无效。");
  for (let index = 0; index < count; index++) {
    if (at + 46 > centralEnd || data.readUInt32LE(at) !== 0x02014b50) throw new Error("ZIP 中央目录条目无效。");
    const flags = data.readUInt16LE(at + 8), method = data.readUInt16LE(at + 10);
    const compressed = data.readUInt32LE(at + 20), uncompressed = data.readUInt32LE(at + 24);
    const nameLength = data.readUInt16LE(at + 28), extraLength = data.readUInt16LE(at + 30), commentLength = data.readUInt16LE(at + 32);
    const next = at + 46 + nameLength + extraLength + commentLength;
    if (next > centralEnd) throw new Error("ZIP 文件名范围无效。");
    const sourceName = data.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    const unixType = (data.readUInt32LE(at + 38) >>> 16) & 0o170000;
    const isDirectory = sourceName.endsWith("/");
    if (unixType !== 0 && unixType !== (isDirectory ? 0o040000 : 0o100000)) throw new Error("ZIP 发行包包含链接或特殊文件。");
    const target = networkArchiveTarget(sourceName, asset.directory, isDirectory);
    if (target !== null) {
      if ((flags & 1) || ![0, 8].includes(method) || uncompressed > 256 * 1024 * 1024) throw new Error("ZIP 发行文件加密、压缩方式不受支持或过大。");
      const local = data.readUInt32LE(at + 42);
      if (local + 30 > at || data.readUInt32LE(local) !== 0x04034b50 || data.readUInt16LE(local + 8) !== method || data.readUInt16LE(local + 6) !== flags) throw new Error("ZIP 文件头无效。");
      const nameBytes = data.readUInt16LE(local + 26), extraBytes = data.readUInt16LE(local + 28);
      const begin = local + 30 + nameBytes + extraBytes;
      if (begin + compressed > at || data.subarray(local + 30, local + 30 + nameBytes).toString("utf8") !== sourceName) throw new Error("ZIP 文件数据范围无效。");
      const bytes = data.subarray(begin, begin + compressed);
      const content = method === 8 ? networkZlib.inflateRawSync(bytes, { maxOutputLength: Math.max(1, uncompressed) }) : bytes;
      if (content.length !== uncompressed) throw new Error("ZIP 解压后的文件大小不一致。");
      collector.write(target, content);
    }
    at = next;
  }
  if (at !== centralEnd) throw new Error("ZIP 中央目录大小无效。");
  return collector.finish();
}

/** The current official Linux sing-box archive uses ordinary ustar headers. */
function networkExtractTar(archive: string, destination: string, asset: CoreReleaseCandidate["asset"]): Record<string, string> {
  const data = networkZlib.gunzipSync(networkFs.readFileSync(archive), { maxOutputLength: 512 * 1024 * 1024 });
  const collector = networkArchiveCollector(destination, asset);
  const field = (header: Buffer, offset: number, length: number): string => header.subarray(offset, offset + length).toString("utf8").split("\0")[0]!;
  const octal = (text: string): number => {
    const value = text.trim(); if (!/^[0-7]+$/.test(value)) throw new Error("TAR 数字字段不受支持。");
    const number = Number.parseInt(value, 8); if (!Number.isSafeInteger(number)) throw new Error("TAR 数字超出范围。"); return number;
  };
  let at = 0, count = 0, ended = false;
  for (; at + 512 <= data.length;) {
    const header = data.subarray(at, at + 512);
    if (header.every(byte => byte === 0)) { ended = true; break; }
    if (++count > 256) throw new Error("TAR 文件数量超过限制。");
    let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i]!;
    if (octal(field(header, 148, 8)) !== sum) throw new Error("TAR 文件头校验失败。");
    const size = octal(field(header, 124, 12)), type = header[156];
    if (size > 256 * 1024 * 1024 || at + 512 + size > data.length) throw new Error("TAR 文件范围或大小无效。");
    if (type !== 0 && type !== 48 && type !== 53) throw new Error("TAR 发行包包含链接、特殊文件或不支持的扩展格式。");
    const prefix = field(header, 345, 155), name = field(header, 0, 100);
    const target = networkArchiveTarget(prefix ? `${prefix}/${name}` : name, asset.directory, type === 53);
    if (target !== null) collector.write(target, data.subarray(at + 512, at + 512 + size));
    else if (size !== 0) throw new Error("TAR 目录不应包含文件数据。");
    at += 512 + Math.ceil(size / 512) * 512;
  }
  if (!ended || !data.subarray(at).every(byte => byte === 0)) throw new Error("TAR 结束标记或尾部数据无效。");
  return collector.finish();
}

async function networkProbeCoreVersion(executable: string, release: CoreRelease): Promise<void> {
  const result = await runCommand(executable, release.tool === "cloudflared" ? ["--version"] : ["version"], { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`${coreReleaseLabel(release.tool)} ${release.version} 无法在本机运行（版本检查退出码 ${result.code}）。`);
  const output = result.stdout + "\n" + result.stderr;
  const pattern = release.tool === "singBox" ? /^sing-box version\s+(\S+)/im : release.tool === "xray" ? /^Xray\s+(\S+)/im : /^cloudflared version\s+(\S+)/im;
  const actual = output.match(pattern)?.[1]?.replace(/^v/, "");
  if (actual !== release.version) throw new Error(`${coreReleaseLabel(release.tool)} 返回的实际版本与所选 ${release.version} 不符，已拒绝切换。`);
}

async function networkInstallRelease(paths: AppPaths, selected: CoreReleaseCandidate, report: (message: string) => void, discoverFiles: boolean): Promise<CoreRelease> {
  assertSupportedPlatform(); ensureDataDir(paths);
  const candidate = networkValidateCandidate(selected, !discoverFiles);
  if (candidate.platform !== `${process.platform}-${process.arch}`) throw new Error("不能安装其他平台的内核版本。");
  const asset = discoverFiles ? { ...candidate.asset, files: undefined } : candidate.asset;
  if (!discoverFiles) {
    const complete = candidate as CoreRelease, executable = coreBinaryPath(paths, complete);
    if (await networkCacheMatches(networkPath.dirname(executable), complete.asset)) {
      if (process.platform !== "win32") networkFs.chmodSync(executable, 0o755);
      return complete;
    }
  }
  report(`下载并校验 ${coreReleaseLabel(candidate.tool)} ${candidate.version}…`);
  const staging = networkFs.mkdtempSync(networkPath.join(paths.bin, `.install-${candidate.tool}-`));
  networkFs.chmodSync(staging, 0o700);
  let backup: string | undefined, destination: string | undefined;
  try {
    const downloadPath = networkPath.join(staging, asset.asset);
    await networkDownload(candidate.downloadUrl, downloadPath, asset.sha256);
    const ready = networkPath.join(staging, "ready"); networkFs.mkdirSync(ready, { mode: 0o700 });
    let files: Record<string, string>;
    if (asset.archive === "binary") {
      files = { [asset.executable]: asset.sha256 };
      if (asset.files && (Object.keys(asset.files).length !== 1 || asset.files[asset.executable] !== asset.sha256)) throw new Error("单文件发行包校验清单与归档不一致。");
      networkFs.renameSync(downloadPath, networkPath.join(ready, asset.executable));
    } else if (asset.archive === "zip") files = networkExtractZip(downloadPath, ready, asset);
    else files = networkExtractTar(downloadPath, ready, asset);
    const complete: CoreRelease = { ...candidate, asset: { ...asset, files } };
    if (!await networkCacheMatches(ready, complete.asset)) throw new Error("解压后的内核文件校验失败，已拒绝安装。");
    const readyExecutable = networkPath.join(ready, asset.executable);
    if (process.platform !== "win32") networkFs.chmodSync(readyExecutable, 0o755);
    // Older bundled snapshots remain valid when a future script changes its
    // default pins. Their saved hashes have configuration-file trust, and a
    // reinstalled historical binary must still report the selected version.
    if (discoverFiles || candidate.source === "github" || candidate.version !== NETWORK_RELEASES[candidate.tool].version) await networkProbeCoreVersion(readyExecutable, complete);
    destination = networkPath.dirname(coreBinaryPath(paths, complete));
    if (await networkCacheMatches(destination, complete.asset)) return complete;
    try {
      const stat = networkFs.lstatSync(destination);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("拒绝替换异常内核目录。");
      backup = `${destination}.old-${networkCrypto.randomUUID()}`;
      networkFs.renameSync(destination, backup);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    try { networkFs.renameSync(ready, destination); }
    catch (error) { if (backup && !networkFs.existsSync(destination)) networkFs.renameSync(backup, destination); throw error; }
    report(`${coreReleaseLabel(candidate.tool)} ${candidate.version} 已校验并安装。`);
    return complete;
  } finally {
    networkFs.rmSync(staging, { recursive: true, force: true });
    if (backup && destination && networkFs.existsSync(destination)) {
      try { networkFs.rmSync(backup, { recursive: true, force: true }); } catch { /* A Windows antivirus may hold a replaced cache file. */ }
    }
  }
}

/** Prepare a separately versioned, verified cache. Does not select it or stop any running core. */
export async function prepareCoreRelease(paths: AppPaths, candidate: CoreReleaseCandidate, report: (message: string) => void = () => {}): Promise<CoreRelease> {
  if (candidate.source !== "github") throw new Error("更新候选必须来自官方 GitHub 发行信息。");
  return await networkInstallRelease(paths, candidate, report, true);
}

/** Validate the selected cache and restore it from the same official archive when necessary. */
export async function ensureSingleCore(paths: AppPaths, release: CoreRelease, report: (message: string) => void = () => {}): Promise<string> {
  return coreBinaryPath(paths, await networkInstallRelease(paths, release, report, false));
}

async function networkInstallAsset(paths: AppPaths, tool: BinaryKind, report: (message: string) => void): Promise<string> {
  return await ensureSingleCore(paths, initializeCoreSelection(paths).active[tool], report);
}

export function requiredBinaries(config: AppConfig): BinaryKind[] {
  const nodes = validateConfig(config).nodes.filter(node => node.enabled);
  const required = new Set<BinaryKind>(nodes.map(nodeEngine));
  if (nodes.some(node => node.tunnel.mode !== "none")) required.add("cloudflared");
  return (["singBox", "xray", "cloudflared"] as BinaryKind[]).filter(tool => required.has(tool));
}

/** An empty collection is a valid saved draft; it does not trigger any downloads. */
export async function ensureBinaries(paths: AppPaths, config: AppConfig, report: (message: string) => void = () => {}, releases?: CoreReleaseMap): Promise<Binaries> {
  const required = requiredBinaries(config);
  assertSupportedPlatform();
  ensureDataDir(paths);
  const selected = releases ? networkValidateCoreMap(releases) : (required.length ? initializeCoreSelection(paths) : readCoreSelection(paths)).active;
  const result = await Promise.allSettled(required.map(tool => ensureSingleCore(paths, selected[tool], report)));
  const failed = result.filter((r): r is PromiseRejectedResult => r.status === "rejected");
  if (failed.length) throw new Error(failed.map(r => r.reason instanceof Error ? r.reason.message : String(r.reason)).join("\n"));
  return Object.fromEntries(required.map((tool, index) => [tool, (result[index] as PromiseFulfilledResult<string>).value])) as Binaries;
}

function networkNodeTag(node: NodeConfig): string { return `node:${node.id}`; }
function networkPemLines(value: string): string[] { return value.trim().split(/\r?\n/); }
function networkHostPort(host: string, port: number): string { return `${networkNet.isIP(host) === 6 ? `[${host}]` : host}:${port}`; }

function networkSingTls(node: NodeConfig): Record<string, unknown> | undefined {
  if (node.tls.mode === "none") return undefined;
  const tls: Record<string, unknown> = { enabled: true };
  if (node.tls.serverName) tls.server_name = node.tls.serverName;
  if (node.tls.alpn.length) tls.alpn = node.tls.alpn;
  if (node.tls.mode === "reality") {
    const r = node.tls.reality;
    tls.reality = { enabled: true, handshake: { server: r.handshakeServer, server_port: r.handshakePort }, private_key: r.privateKey, short_id: [r.shortId] };
  } else {
    tls.certificate = networkPemLines(node.tls.certificatePem);
    tls.key = networkPemLines(node.tls.keyPem);
  }
  return tls;
}

function networkSingTransport(node: NodeConfig): Record<string, unknown> | undefined {
  if (node.transport.type === "ws") return { type: "ws", path: node.transport.path };
  if (node.transport.type === "grpc") return { type: "grpc", service_name: node.transport.serviceName };
  return undefined;
}

function networkSingInbound(node: NodeConfig): Record<string, unknown> {
  const inbound: Record<string, unknown> = { type: node.protocol, tag: networkNodeTag(node), listen: node.listen, listen_port: node.port };
  switch (node.protocol) {
    case "vmess": inbound.users = [{ uuid: node.uuid, alterId: 0 }]; break;
    case "shadowsocks": inbound.method = node.method; inbound.password = node.password; break;
    case "trojan": case "anytls": inbound.users = [{ password: node.password }]; break;
    case "hysteria2":
      inbound.users = [{ password: node.password }];
      if (node.hy2.upMbps) inbound.up_mbps = node.hy2.upMbps;
      if (node.hy2.downMbps) inbound.down_mbps = node.hy2.downMbps;
      if (node.hy2.obfsPassword) inbound.obfs = { type: "salamander", password: node.hy2.obfsPassword };
      break;
    case "tuic":
      inbound.users = [{ uuid: node.uuid, password: node.password }];
      inbound.congestion_control = node.tuic.congestionControl;
      inbound.zero_rtt_handshake = node.tuic.zeroRttHandshake;
      break;
    case "socks": case "naive":
      inbound.users = [{ username: node.username, password: node.password }];
      // Naive HTTP/2 uses TCP. HTTP/3 would require an additional UDP listener.
      if (node.protocol === "naive") inbound.network = "tcp";
      break;
    default: throw new Error(`sing-box 不负责 ${node.protocol} 节点。`);
  }
  const tls = networkSingTls(node);
  const transport = networkSingTransport(node);
  if (tls) inbound.tls = tls;
  if (transport) inbound.transport = transport;
  return inbound;
}

export function buildSingBoxConfig(config: AppConfig): object | null {
  const c = validateConfig(config);
  const nodes = c.nodes.filter(node => node.enabled && nodeEngine(node) === "singBox");
  if (!nodes.length) return null;
  const warpTags = nodes.filter(node => node.egress === "warp").map(networkNodeTag);
  const generated: Record<string, unknown> = {
    log: { level: "warn", timestamp: true },
    dns: { servers: [{ type: "local", tag: "dns-local" }], final: "dns-local" },
    inbounds: nodes.map(networkSingInbound), outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct", default_domain_resolver: "dns-local" },
  };
  if (warpTags.length) {
    const w = c.warp!;
    generated.dns = { servers: [
      { type: "local", tag: "dns-local" },
      { type: "udp", tag: "dns-warp", server: "1.1.1.1", server_port: 53, detour: "warp-out" },
    ], final: "dns-local" };
    generated.endpoints = [{
      type: "wireguard", tag: "warp-out", system: false, mtu: 1280,
      address: w.addresses, private_key: w.privateKey, domain_resolver: "dns-local",
      peers: [{ address: w.endpointHost, port: w.endpointPort, public_key: w.peerPublicKey,
        allowed_ips: ["0.0.0.0/0", "::/0"], persistent_keepalive_interval: 25, reserved: w.reserved }],
    }];
    generated.route = { final: "direct", default_domain_resolver: "dns-local", rules: [
      { inbound: warpTags, action: "resolve", server: "dns-warp" },
      { inbound: warpTags, action: "route", outbound: "warp-out" },
    ] };
  }
  return generated;
}

function networkXrayInbound(node: NodeConfig): Record<string, unknown> {
  const stream: Record<string, unknown> = { network: node.transport.type, security: node.tls.mode };
  if (node.transport.type === "ws") stream.wsSettings = { path: node.transport.path };
  if (node.transport.type === "grpc") stream.grpcSettings = { serviceName: node.transport.serviceName };
  if (node.transport.type === "xhttp") stream.xhttpSettings = { path: node.transport.path, mode: node.transport.mode };
  if (node.tls.mode === "tls") {
    stream.tlsSettings = { ...(node.tls.serverName ? { serverName: node.tls.serverName } : {}),
      ...(node.tls.alpn.length ? { alpn: node.tls.alpn } : {}),
      certificates: [{ certificate: networkPemLines(node.tls.certificatePem), key: networkPemLines(node.tls.keyPem) }] };
  } else if (node.tls.mode === "reality") {
    const r = node.tls.reality;
    stream.realitySettings = { target: networkHostPort(r.handshakeServer, r.handshakePort), serverNames: [node.tls.serverName], privateKey: r.privateKey, shortIds: [r.shortId] };
  }
  return { tag: networkNodeTag(node), listen: node.listen, port: node.port, protocol: "vless",
    settings: { clients: [{ id: node.uuid, ...(node.flow ? { flow: node.flow } : {}) }], decryption: node.vlessDecryption }, streamSettings: stream };
}

export function buildXrayConfig(config: AppConfig): object | null {
  const c = validateConfig(config);
  const nodes = c.nodes.filter(node => node.enabled && nodeEngine(node) === "xray");
  if (!nodes.length) return null;
  const warpTags = nodes.filter(node => node.egress === "warp").map(networkNodeTag);
  const outbounds: Record<string, unknown>[] = [{ tag: "direct", protocol: "freedom", settings: { domainStrategy: "AsIs" } }];
  const generated: Record<string, unknown> = { log: { loglevel: "warning" }, inbounds: nodes.map(networkXrayInbound), outbounds };
  if (warpTags.length) {
    const w = c.warp!;
    outbounds.push({ tag: "warp-out", protocol: "wireguard", settings: {
      secretKey: w.privateKey, address: w.addresses, mtu: 1280, noKernelTun: true, reserved: w.reserved, domainStrategy: "ForceIP",
      peers: [{ publicKey: w.peerPublicKey, endpoint: networkHostPort(w.endpointHost, w.endpointPort), allowedIPs: ["0.0.0.0/0", "::/0"], keepAlive: 25 }],
    } });
    // The native WireGuard outbound resolves targets through the built-in DNS.
    // Resolve ONLY the peer hostname using system DNS, avoiding a recursive
    // attempt to establish WARP by sending its own bootstrap lookup over WARP.
    generated.dns = { tag: "warp-dns", queryStrategy: "UseIP", disableFallbackIfMatch: true, servers: [
      ...(!networkNet.isIP(w.endpointHost) ? [{ address: "localhost", domains: [`full:${w.endpointHost}`], skipFallback: true }] : []),
      { address: "1.1.1.1", port: 53 },
    ] };
    generated.routing = { domainStrategy: "AsIs", rules: [
      { type: "field", inboundTag: ["warp-dns"], outboundTag: "warp-out" },
      { type: "field", inboundTag: warpTags, outboundTag: "warp-out" },
    ] };
  }
  return generated;
}

function networkSafeNodeId(nodeId: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(nodeId)) throw new Error("节点 ID 不能用于隧道文件名。");
  return nodeId;
}
export function cloudflaredTokenPath(paths: AppPaths, nodeId: string): string { return networkPath.join(paths.data, `cloudflared-${networkSafeNodeId(nodeId)}.token`); }
export function cloudflaredConfigPath(paths: AppPaths, nodeId: string): string { return networkPath.join(paths.data, `cloudflared-${networkSafeNodeId(nodeId)}.yaml`); }

export function buildCloudflaredArgs(node: NodeConfig, paths: AppPaths, metricsPort: number): string[] {
  const n = validateNode(node);
  if (n.tunnel.mode === "none") throw new Error("此节点没有启用隧道。");
  if (!Number.isInteger(metricsPort) || metricsPort < 1024 || metricsPort > 65535) throw new Error("cloudflared 指标端口无效。");
  const args = [
    "tunnel", "--config", cloudflaredConfigPath(paths, n.id), "--no-autoupdate",
    // Quick tunnels otherwise override the unset default to QUIC, disabling fallback.
    "--protocol", n.tunnel.protocol, "--edge-ip-version", "auto",
    "--metrics", `127.0.0.1:${metricsPort}`, "--loglevel", "info", "--output", "json",
  ];
  const origin = n.listen === "0.0.0.0" ? "127.0.0.1" : n.listen === "::" ? "::1" : n.listen;
  return n.tunnel.mode === "fixed"
    ? [...args, "run", "--token-file", cloudflaredTokenPath(paths, n.id)]
    : [...args, "--url", `http://${networkHostPort(origin, n.port)}`];
}

/** Check all selected cores before publishing any generated runtime configuration. */
export async function preflightCores(paths: AppPaths, config: AppConfig, options: { releases?: CoreReleaseMap; publish?: boolean; report?: (message: string) => void } = {}): Promise<Binaries> {
  const c = validateConfig(config);
  if (!c.nodes.some(node => node.enabled)) throw new Error("没有启用的节点；请先创建或启用至少一个节点。");
  const binaries = await ensureBinaries(paths, c, options.report, options.releases);
  const jobs: { tool: "singBox" | "xray"; path: string; candidate: string; text: string }[] = [];
  for (const [tool, path, generated] of [
    ["singBox", paths.singConfig, buildSingBoxConfig(c)], ["xray", paths.xrayConfig, buildXrayConfig(c)],
  ] as const) if (generated) jobs.push({ tool, path, candidate: `${path}.${networkCrypto.randomUUID()}.candidate.json`, text: JSON.stringify(generated, null, 2) + "\n" });
  try {
    for (const job of jobs) atomicWrite(job.candidate, job.text);
    const checks = await Promise.allSettled(jobs.map(async job => {
      const executable = binaries[job.tool]!;
      const args = job.tool === "singBox" ? ["check", "-c", job.candidate] : ["run", "-test", "-config", job.candidate];
      const result = await runCommand(executable, args, { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
      if (result.code !== 0) {
        const detail = redact((result.stderr || result.stdout).trim(), collectConfigSecrets(c)).slice(-1500);
        throw new Error(`${job.tool === "singBox" ? "sing-box" : "Xray"} 配置检查失败：${detail || `退出码 ${result.code}`}`);
      }
    }));
    const errors = checks.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    if (errors.length) throw new Error(errors.map(error => error.reason instanceof Error ? error.reason.message : String(error.reason)).join("\n"));
    if (options.publish !== false) {
      for (const job of jobs) atomicWrite(job.path, job.text);
      for (const node of c.nodes) {
        if (node.enabled && node.tunnel.mode !== "none") {
          // Isolate each connector from other cloudflared installations/configs.
          atomicWrite(cloudflaredConfigPath(paths, node.id), "{}\n");
          if (node.tunnel.mode === "fixed") atomicWrite(cloudflaredTokenPath(paths, node.id), node.tunnel.token + "\n");
          else networkFs.rmSync(cloudflaredTokenPath(paths, node.id), { force: true });
        }
      }
    }
    return binaries;
  } finally { for (const job of jobs) networkFs.rmSync(job.candidate, { force: true }); }
}

export async function generateSelfSignedCertificate(paths: AppPaths, node: NodeConfig): Promise<{ certificatePem: string; keyPem: string }> {
  // This is deliberately usable by the wizard before its TLS draft is complete.
  assertSupportedPlatform();
  ensureDataDir(paths);
  const engine = nodeEngine(node);
  const executable = await networkInstallAsset(paths, engine, () => {});
  const requestedName = node.tls.serverName || node.address || "localhost";
  const name = requestedName === "localhost" ? "localhost" : normalizeConnectAddress(requestedName);
  if (!name || /[\u0000-\u0020\u007f]/.test(name)) throw new Error("自签证书需要有效的 Server Name / 地址。");
  const args = engine === "xray" ? ["tls", "cert", `--domain=${name}`, "--expire=8760h"] : ["generate", "tls-keypair", name, "--months", "12"];
  const result = await runCommand(executable, args, { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`${engine === "xray" ? "Xray" : "sing-box"} 生成自签证书失败（退出码 ${result.code}）。`);
  let certificatePem = "", keyPem = "";
  if (engine === "xray") {
    const generated = JSON.parse(result.stdout) as { certificate?: unknown; key?: unknown };
    if (Array.isArray(generated.certificate) && generated.certificate.every(line => typeof line === "string")) certificatePem = generated.certificate.join("\n") + "\n";
    if (Array.isArray(generated.key) && generated.key.every(line => typeof line === "string")) keyPem = generated.key.join("\n") + "\n";
  } else {
    certificatePem = (result.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0] ?? "") + "\n";
    keyPem = (result.stdout.match(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----/)?.[0] ?? "") + "\n";
  }
  try {
    const certificate = new networkCrypto.X509Certificate(certificatePem);
    let key: networkCrypto.KeyObject | undefined;
    try { key = networkCrypto.createPrivateKey(keyPem); }
    catch {
      // Xray v26.3.27 emits an EC key with a historical RSA PEM label. Go accepts
      // that label; OpenSSL-based runtimes do not. Parse its actual DER structure
      // and normalize below instead of carrying the misleading header forward.
      const encoded = keyPem.replace(/-----[^\n]+-----/g, "").replace(/\s/g, "");
      const der = Buffer.from(encoded, "base64");
      for (const type of ["pkcs8", "sec1", "pkcs1"] as const) {
        try { key = networkCrypto.createPrivateKey({ key: der, format: "der", type }); break; } catch { /* Try the next standard DER envelope. */ }
      }
    }
    if (!key) throw new Error("unrecognized private key");
    if (!certificate.checkPrivateKey(key)) throw new Error("mismatched key");
    keyPem = key.export({ format: "pem", type: "pkcs8" }).toString();
  } catch { throw new Error("内核没有返回有效且相互匹配的 PEM 证书和私钥。"); }
  return { certificatePem, keyPem };
}

export async function generateVlessEncryption(paths: AppPaths): Promise<{ vlessEncryption: string; vlessDecryption: string }> {
  assertSupportedPlatform();
  ensureDataDir(paths);
  const executable = await networkInstallAsset(paths, "xray", () => {});
  const result = await runCommand(executable, ["vlessenc"], { cwd: networkPath.dirname(executable), timeoutMs: 20_000 });
  if (result.code !== 0) throw new Error(`Xray 生成 VLESS ENC 失败（退出码 ${result.code}）。`);
  const section = result.stdout.split("Authentication: ML-KEM-768")[1];
  const encryption = section?.match(/"encryption"\s*:\s*"([^"\r\n]+)"/)?.[1];
  const decryption = section?.match(/"decryption"\s*:\s*"([^"\r\n]+)"/)?.[1];
  if (!encryption || !decryption) throw new Error("Xray 没有返回完整配对的 ML-KEM-768 ENC 参数。");
  return { vlessEncryption: encryption, vlessDecryption: decryption };
}

function networkObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} 缺失或不是对象。`);
  return value as Record<string, unknown>;
}

function networkReserved(value: unknown, clientId?: unknown): number[] {
  if (value !== undefined) {
    if (typeof value === "string") {
      const text = value.trim();
      if (text.startsWith("[")) value = JSON.parse(text);
      else {
        const fields = text.split(",").map(v => v.trim());
        if (fields.some(field => !/^\d{1,3}$/.test(field))) throw new Error("Reserved 必须是三个 0–255 整数。");
        value = fields.map(Number);
      }
    }
    if (!Array.isArray(value) || value.length !== 3 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error("Reserved 必须是三个 0–255 整数。");
    return [...value] as number[];
  }
  if (clientId !== undefined) {
    if (typeof clientId !== "string" || !/^[A-Za-z0-9+/]{4}$/.test(clientId)) throw new Error("WARP client_id 必须是准确三个字节的 Base64，不能截断或补零。");
    const decoded = Buffer.from(clientId, "base64");
    if (decoded.length !== 3 || decoded.toString("base64") !== clientId) throw new Error("WARP client_id 编码无效。");
    return Array.from(decoded);
  }
  // A standard wgcf-profile.conf cannot express the non-standard reserved bytes.
  // Its ordinary WireGuard behavior is zero. An explicit Reserved/JSON overrides it.
  return [0, 0, 0];
}

function networkEndpoint(value: unknown, fallbackPort = 2408): { endpointHost: string; endpointPort: number } {
  if (typeof value !== "string" || !value.trim()) throw new Error("WARP Endpoint 缺失。");
  const text = value.trim();
  let endpointHost = text;
  let endpointPort = fallbackPort;
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(text);
  if (bracketed) {
    if (networkNet.isIP(bracketed[1]!) !== 6) throw new Error("Endpoint 方括号内必须是 IPv6 地址。");
    endpointHost = bracketed[1]!;
    if (bracketed[2]) endpointPort = Number(bracketed[2]);
  } else if (networkNet.isIP(text) !== 6 && text.includes(":")) {
    const hostPort = /^([^:]+):(\d+)$/.exec(text);
    if (!hostPort) throw new Error("Endpoint 应为 host:port 或 [IPv6]:port。");
    endpointHost = hostPort[1]!; endpointPort = Number(hostPort[2]);
  }
  return { endpointHost, endpointPort };
}

function networkAddresses(value: unknown): string[] {
  const entries = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(entries)) throw new Error("WARP 地址列表缺失。");
  return entries.map(entry => {
    if (typeof entry !== "string") throw new Error("WARP 地址必须为文本。");
    const address = entry.trim();
    if (address.includes("/")) return address;
    const family = networkNet.isIP(address);
    if (!family) throw new Error("WARP 地址必须是 IPv4/IPv6，不能使用域名。");
    return `${address}/${family === 4 ? 32 : 128}`;
  });
}

function networkRegistrationProfile(value: unknown, privateKey: string): WarpProfile {
  const root = networkObject(value, "WARP 注册响应");
  if (root.tunnel_type !== undefined && root.tunnel_type !== "wireguard") throw new Error("注册接口没有返回 WireGuard 配置。");
  if (root.key_type !== undefined && root.key_type !== "curve25519") throw new Error("注册接口没有返回 Curve25519 密钥类型。");
  const config = networkObject(root.config, "WARP config");
  const iface = networkObject(config.interface, "WARP interface");
  const addresses = networkObject(iface.addresses, "WARP addresses");
  if (!Array.isArray(config.peers) || !config.peers.length) throw new Error("WARP 响应没有 peer。");
  const peer = networkObject(config.peers[0], "WARP peer");
  const endpoint = networkObject(peer.endpoint, "WARP peer endpoint");
  const ports = Array.isArray(endpoint.ports) ? endpoint.ports : [];
  const fallbackPort = ports.length ? Number(ports[0]) : 2408;
  const parsed = networkEndpoint(endpoint.host || endpoint.v4 || endpoint.v6, fallbackPort);
  // Current API responses may omit host and provide v4/v6 plus a separate ports
  // array. Match wgcf: in that form the ports array, not a stale address suffix,
  // selects the port. A complete endpoint.host still takes precedence.
  if (!endpoint.host) parsed.endpointPort = fallbackPort;
  if (config.client_id === undefined) throw new Error("WARP 注册响应缺少 client_id，不能确认 Reserved。");
  return validateWarpProfile({
    privateKey, addresses: networkAddresses([addresses.v4, addresses.v6].filter(v => typeof v === "string" && v)),
    peerPublicKey: peer.public_key, ...parsed, reserved: networkReserved(undefined, config.client_id),
  });
}

async function networkReadRegistration(response: Response): Promise<string> {
  if (!response.body) throw new Error("WARP 注册响应为空。");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024 * 1024) throw new Error("WARP 注册响应超过大小限制。");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Accept NexusEdge JSON, a sing-box WireGuard endpoint, or a standard WG profile. */
export function parseWarpProfile(text: string): WarpProfile {
  if (text.length > 1024 * 1024) throw new Error("WARP 配置文件超过 1 MiB。");
  const input = text.replace(/^\uFEFF/, "").trim();
  if (!input) throw new Error("WARP 配置为空。");
  if (input.startsWith("{")) {
    const data = networkObject(JSON.parse(input), "WARP JSON");
    if (data.config && (typeof data.privateKey === "string" || typeof data.private_key === "string")) {
      return networkRegistrationProfile(data, String(data.privateKey ?? data.private_key));
    }
    if (data.privateKey !== undefined) return validateWarpProfile({ ...data, reserved: networkReserved(data.reserved, data.client_id) });
    if (Array.isArray(data.peers)) {
      if (data.peers.length !== 1) throw new Error("仅支持单 peer 的 WARP 配置。");
      const peer = networkObject(data.peers[0], "WireGuard peer");
      return validateWarpProfile({
        privateKey: data.private_key, addresses: networkAddresses(data.address), peerPublicKey: peer.public_key,
        ...networkEndpoint(peer.address, Number(peer.port ?? 2408)), reserved: networkReserved(peer.reserved, data.client_id),
      });
    }
    return validateWarpProfile({
      privateKey: data.private_key, addresses: networkAddresses(data.local_address ?? data.addresses),
      peerPublicKey: data.peer_public_key,
      ...networkEndpoint(data.server ?? data.endpoint, Number(data.server_port ?? 2408)),
      reserved: networkReserved(data.reserved, data.client_id),
    });
  }
  // An optional trailing JSON object may carry reserved or a registration client_id.
  const suffixAt = input.search(/^\s*\{/m);
  const wgText = suffixAt < 0 ? input : input.slice(0, suffixAt);
  const metadata = suffixAt < 0 ? {} : networkObject(JSON.parse(input.slice(suffixAt)), "附加 WARP JSON");
  const metadataConfig = metadata.config ? networkObject(metadata.config, "附加 WARP config") : {};
  const iface = new Map<string, string>();
  const peer = new Map<string, string>();
  let section = "";
  let peerCount = 0;
  let commentReserved: string | undefined;
  for (const rawLine of wgText.split(/\r?\n/)) {
    const reservedComment = /^\s*[#;]\s*Reserved\s*=\s*(.+)$/i.exec(rawLine);
    if (reservedComment) commentReserved = reservedComment[1];
    const line = rawLine.replace(/\s*[#;].*$/, "").trim();
    if (!line) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.toLowerCase();
      if (section === "peer" && ++peerCount > 1) throw new Error("仅支持单 peer 的 WARP 配置。");
      continue;
    }
    const field = /^([^=]+)=(.*)$/.exec(line);
    if (!field) throw new Error("WireGuard 配置有无法识别的行。");
    const key = field[1]!.trim().toLowerCase();
    const target = section === "interface" ? iface : section === "peer" ? peer : undefined;
    if (!target) throw new Error("WireGuard 字段必须位于 [Interface] 或 [Peer]。");
    if (target.has(key)) throw new Error(`WireGuard 配置包含重复字段 ${key}。`);
    target.set(key, field[2]!.trim());
  }
  if (peerCount !== 1) throw new Error("WireGuard 配置必须包含一个 [Peer]。");
  return validateWarpProfile({
    privateKey: iface.get("privatekey"), addresses: networkAddresses(iface.get("address")),
    peerPublicKey: peer.get("publickey"), ...networkEndpoint(peer.get("endpoint")),
    reserved: networkReserved(peer.get("reserved") ?? iface.get("reserved") ?? commentReserved ?? metadata.reserved, metadata.client_id ?? metadataConfig.client_id),
  });
}

/** Best-effort compatibility registration, only called after the user's explicit action.
 * This is Cloudflare's client endpoint, NOT a supported public Cloudflare API.
 * Reference: ViRb3/wgcf commit 803310a27bf040ac831b74cf3b4b993482f48647.
 * wgcf also uses a custom TLS fingerprint; Bun fetch may be rejected by the service.
 * Never substitute shared credentials or silently switch an enabled WARP to direct.
 */
export async function registerWarp(): Promise<WarpProfile> {
  const pair = networkCrypto.generateKeyPairSync("x25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  if (!privateJwk.d || !publicJwk.x) throw new Error("当前 Bun 无法生成 X25519 WireGuard 密钥，请升级 Bun。");
  const privateKey = Buffer.from(privateJwk.d, "base64url").toString("base64");
  const publicKey = Buffer.from(publicJwk.x, "base64url").toString("base64");
  let response: Response;
  try {
    response = await fetch("https://api.cloudflareclient.com/v0a5641/reg", {
      method: "POST", signal: AbortSignal.timeout(25_000), redirect: "error",
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
        "CF-Client-Version": "a-6.38.9-5641",
      },
      body: JSON.stringify({
        key: publicKey, key_type: "curve25519", tunnel_type: "wireguard", os_version: "16.0.0",
        install_id: "", fcm_token: "", tos: new Date().toISOString(), model: "PC", serial_number: "", locale: "en_US",
      }),
    });
  } catch {
    throw new Error("WARP 兼容注册请求失败或超时。此接口可能限制普通客户端请求，请使用已有的 WireGuard/WARP 配置导入；未启用 WARP。");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`WARP 兼容注册失败（HTTP ${response.status}）。该接口不保证第三方调用可用，请导入已有配置；未启用 WARP。`);
  }
  if (Number(response.headers.get("content-length")) > 1024 * 1024) {
    await response.body?.cancel();
    throw new Error("WARP 注册响应异常，已拒绝保存。");
  }
  try {
    const data = networkObject(JSON.parse(await networkReadRegistration(response)), "WARP 注册响应");
    if (data.key !== undefined && data.key !== publicKey) throw new Error("WARP 注册响应的公钥不匹配。");
    return networkRegistrationProfile(data, privateKey);
  }
  catch {
    // Never include an upstream response here: it may contain account tokens.
    throw new Error("WARP 响应没有完整、有效的 WireGuard 地址、peer 或 Reserved。未保存也未启用；可导入已有配置。");
  }
}
