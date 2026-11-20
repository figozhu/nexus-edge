import { afterEach, describe, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs";
import * as crypto from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { type AppConfig, APP_VERSION, createPaths, defaultConfig, createDefaultNode, ensureDataDir, validateConfig, writeConfig } from "../src/core.ts";
import { BACKUP_FILE_LIMIT, encodeConfigBackup, decodeConfigBackup, exportConfigBackup, prepareConfigImport, commitConfigImport } from "../src/backup.ts";
import { certificatePem, keyPem } from "./fixtures/tls.ts";

const password = "synthetic backup password only";
const directories: string[] = [];
afterEach(() => { for (const dir of directories.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function scratch() { const root = fs.mkdtempSync(join(tmpdir(), "nexus-backup-test-")); directories.push(root); return root; }
function config(): AppConfig {
  const node = createDefaultNode("trojan");
  node.address = "198.51.100.32"; node.listen = "192.0.2.11";
  Object.assign(node.tls, { certificatePem, keyPem, serverName: "node.example.com" });
  const tunnel = createDefaultNode("vless");
  tunnel.port = tunnel.publicPort = 22445; tunnel.listen = "127.0.0.1"; tunnel.address = "node.example.com";
  tunnel.transport.type = "ws"; tunnel.tunnel = { mode: "fixed", domain: "node.example.com", token: "synthetic-tunnel-token-0123456789", connectAddress: "192.0.2.10", protocol: "auto" };
  const reality = createDefaultNode("vless");
  reality.enabled = false; reality.tls.mode = "reality"; reality.tls.serverName = "example.com";
  const pair = crypto.generateKeyPairSync("x25519");
  reality.tls.reality = { privateKey: pair.privateKey.export({ format: "jwk" }).d!, publicKey: pair.publicKey.export({ format: "jwk" }).x!, shortId: "a123b456", handshakeServer: "example.com", handshakePort: 443 };
  return validateConfig({ ...defaultConfig(), nodes: [node, tunnel, reality], coreIpv6: true,
    firewall: { mode: "auto", linuxBackend: "firewalld", firewalldZone: "source-zone" },
    webhook: { kind: "generic", url: "https://example.com/synthetic-webhook-secret" },
    warp: { privateKey: Buffer.alloc(32, 7).toString("base64"), addresses: ["172.16.0.2/32"], peerPublicKey: Buffer.alloc(32, 11).toString("base64"), endpointHost: "engage.cloudflareclient.com", endpointPort: 2408, reserved: [0, 1, 2] },
  }, { allowExpiredCertificate: true });
}
function setup() {
  const root = scratch(), paths = createPaths(join(root, "新服务器", "nexus-edge.ts")), file = join(root, "迁移.nexus-backup");
  writeConfig(paths, defaultConfig());
  exportConfigBackup(config(), file, password);
  return { root, paths, file, before: fs.readFileSync(paths.config) };
}
/** Create authenticated future/invalid payloads to test validation beyond GCM. */
function alteredPayload(change: (payload: any) => void): string {
  const envelope = JSON.parse(encodeConfigBackup(config(), password));
  const key = crypto.scryptSync(password, Buffer.from(envelope.salt, "base64"), 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const aad = Buffer.from(`nexus-edge-backup:1:${envelope.suite}`);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  decipher.setAAD(aad); decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const payload = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, "base64")), decipher.final()]).toString());
  change(payload);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64")); cipher.setAAD(aad);
  envelope.data = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]).toString("base64"); envelope.tag = cipher.getAuthTag().toString("base64"); key.fill(0);
  return JSON.stringify(envelope);
}

describe("portable encrypted configuration", () => {
  test("round trip preserves every portable field, encrypted metadata and credentials", () => {
    const source = config(), text = encodeConfigBackup(source, password), decoded = decodeConfigBackup(text, password);
    expect(decoded.config).toEqual(source); expect(decoded.appVersion).toBe(APP_VERSION);
    for (const secret of [password, source.nodes[0]!.password, keyPem, source.nodes[1]!.uuid, source.nodes[1]!.tunnel.token, source.nodes[2]!.tls.reality.privateKey, source.warp!.privateKey, source.webhook.url, source.nodes[0]!.address]) expect(text).not.toContain(secret);
    expect(encodeConfigBackup(source, password)).not.toBe(text);
  });
  test("new-host import keeps credentials and domains, resets host settings and disables nodes", () => {
    const { paths, file, before } = setup(), original = decodeConfigBackup(fs.readFileSync(file, "utf8"), password).config;
    const preview = prepareConfigImport(paths, file, password);
    expect(fs.readFileSync(paths.config)).toEqual(before);
    expect(preview.config.nodes.every(node => !node.enabled)).toBe(true);
    expect(preview.config.nodes[0]!.address).toBe(""); expect(preview.config.nodes[0]!.listen).toBe("0.0.0.0");
    expect(preview.config.nodes[1]!.address).toBe("node.example.com"); expect(preview.config.nodes[1]!.listen).toBe("127.0.0.1");
    expect(preview.config.nodes[1]!.tunnel.connectAddress).toBe("");
    expect(preview.config.nodes[0]!.tls).toEqual(original.nodes[0]!.tls);
    expect(preview.config.nodes[1]!.tunnel.token).toBe(original.nodes[1]!.tunnel.token);
    expect(preview.config.warp).toEqual(original.warp);
    expect(preview.config.webhook).toEqual({ kind: "none", url: "" }); expect(preview.config.coreIpv6).toBe(false);
    expect(preview.config.firewall).toEqual({ mode: "manual", linuxBackend: "auto", firewalldZone: "" });
    const { recovery } = commitConfigImport(paths, preview);
    expect(fs.readFileSync(recovery!)).toEqual(before);
    expect(JSON.parse(fs.readFileSync(paths.config, "utf8"))).toEqual(preview.config);
    expect(fs.existsSync(paths.log)).toBe(false); expect(fs.existsSync(paths.runtimeState)).toBe(false);
  });
  test("empty fresh destination and repeated imports use independent recovery copies", () => {
    const { root, file } = setup(), paths = createPaths(join(root, "fresh", "nexus-edge.ts"));
    const preview = prepareConfigImport(paths, file, password);
    expect(preview.expected).toBeNull(); expect(fs.existsSync(paths.data)).toBe(false);
    expect(commitConfigImport(paths, preview).recovery).toBeNull();
    const a = commitConfigImport(paths, prepareConfigImport(paths, file, password));
    const b = commitConfigImport(paths, prepareConfigImport(paths, file, password));
    expect(a.recovery).not.toBe(b.recovery); expect(fs.readFileSync(a.recovery!)).toEqual(fs.readFileSync(b.recovery!));
  });
  test("wrong password, corruption, truncation and plaintext imports leave destination untouched", () => {
    const { paths, file, before } = setup(), text = fs.readFileSync(file, "utf8");
    expect(() => prepareConfigImport(paths, file, "incorrect password phrase")).toThrow("密码错误");
    const changed = JSON.parse(text); changed.data = (changed.data.startsWith("A") ? "B" : "A") + changed.data.slice(1);
    for (const bad of [JSON.stringify(changed), text.slice(0, -12), JSON.stringify(config()), "null", "[]"]) {
      fs.writeFileSync(file, bad); expect(() => prepareConfigImport(paths, file, password)).toThrow(); expect(fs.readFileSync(paths.config)).toEqual(before);
    }
  });
  test("unsupported envelope version and untrusted KDF parameters fail before decryption", () => {
    const envelope = JSON.parse(encodeConfigBackup(config(), password));
    for (const change of [{ version: 2 }, { suite: "scrypt-expensive" }, { format: "other-app" }, { N: 2 ** 30 }, { salt: "?" }]) expect(() => decodeConfigBackup(JSON.stringify({ ...envelope, ...change }), password)).toThrow();
  });
  test.each(["schema", "version", "unknown", "missing", "duplicates", "conflict", "secret-error"])("authenticated %s payload fails validation without echoing values", kind => {
    const text = alteredPayload(p => {
      if (kind === "schema") p.config.schema = 99;
      if (kind === "version") p.appVersion = "4.0.0";
      if (kind === "unknown") p.config.nodes[0].tls.futureSecret = "secret-do-not-echo";
      if (kind === "missing") delete p.config.nodes[0].tls;
      if (kind === "duplicates") p.config.nodes.push(p.config.nodes[0]);
      if (kind === "conflict") { p.config.nodes[1].listen = p.config.nodes[0].listen; p.config.nodes[1].port = p.config.nodes[0].port; }
      if (kind === "secret-error") p.config.nodes[0].protocol = "secret-do-not-echo";
    });
    expect(() => decodeConfigBackup(text, password)).toThrow();
    try { decodeConfigBackup(text, password); } catch (error) { expect(String(error)).not.toContain("secret-do-not-echo"); }
  });
  test("weak passwords and existing export destinations are refused without overwrite", () => {
    const { file } = setup(), before = fs.readFileSync(file);
    expect(() => exportConfigBackup(config(), file, "short")).toThrow();
    expect(() => exportConfigBackup(config(), file, password)).toThrow(); expect(fs.readFileSync(file)).toEqual(before);
    expect(() => exportConfigBackup(config(), file + ".json", password)).toThrow();
  });
  test("oversized files and hardlinks are refused", () => {
    const { root, paths, file, before } = setup();
    const big = join(root, "large.nexus-backup"), fd = fs.openSync(big, "wx"); fs.ftruncateSync(fd, BACKUP_FILE_LIMIT + 1); fs.closeSync(fd);
    expect(() => prepareConfigImport(paths, big, password)).toThrow();
    fs.linkSync(file, join(root, "hardlink.nexus-backup")); expect(() => prepareConfigImport(paths, file, password)).toThrow();
    expect(fs.readFileSync(paths.config)).toEqual(before);
  });
  test("concurrent edit after preview is preserved; no stale overwrite", () => {
    const { paths, file } = setup(), preview = prepareConfigImport(paths, file, password);
    const changed = Buffer.from('{"manually":"edited"}\n'); fs.writeFileSync(paths.config, changed);
    expect(() => commitConfigImport(paths, preview)).toThrow("另一处修改"); expect(fs.readFileSync(paths.config)).toEqual(changed);
  });
  test("corrupt original is archived byte for byte; standard .bak remains untouched", () => {
    const { paths, file } = setup(), original = Buffer.from("invalid old config\n");
    fs.writeFileSync(paths.config, original); fs.writeFileSync(paths.config + ".bak", "known-good-backup");
    const { recovery } = commitConfigImport(paths, prepareConfigImport(paths, file, password));
    expect(fs.readFileSync(recovery!)).toEqual(original); expect(fs.readFileSync(paths.config + ".bak", "utf8")).toBe("known-good-backup");
  });
  test.each(["recovery", "staging", "rename"])("failure at %s preserves original bytes and cleans staging/lock", point => {
    const { paths, file, before } = setup(), preview = prepareConfigImport(paths, file, password);
    const originalWrite = fs.writeFileSync, originalRename = fs.renameSync;
    const write = spyOn(fs, "writeFileSync").mockImplementation(((fd: any, ...args: any[]) => {
      const calls = write.mock.calls.length;
      if ((point === "recovery" && calls === 1) || (point === "staging" && calls === 2)) throw new Error("injected disk full");
      return (originalWrite as any)(fd, ...args);
    }) as any);
    const rename = spyOn(fs, "renameSync").mockImplementation(((...args: any[]) => { if (point === "rename") throw new Error("injected rename failure"); return (originalRename as any)(...args); }) as any);
    try { expect(() => commitConfigImport(paths, preview)).toThrow("导入保存失败"); }
    finally { write.mockRestore(); rename.mockRestore(); }
    expect(fs.readFileSync(paths.config)).toEqual(before);
    expect(fs.readdirSync(paths.data).some(name => name.endsWith(".tmp") || name.endsWith(".lock"))).toBe(false);
  });
  test("existing import lock blocks replacement", () => {
    const { paths, file, before } = setup(), preview = prepareConfigImport(paths, file, password);
    fs.writeFileSync(join(paths.data, "config-import.lock"), "");
    expect(() => commitConfigImport(paths, preview)).toThrow("另一个导入"); expect(fs.readFileSync(paths.config)).toEqual(before);
  });
  test.skipIf(process.platform === "win32")("Unix config and recovery have private permissions; symlinks are refused", () => {
    const { root, paths, file } = setup(), preview = prepareConfigImport(paths, file, password), result = commitConfigImport(paths, preview);
    for (const path of [file, paths.config, result.recovery!]) expect(fs.statSync(path).mode & 0o777).toBe(0o600);
    const linked = join(root, "linked.nexus-backup"); fs.symlinkSync(file, linked);
    expect(() => prepareConfigImport(paths, linked, password)).toThrow();
    fs.unlinkSync(paths.config); fs.symlinkSync(result.recovery!, paths.config);
    expect(() => prepareConfigImport(paths, file, password)).toThrow();
  });
});
