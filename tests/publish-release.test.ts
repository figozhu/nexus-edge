import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
const { publishRelease } = require("../scripts/publish-release.cjs");
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

/** 创建完全离线的 GitHub API 替身和九个测试附件，记录每次写入用于验证发布顺序。 */
function environment(options: { release?: object; tag?: object; uploadFails?: boolean; assets?: object[] } = {}) {
  const root = mkdtempSync(join(tmpdir(), "nexus-publish-test-")); roots.push(root);
  writeFileSync(join(root, "package.json"), JSON.stringify({ version: "3.0.0" }));
  const directory = join(root, "dist", "release"); mkdirSync(directory, { recursive: true });
  for (const name of ["SHA256SUMS", ...Array.from({ length: 8 }, (_, i) => `asset-${i}`)]) writeFileSync(join(directory, name), "fixture");
  const writes: { operation: string; args: any }[] = [];
  /** 模拟不存在的 API 对象，保留与 Octokit 一致的 status 字段。 */
  const missing = () => { throw Object.assign(new Error("Not Found"), { status: 404 }); };
  /** 记录模拟写入；可注入附件上传失败，验证草稿不能被错误公开。 */
  const operation = (name: string) => async (args: any) => {
    writes.push({ operation: name, args });
    if (name === "upload" && options.uploadFails) throw new Error("上传失败");
    return { data: { id: 1, html_url: "https://example.test/release", ...args } };
  };
  const github = { rest: {
    repos: {
      getReleaseByTag: async () => options.release ? { data: options.release } : missing(),
      createRelease: operation("create"), updateRelease: operation("publish"),
      listReleaseAssets: async () => ({ data: [] }), deleteReleaseAsset: operation("delete"), uploadReleaseAsset: operation("upload"),
    },
    git: { getRef: async () => options.tag ? { data: { object: options.tag } } : missing(), getTag: async () => missing() },
  }, paginate: async () => options.assets ?? [] };
  return { root, github, context: { eventName: "push", ref: "refs/heads/main", sha: "commit-300", repo: { owner: "test", repo: "test" } }, core: { info: () => {} }, writes };
}

test("main 推送创建固定提交的版本，九个附件上传后才公开", async () => {
  const env = environment();
  expect(await publishRelease(env)).toMatchObject({ skipped: false, tag: "v3.0.0" });
  expect(env.writes[0]).toMatchObject({ operation: "create", args: { tag_name: "v3.0.0", target_commitish: "commit-300", draft: true } });
  expect(env.writes.filter(item => item.operation === "upload")).toHaveLength(9);
  expect(env.writes.at(-1)).toMatchObject({ operation: "publish", args: { draft: false } });
});
test("同版本后续推送不覆盖已公开 Release", async () => {
  const env = environment({ release: { id: 1, draft: false } });
  expect(await publishRelease(env)).toMatchObject({ skipped: true });
  expect(env.writes).toHaveLength(0);
});
test("上传失败保留草稿，不能执行公开操作", async () => {
  const env = environment({ uploadFails: true });
  await expect(publishRelease(env)).rejects.toThrow("上传失败");
  expect(env.writes.some(item => item.operation === "publish")).toBe(false);
});
test("同提交草稿可清理部分附件并重试", async () => {
  const env = environment({ release: { id: 1, draft: true, target_commitish: "commit-300" }, assets: [{ id: 8, name: "asset-0" }] });
  await publishRelease(env);
  expect(env.writes[0]).toMatchObject({ operation: "delete", args: { asset_id: 8 } });
  expect(env.writes.some(item => item.operation === "create")).toBe(false);
  expect(env.writes.at(-1)?.operation).toBe("publish");
});
test("另一个提交的草稿或标签都拒绝，不执行写操作", async () => {
  for (const options of [{ release: { id: 1, draft: true, target_commitish: "other" } }, { tag: { type: "commit", sha: "other" } }]) {
    const env = environment(options);
    await expect(publishRelease(env)).rejects.toThrow("另一");
    expect(env.writes).toHaveLength(0);
  }
});
test("非 main、错误标签和手动触发都不能发布", async () => {
  for (const context of [{ ref: "refs/heads/feature" }, { ref: "refs/tags/v9.0.0" }, { eventName: "workflow_dispatch" }]) {
    const env = environment(); Object.assign(env.context, context);
    await expect(publishRelease(env)).rejects.toThrow("发布仅允许");
    expect(env.writes).toHaveLength(0);
  }
});
