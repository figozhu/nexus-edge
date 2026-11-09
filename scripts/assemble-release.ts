import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { releaseTargets, validateReleaseVersion } from "./build-release.ts";

/**
 * 将三个平台的 CI 产物汇总为唯一发布目录，重新计算并核对每个文件摘要。
 * @param artifactRoot 下载的 artifact 父目录；每个平台使用独立子目录。
 * @returns 发布目录绝对路径。缺失、额外文件或摘要不匹配都中止发布。
 */
export async function assembleRelease(artifactRoot: string): Promise<string> {
  validateReleaseVersion();
  const root = resolve(import.meta.dir, "..");
  const output = join(root, "dist", "release");
  mkdirSync(output, { recursive: true });
  const expected = Object.entries(releaseTargets).map(([id]) => `executable-${id}`).sort();
  if (JSON.stringify(readdirSync(artifactRoot).sort()) !== JSON.stringify(expected)) throw new Error("发布产物集合不完整或含意外目录。");
  const files: string[] = [];
  for (const [id, spec] of Object.entries(releaseTargets)) {
    const directory = join(artifactRoot, `executable-${id}`);
    if (JSON.stringify(readdirSync(directory).sort()) !== JSON.stringify(["SHA256SUMS", spec.file].sort())) throw new Error(`${id} 附件集合不匹配。`);
    const bytes = readFileSync(join(directory, spec.file));
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (readFileSync(join(directory, "SHA256SUMS"), "utf8") !== `${digest}  ${spec.file}\n`) throw new Error(`${id} 摘要验证失败。`);
    copyFileSync(join(directory, spec.file), join(output, spec.file)); files.push(spec.file);
  }
  const build = Bun.spawn([process.execPath, "scripts/build.ts"], { cwd: root, stdout: "inherit", stderr: "inherit" });
  if (await build.exited !== 0) throw new Error("发布源码生成失败。");
  for (const file of ["nexus-edge.ts", "LICENSE", "README.md", "THIRD_PARTY.md", "BUN-LICENSE.md"]) {
    copyFileSync(join(root, file), join(output, file)); files.push(file);
  }
  // 拒绝脏目录中的旧附件；失败时请使用新的构建目录，不自动覆盖或发布未知文件。
  if (readdirSync(output).some(file => ![...files, "SHA256SUMS"].includes(file))) throw new Error("发布目录含旧的或未知附件。");
  writeFileSync(join(output, "SHA256SUMS"), files.sort().map(file => `${createHash("sha256").update(readFileSync(join(output, file))).digest("hex")}  ${file}\n`).join(""));
  console.log(`已验证并汇总 ${files.length} 个发布附件：${output}`);
  return output;
}

if (import.meta.main) {
  try { await assembleRelease(resolve(import.meta.dir, "..", "dist", "artifacts")); }
  catch (error) { console.error(error); process.exitCode = 1; }
}
