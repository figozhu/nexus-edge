import { chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { APP_VERSION } from "../src/core.ts";

/** 本项目已有内核映射的受支持平台；x64 使用 baseline 兼容较旧 CPU。 */
export const releaseTargets = {
  "windows-x64": { target: "bun-windows-x64-baseline", file: "nexus-edge-windows-x64.exe" },
  "linux-x64": { target: "bun-linux-x64-baseline", file: "nexus-edge-linux-x64" },
  "linux-arm64": { target: "bun-linux-arm64", file: "nexus-edge-linux-arm64" },
} as const;
export type ReleaseTarget = keyof typeof releaseTargets;
const root = resolve(import.meta.dir, "..");

/**
 * 验证源码版本、固定 Bun 和可选 tag，阻止把错误版本发布到同名 release。
 * @param tag 可选 Git 标签；提供时必须精确等于 v + package.json 版本。
 * @returns 当前应用版本；不一致时在生成任何产物前抛错。
 */
export function validateReleaseVersion(tag?: string): string {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const bun = readFileSync(join(root, ".bun-version"), "utf8").trim();
  if (pkg.version !== APP_VERSION) throw new Error("package.json 与 APP_VERSION 不一致。");
  if (Bun.version !== bun) throw new Error(`发布构建需要 Bun ${bun}，当前为 ${Bun.version}。`);
  if (tag !== undefined && tag !== `v${APP_VERSION}`) throw new Error(`发布标签必须为 v${APP_VERSION}，收到 ${tag}。`);
  return APP_VERSION;
}

/**
 * 使用当前固定 Bun 的 CLI 编译一个完整可执行文件并生成 SHA-256。
 * @param id 白名单中的平台名，不接受任意 Bun target 或输出路径。
 * @returns 生成文件的绝对路径。编译失败会保留错误并中止发布。
 */
export async function buildRelease(id: ReleaseTarget): Promise<string> {
  validateReleaseVersion();
  const spec = releaseTargets[id];
  const directory = join(root, "dist", id);
  mkdirSync(directory, { recursive: true });
  const output = join(directory, spec.file);
  const args = ["build", "src/main.ts", "--compile", `--target=${spec.target}`, `--outfile=${output}`,
    "--define", "NEXUS_EDGE_COMPILED=true", "--env=disable", "--no-compile-autoload-dotenv",
    "--no-compile-autoload-bunfig", "--no-compile-autoload-tsconfig", "--no-compile-autoload-package-json"];
  if (id === "windows-x64") args.push("--windows-title=NexusEdge", `--windows-version=${APP_VERSION}.0`);
  const child = Bun.spawn([process.execPath, ...args], { cwd: root, stdout: "inherit", stderr: "inherit" });
  if (await child.exited !== 0) throw new Error(`${id} 编译失败。`);
  if (id !== "windows-x64") chmodSync(output, 0o755);
  const digest = createHash("sha256").update(readFileSync(output)).digest("hex");
  writeFileSync(join(directory, "SHA256SUMS"), `${digest}  ${spec.file}\n`);
  console.log(`已生成 ${output}`);
  return output;
}

/**
 * 解析构建命令；默认构建三平台，--target 允许单平台，--check-tag 只检查版本。
 * @returns 构建全部完成的 Promise；未知参数和缺失参数均拒绝。
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "--check-tag" && args.length === 2) { validateReleaseVersion(args[1]); return; }
  if (args.length && (args.length !== 2 || args[0] !== "--target" || !(args[1]! in releaseTargets))) {
    throw new Error("用法：bun run build:release [--target windows-x64|linux-x64|linux-arm64]");
  }
  validateReleaseVersion();
  const source = Bun.spawn([process.execPath, "scripts/build.ts"], { cwd: root, stdout: "inherit", stderr: "inherit" });
  if (await source.exited !== 0) throw new Error("单文件源码构建失败。");
  const targets = args.length ? [args[1] as ReleaseTarget] : Object.keys(releaseTargets) as ReleaseTarget[];
  for (const id of targets) await buildRelease(id);
  // 同时携带可重构建的完整源码和许可说明，便于审计和替换内嵌运行时。
  const common = join(root, "dist", "common");
  mkdirSync(common, { recursive: true });
  for (const file of ["nexus-edge.ts", "LICENSE", "README.md", "THIRD_PARTY.md", "BUN-LICENSE.md"]) copyFileSync(join(root, file), join(common, file));
}

if (import.meta.main) {
  try { await main(); }
  catch (error) { console.error(`发布构建失败：${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; }
}
