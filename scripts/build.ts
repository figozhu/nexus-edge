import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { APP_VERSION } from "../src/core.ts";

// 拼接相互隔离的源码模块，保留 TypeScript 类型；相对导入必须保持单行。
// 命名空间导入名称互不冲突，生成的脚本无需 npm 运行时依赖。
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const files = ["core.ts", "address.ts", "presets.ts", "network.ts", "platform.ts", "ipv6.ts", "firewall-linux.ts", "firewall.ts", "firewall-control.ts", "daemon.ts", "migration.ts", "updates.ts", "ui.ts", "uninstall.ts", "ipv6-panel.ts", "firewall-panel.ts", "simple.ts", "core-panel.ts", "panel.ts", "main.ts"];
const parts = files.map(file => {
  const source = readFileSync(join(root, "src", file), "utf8");
  const stripped = source.replace(/^import[^\n]*from ["']\.\/[^"']+["'];?\r?\n/gm, "");
  if (/from\s*["']\.\//.test(stripped)) throw new Error(`Unexpected multiline relative import in ${file}`);
  return `\n// ==================== ${file} ====================\n${stripped}`;
});
const header = `#!/usr/bin/env bun\n/**\n * NexusEdge ${APP_VERSION} — 多协议节点管理，兼容独立程序和 TypeScript 单文件。\n * 运行脚本：bun nexus-edge.ts；独立程序版本无需安装 Bun。\n * 脚本要求 Bun >= 1.4.3；支持 Windows x64 / Linux x64、arm64。\n * 由 scripts/build.ts 从类型化源码生成，不需要 npm 运行时依赖。\n * 操作与验证说明见 README.md。\n */\n`;
writeFileSync(join(root, "nexus-edge.ts"), header + parts.join("\n"));
console.log(`Built ${join(root, "nexus-edge.ts")}`);
