import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Concatenate our deliberately isolated modules, preserving TypeScript types.
// Runtime imports are namespace imports with unique names; relative imports are
// single-line imports. No bundler or third-party runtime dependency is required.
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const files = ["core.ts", "address.ts", "presets.ts", "network.ts", "platform.ts", "ipv6.ts", "firewall-linux.ts", "firewall.ts", "firewall-control.ts", "daemon.ts", "migration.ts", "updates.ts", "ui.ts", "ipv6-panel.ts", "firewall-panel.ts", "simple.ts", "core-panel.ts", "panel.ts", "main.ts"];
const parts = files.map(file => {
  const source = readFileSync(join(root, "src", file), "utf8");
  const stripped = source.replace(/^import[^\n]*from ["']\.\/[^"']+["'];?\r?\n/gm, "");
  if (/from\s*["']\.\//.test(stripped)) throw new Error(`Unexpected multiline relative import in ${file}`);
  return `\n// ==================== ${file} ====================\n${stripped}`;
});
const header = `#!/usr/bin/env bun\n/**\n * NexusEdge 2.3.2 — 按需编辑节点、REALITY 单次域名输入与跨平台终端交互。\n * Run: bun nexus-edge.ts\n * Requires Bun >= 1.4.3; Windows x64 / Linux x64, arm64.\n * Generated from the typed source modules using scripts/build.ts.\n * No npm runtime dependencies. See README.md for operation and verification.\n */\n`;
writeFileSync(join(root, "nexus-edge.ts"), header + parts.join("\n"));
console.log(`Built ${join(root, "nexus-edge.ts")}`);
