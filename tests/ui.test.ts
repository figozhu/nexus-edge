import { expect, test } from "bun:test";
import { selectMenu } from "../src/ui.ts";

/** 非 TTY 子进程输入完整一行，检查字母序号及回车默认值，不创建配置文件。 */
for (const [count, input, initial, selected] of [[11, "J\n", 0, 9], [33, "aa\n", 0, 26], [11, "\n", 10, 10]] as const) {
  test(`非 TTY ${count} 项输入 ${JSON.stringify(input)} 返回 ${selected}`, () => {
    const moduleUrl = new URL("../src/ui.ts", import.meta.url).href;
    const source = `import { selectMenu } from ${JSON.stringify(moduleUrl)}; console.log('RESULT=' + await selectMenu('测试', '', Array.from({length:${count}}, (_, i) => String(i)), ${initial}));`;
    const child = Bun.spawnSync([process.execPath, "-e", source], { stdin: Buffer.from(input), stdout: "pipe", stderr: "pipe" });
    expect(child.exitCode).toBe(0);
    expect(child.stdout.toString()).toContain(`RESULT=${selected}`);
  });
}

test("空菜单明确报错而不挂起", async () => {
  await expect(selectMenu("空菜单", "", [])).rejects.toThrow("至少需要一个选项");
});
