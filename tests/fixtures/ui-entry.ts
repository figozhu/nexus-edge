/** PTY-only fixture. It calls no panel, network, daemon, or startup entry points. */
import * as uiFixtureCrypto from "node:crypto";
import { selectMenu, promptInput, UserCancelledError, UiExitRequestedError } from "../../src/ui.ts";

globalThis.fetch = (async () => { throw new Error("The UI PTY fixture must never access the network."); }) as unknown as typeof fetch;

function uiFixtureTrace(event: string, value: Record<string, unknown> = {}): void {
  process.stdout.write(`\r\n__NEXUS_PTY__${JSON.stringify({ event, ...value, raw: Boolean(process.stdin.isRaw), keypressListeners: process.stdin.listenerCount("keypress") })}\r\n`);
}

async function uiFixtureCancelled(action: () => Promise<unknown>, event: string, exitRequested = false): Promise<void> {
  try {
    const value = await action();
    throw new Error(`Cancellation resolved a selection instead: ${JSON.stringify(value)}`);
  } catch (error) {
    if (!(exitRequested ? error instanceof UiExitRequestedError : error instanceof UserCancelledError)) throw error;
    uiFixtureTrace(event, { cancelled: true, exitRequested });
  }
}

async function uiFixtureMain(): Promise<void> {
  const scenario = process.argv[2];
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("This fixture must run under a real PTY.");
  uiFixtureTrace("start", { scenario, stdinTTY: process.stdin.isTTY, stdoutTTY: process.stdout.isTTY });
  switch (scenario) {
    case "cycles": {
      for (let round = 1; round <= 3; round++) {
        const selected = await selectMenu(`循环菜单 ${round}`, "菜单与 readline 输入切换测试", ["填写", "备用", "第三项"]);
        uiFixtureTrace("selected", { round, selected });
        const text = await promptInput(`中文输入 ${round}`);
        uiFixtureTrace("input", { round, text });
        const returned = await selectMenu(`返回菜单 ${round}`, "重复进入菜单", ["继续", "另一个选项", "返回"]);
        uiFixtureTrace("returned", { round, selected: returned });
      }
      break;
    }
    case "secret": {
      const text = await promptInput("请输入测试密钥", "", { secret: true });
      uiFixtureTrace("secret", { length: Array.from(text).length, sha256: uiFixtureCrypto.createHash("sha256").update(text).digest("hex") });
      const visible = await promptInput("请输入可见中文");
      uiFixtureTrace("visible", { text: visible });
      break;
    }
    case "ctrlc": {
      await uiFixtureCancelled(() => selectMenu("CtrlC 菜单", "Ctrl+C 应取消并恢复终端", ["一", "二", "三"]), "menu-cancelled", true);
      const text = await promptInput("菜单取消后输入");
      uiFixtureTrace("after-menu-cancel", { text });
      await uiFixtureCancelled(() => promptInput("CtrlC 密钥输入", "", { secret: true }), "input-cancelled", true);
      const selected = await selectMenu("取消后的菜单", "键盘仍应正常响应", ["继续", "结束"]);
      uiFixtureTrace("after-input-cancel", { selected });
      break;
    }
    case "escape": {
      await uiFixtureCancelled(() => selectMenu("协议选择测试", "Esc 不能隐式选择最后的 QUIC", ["自动", "HTTP2", "QUIC"]), "escape-cancelled");
      const text = await promptInput("Esc 取消后输入");
      uiFixtureTrace("after-escape", { text });
      break;
    }
    default: throw new Error(`Unknown PTY scenario: ${scenario}`);
  }
  uiFixtureTrace("done", { scenario });
  process.stdin.pause();
}

try { await uiFixtureMain(); }
catch (error) {
  uiFixtureTrace("failure", { message: error instanceof Error ? error.message : String(error) });
  process.exitCode = 1;
}
