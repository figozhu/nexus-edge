import * as uiReadline from "node:readline";
import * as uiStream from "node:stream";
import { APP_VERSION, errorMessage } from "./core.ts";

export class UserCancelledError extends Error { constructor() { super("已取消当前操作。"); } }
export class UiExitRequestedError extends Error { constructor() { super("已退出管理面板。"); } }
const uiAnsi = { reset: "\x1b[0m", cyan: "\x1b[36m", green: "\x1b[32m", yellow: "\x1b[33m", dim: "\x1b[2m", bold: "\x1b[1m" };
let uiKeyEventsInitialized = false;

/** Raw mode is scoped to one menu. Every exit path restores the cursor and stdin. */
export async function selectMenu(title: string, information: string, choices: string[], initial = 0): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(`\n${title}\n${information}`);
    choices.forEach((item, index) => console.log(`${index + 1}. ${item}`));
    for (;;) {
      const answer = await promptInput("输入选项编号", String(initial + 1));
      const n = Number(answer);
      if (Number.isInteger(n) && n >= 1 && n <= choices.length) return n - 1;
      console.log("请输入列表中的编号。");
    }
  }
  if (!uiKeyEventsInitialized) { uiReadline.emitKeypressEvents(process.stdin); uiKeyEventsInitialized = true; }
  return new Promise((resolve, reject) => {
    let selected = Math.min(Math.max(initial, 0), choices.length - 1);
    const wasRaw = Boolean(process.stdin.isRaw);
    const render = () => {
      process.stdout.write("\x1b[2J\x1b[H\x1b[?25l");
      console.log(`${uiAnsi.bold}${uiAnsi.cyan}NexusEdge ${APP_VERSION}${uiAnsi.reset}\n`);
      if (information) console.log(information + "\n");
      console.log(`${uiAnsi.bold}${title}${uiAnsi.reset}\n`);
      choices.forEach((choice, index) => console.log(index === selected ? `${uiAnsi.cyan}  › ${index + 1}. ${choice}${uiAnsi.reset}` : `    ${index + 1}. ${choice}`));
      console.log(`\n${uiAnsi.dim}↑/↓ 或 j/k 选择 · Enter 确定 · 数字直接选择${choices.length === 10 ? "（0 选第 10 项）" : ""} · Esc 返回 · Ctrl+C 退出面板${uiAnsi.reset}`);
    };
    const cleanup = () => {
      process.stdin.removeListener("keypress", onKey);
      process.stdin.removeListener("end", onEnd);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\x1b[?25h");
    };
    const onEnd = () => { cleanup(); reject(new UserCancelledError()); };
    const onKey = (text: string, key: uiReadline.Key) => {
      if (key.ctrl && key.name === "c") { cleanup(); reject(new UiExitRequestedError()); return; }
      if (key.name === "escape") { cleanup(); reject(new UserCancelledError()); return; }
      if (key.name === "up" || key.name === "k") selected = (selected + choices.length - 1) % choices.length;
      else if (key.name === "down" || key.name === "j") selected = (selected + 1) % choices.length;
      else if (key.name === "return") { cleanup(); resolve(selected); return; }
      else if (/^[1-9]$/.test(text) && Number(text) <= choices.length) { cleanup(); resolve(Number(text) - 1); return; }
      else if (text === "0" && choices.length === 10) { cleanup(); resolve(9); return; }
      else return;
      render();
    };
    process.stdin.on("keypress", onKey);
    process.stdin.once("end", onEnd);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    render();
  });
}

class UiMutedOutput extends uiStream.Writable {
  _write(_chunk: unknown, _encoding: string, callback: (error?: Error | null) => void): void { callback(); }
}

export async function promptInput(label: string, current = "", options: { secret?: boolean; clearable?: boolean } = {}): Promise<string> {
  const display = options.secret && current ? "已设置，回车保留" : current;
  const hint = [display ? `[${display}]` : "", options.clearable ? "输入 - 清除" : ""].filter(Boolean).join("；");
  return new Promise((resolve, reject) => {
    const hidden = Boolean(options.secret && process.stdin.isTTY);
    const output = hidden ? new UiMutedOutput() : process.stdout;
    const rl = uiReadline.createInterface({ input: process.stdin, output, terminal: Boolean(process.stdin.isTTY) });
    let answered = false;
    const cancel = () => { if (!answered) { answered = true; rl.close(); reject(new UiExitRequestedError()); } };
    rl.once("SIGINT", cancel);
    rl.once("close", () => { if (!answered) { answered = true; reject(new UserCancelledError()); } });
    const prompt = `${label}${hint ? `（${hint}）` : ""}：`;
    if (hidden) process.stdout.write(prompt);
    process.stdin.resume();
    rl.question(hidden ? "" : prompt, answer => {
      answered = true; rl.close();
      if (hidden) process.stdout.write("\n");
      const trimmed = answer.trim();
      resolve(options.clearable && trimmed === "-" ? "" : trimmed || current);
    });
  });
}

export async function uiPause(): Promise<void> { await promptInput("按 Enter 返回面板"); }

export async function uiValidatedInput(label: string, current: string, validate: (value: string) => string, options: { secret?: boolean; clearable?: boolean } = {}): Promise<string> {
  for (;;) {
    const value = await promptInput(label, current, options);
    try { return validate(value); }
    catch (e) { console.log(`输入有误：${errorMessage(e)}`); }
  }
}

