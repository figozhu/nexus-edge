import * as uiReadline from "node:readline";
import * as uiStream from "node:stream";
import { APP_VERSION, errorMessage } from "./core.ts";

export class UserCancelledError extends Error { constructor() { super("已取消当前操作。"); } }
export class UiExitRequestedError extends Error { constructor() { super("已退出管理面板。"); } }
const uiAnsi = { reset: "\x1b[0m", cyan: "\x1b[36m", green: "\x1b[32m", yellow: "\x1b[33m", dim: "\x1b[2m", bold: "\x1b[1m" };
let uiKeyEventsInitialized = false;
let uiWindowsInputSession = false;

/**
 * 为一段完整交互管理 Windows TTY 模式，避免菜单之间反复 raw/cooked 切换导致 Bun 停止读键。
 * @param operation 同一交互会话中的异步操作；嵌套会话复用外层，不提前恢复输入。
 * @returns operation 的结果；正常、取消及异常退出都会恢复原始模式并暂停读取。
 * POSIX 和非 TTY 保持原行为。会话之外的 selectMenu 仍恢复每次调用前的模式。
 */
export async function withUiInputSession<T>(operation: () => Promise<T>): Promise<T> {
  if (process.platform !== "win32" || !process.stdin.isTTY || uiWindowsInputSession) return operation();
  const originalRaw = Boolean(process.stdin.isRaw);
  uiWindowsInputSession = true;
  if (!uiKeyEventsInitialized) { uiReadline.emitKeypressEvents(process.stdin); uiKeyEventsInitialized = true; }
  // 菜单及 Readline 有各自的 Ctrl+C 处理器；无交互处理器的等待阶段沿用终端默认退出语义。
  const onIdleKey = (_text: string, key: uiReadline.Key): void => {
    if (key.ctrl && key.name === "c" && process.stdin.listenerCount("keypress") === 1) {
      process.stdin.setRawMode(originalRaw); process.stdout.write("\x1b[?25h"); process.stdin.pause();
      process.exit(130);
    }
  };
  process.stdin.on("keypress", onIdleKey);
  try { return await operation(); }
  finally {
    process.stdin.removeListener("keypress", onIdleKey);
    process.stdin.setRawMode(originalRaw);
    process.stdin.pause();
    uiWindowsInputSession = false;
  }
}

/**
 * 显示菜单并返回选中项的零基索引；initial 为默认项。
 * TTY 每页最多 26 项，字母不区分大小写，方向键跨页移动；非 TTY 输入字母序号后回车。
 * 数字 1–9 保留为当前页前九项的兼容快捷键；j/k 现在分别选择第十/十一项。
 * 所有退出路径均恢复 raw mode、光标和监听器；空菜单直接报错。
 */
export async function selectMenu(title: string, information: string, choices: string[], initial = 0): Promise<number> {
  if (!choices.length) throw new Error("菜单至少需要一个选项。");
  const pageSize = 26;
  const label = (index: number): string => {
    // 非 TTY 的完整列表使用 a…z、aa…az 等序号，输入整行后才解析，不会误选 a。
    let result = "";
    for (let value = index + 1; value > 0; value = Math.floor((value - 1) / 26)) result = String.fromCharCode(97 + (value - 1) % 26) + result;
    return result;
  };
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(`\n${title}\n${information}`);
    choices.forEach((item, index) => console.log(`${label(index)}. ${item}`));
    for (;;) {
      const answer = (await promptInput("输入选项字母", label(initial))).toLowerCase();
      const letterIndex = choices.findIndex((_, index) => label(index) === answer);
      if (letterIndex >= 0) return letterIndex;
      const n = Number(answer);
      if (Number.isInteger(n) && n >= 1 && n <= choices.length) return n - 1;
      console.log("请输入列表中的字母。");
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
      const offset = Math.floor(selected / pageSize) * pageSize;
      choices.slice(offset, offset + pageSize).forEach((choice, local) => console.log(offset + local === selected ? `${uiAnsi.cyan}  › ${label(local)}. ${choice}${uiAnsi.reset}` : `    ${label(local)}. ${choice}`));
      if (choices.length > pageSize) console.log(`\n第 ${Math.floor(selected / pageSize) + 1}/${Math.ceil(choices.length / pageSize)} 页 · ←/→ 或 PageUp/PageDown 翻页`);
      console.log(`\n${uiAnsi.dim}↑/↓ 选择 · Enter 确定 · 字母直接选择（不区分大小写） · Esc 返回 · Ctrl+C 退出面板${uiAnsi.reset}`);
    };
    const cleanup = () => {
      process.stdin.removeListener("keypress", onKey);
      process.stdin.removeListener("end", onEnd);
      if (!uiWindowsInputSession) process.stdin.setRawMode(wasRaw);
      // Bun/Windows 的 TTY 在菜单多次 pause/resume 后可能停止投递 data，
      // 即使 isRaw/flowing 显示正常也无法恢复。保留底层读取，仅释放事件循环引用；
      // 下一次菜单/输入框重新 ref，应用最终退出时由 main 统一 pause。
      if (process.platform === "win32") process.stdin.unref();
      else process.stdin.pause();
      process.stdout.write("\x1b[?25h");
    };
    const onEnd = () => { cleanup(); reject(new UserCancelledError()); };
    const onKey = (text: string, key: uiReadline.Key) => {
      if (key.ctrl && key.name === "c") { cleanup(); reject(new UiExitRequestedError()); return; }
      if (key.name === "escape") { cleanup(); reject(new UserCancelledError()); return; }
      if (key.ctrl || key.meta) return;
      const offset = Math.floor(selected / pageSize) * pageSize;
      if (key.name === "up") selected = (selected + choices.length - 1) % choices.length;
      else if (key.name === "down") selected = (selected + 1) % choices.length;
      else if (["left", "pageup", "right", "pagedown"].includes(key.name ?? "")) {
        const pages = Math.ceil(choices.length / pageSize);
        const direction = key.name === "left" || key.name === "pageup" ? -1 : 1;
        selected = ((Math.floor(selected / pageSize) + direction + pages) % pages) * pageSize;
      }
      else if (key.name === "return") { cleanup(); resolve(selected); return; }
      else if (/^[a-z]$/i.test(text) && offset + text.toLowerCase().charCodeAt(0) - 97 < choices.length) { cleanup(); resolve(offset + text.toLowerCase().charCodeAt(0) - 97); return; }
      else if (/^[1-9]$/.test(text) && offset + Number(text) <= choices.length) { cleanup(); resolve(offset + Number(text) - 1); return; }
      else if (text === "0" && choices.length === 10) { cleanup(); resolve(9); return; }
      else return;
      render();
    };
    process.stdin.on("keypress", onKey);
    process.stdin.once("end", onEnd);
    process.stdin.setRawMode(true);
    if (process.platform === "win32") process.stdin.ref();
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
    if (process.platform === "win32") process.stdin.ref();
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

