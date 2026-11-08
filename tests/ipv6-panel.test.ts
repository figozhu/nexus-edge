import { describe, expect, test } from "bun:test";
import { createPaths } from "../src/core.ts";
import { type HostIpv6Status } from "../src/ipv6.ts";
import { hostIpv6Summary, runHostIpv6Panel, type HostIpv6PanelServices } from "../src/ipv6-panel.ts";

/** 内存菜单夹具；顺序 choices 模拟用户选项并记录实际调用，不启用 UAC。 */
function panelFixture(choices: number[], admin = true) {
  const state: HostIpv6Status = { platform: "win32", state: "enabled", interfaces: [{ name: "Ethernet", enabled: true }], defaultEnabled: null, persistedEnabled: null, detail: "测试状态" };
  const events: string[] = [], messages: string[] = [], helperArgs: string[][] = [];
  const services: HostIpv6PanelServices = {
    inspect: async () => { events.push("inspect"); return structuredClone(state); },
    apply: async enabled => { events.push(`apply:${enabled}`); state.state = enabled ? "enabled" : "disabled"; state.interfaces[0]!.enabled = enabled; return structuredClone(state); },
    isAdministrator: () => admin,
    elevate: async (_paths, args) => { events.push("elevate"); helperArgs.push(args); state.state = args[1] === "enable" ? "enabled" : "disabled"; state.interfaces[0]!.enabled = args[1] === "enable"; },
    menu: async () => { const value = choices.shift(); if (value === undefined) throw new Error("菜单调用次数超出测试预期"); return value; },
    pause: async () => { events.push("pause"); }, report: message => { messages.push(message); },
  };
  return { state, services, events, messages, helperArgs, paths: createPaths("/tmp/nexus-ipv6-menu/nexus-edge.ts") };
}

describe("本机 IPv6 菜单", () => {
  test("返回和取消确认均不修改接口也不请求 UAC", async () => {
    const env = panelFixture([0, 0, 3], false);
    await runHostIpv6Panel(env.paths, env.services);
    expect(env.events).toEqual(["inspect", "inspect"]);
    expect(env.helperArgs).toEqual([]);
  });

  test("管理员明确确认后应用，显示重新读取的接口状态", async () => {
    const env = panelFixture([0, 1, 3]);
    await runHostIpv6Panel(env.paths, env.services);
    expect(env.events).toEqual(["inspect", "apply:false", "pause", "inspect"]);
    expect(env.messages[0]).toContain("已禁用本机 IPv6 网络接口");
  });

  test("普通用户只传有限 helper 参数，返回后再查询状态", async () => {
    const env = panelFixture([0, 1, 3], false);
    await runHostIpv6Panel(env.paths, env.services);
    expect(env.helperArgs).toEqual([["--host-ipv6", "disable"]]);
    expect(env.events).toEqual(["inspect", "elevate", "inspect", "pause", "inspect"]);
  });

  test("UAC 被取消不会报告已禁用", async () => {
    const env = panelFixture([0, 1, 3], false);
    env.services.elevate = async () => { throw new Error("UAC 已取消"); };
    await runHostIpv6Panel(env.paths, env.services);
    expect(env.messages.join("\n")).toContain("UAC 已取消");
    expect(env.messages.join("\n")).not.toContain("已禁用本机");
    expect(env.state.state).toBe("enabled");
  });

  test("提权返回但状态未改变时不能伪报成功", async () => {
    const env = panelFixture([0, 1, 3], false);
    env.services.elevate = async () => {};
    await runHostIpv6Panel(env.paths, env.services);
    expect(env.messages.join("\n")).toContain("状态仍与目标不一致");
    expect(env.messages.join("\n")).not.toContain("已禁用本机");
  });

  test("摘要区分新接口默认值和重启策略，明确不代表连通性", () => {
    const env = panelFixture([]);
    const text = hostIpv6Summary({ ...env.state, platform: "linux", defaultEnabled: false, persistedEnabled: true });
    expect(text).toContain("新接口默认值：禁用");
    expect(text).toContain("本工具重启策略：开启");
    expect(text).toContain("核心 IPv6");
    expect(text).toContain("不等于已取得可用");
  });
});
