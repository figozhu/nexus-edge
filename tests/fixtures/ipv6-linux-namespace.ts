import * as namespaceAssert from "node:assert/strict";
import * as namespaceCp from "node:child_process";
import * as namespaceFs from "node:fs";
import * as namespaceUrl from "node:url";
import { inspectHostIpv6, setHostIpv6Enabled } from "../../src/ipv6.ts";

/**
 * Linux 真内核集成测试。运行：sudo /absolute/path/to/bun tests/fixtures/ipv6-linux-namespace.ts
 * 外层只读宿主状态，随后用 unshare 建立私有 mount/net namespace。
 * 内层同时确认命名空间身份、父进程存活及只有回环接口，才挂载临时策略目录并操作 sysctl。
 * 不创建系统服务、不重启网卡、不向公网建立连接；内层结束即销毁隔离网络状态。
 */
const namespacePolicyPath = "/etc/sysctl.d/99-nexus-edge-ipv6.conf";
const namespaceProcRoot = "/proc/sys/net/ipv6/conf";

/** 读取指定进程的网络/挂载命名空间标识；pid 仅由本测试父进程产生。 */
function namespaceIds(pid: number | "self"): { net: string; mnt: string } {
  return { net: namespaceFs.readlinkSync(`/proc/${pid}/ns/net`), mnt: namespaceFs.readlinkSync(`/proc/${pid}/ns/mnt`) };
}

/** 执行有限系统工具并检查退出码；所有参数都是固定测试常量，不使用 shell。 */
function namespaceCommand(command: string, args: string[]): void {
  const result = namespaceCp.spawnSync(command, args, { encoding: "utf8", timeout: 10000 });
  if (result.error || result.status !== 0) throw new Error(`${command} 失败：${result.error?.message || result.stderr || result.stdout || result.status}`);
}

/** 读取本工具策略文件的原始状态，仅供外层最终核对宿主文件完全不变。 */
function namespaceReadPolicy(): string | null {
  try { return namespaceFs.readFileSync(namespacePolicyPath, "utf8"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
}

/** 对宿主所有 IPv6 控制值取只读快照，不依赖接口是否已获得地址。 */
function namespaceReadControls(): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of namespaceFs.readdirSync(namespaceProcRoot).sort()) {
    namespaceAssert.ok(!/[\\/\x00-\x1f]/.test(name) && name !== "." && name !== "..", "内核接口路径必须是单个安全名称");
    Object.defineProperty(result, name, { value: namespaceFs.readFileSync(`${namespaceProcRoot}/${name}/disable_ipv6`, "utf8"), enumerable: true });
  }
  return result;
}

/** 获取当前 namespace 的接口名，使用 procfs 动态视图，避免继承的 sysfs 显示宿主网卡。 */
function namespaceInterfaces(): string[] {
  return namespaceFs.readFileSync("/proc/net/dev", "utf8").split("\n").slice(2).filter(line => line.includes(":"))
    .map(line => line.slice(0, line.indexOf(":")).trim()).sort();
}

/**
 * 在已验证的隔离环境执行真实生产开关以及 sysctl 持久化重载。
 * outerPid 为仍在等待本子进程的外层进程；任何保护条件不成立时在首次 mount/写入前失败。
 */
async function namespaceInside(outerPid: number): Promise<void> {
  const outer = namespaceIds(outerPid), current = namespaceIds("self"), init = namespaceIds(1);
  namespaceAssert.notEqual(current.net, outer.net, "拒绝在父进程网络命名空间切换 IPv6");
  namespaceAssert.notEqual(current.mnt, outer.mnt, "拒绝在父进程挂载命名空间挂载策略目录");
  namespaceAssert.notEqual(current.net, init.net, "拒绝在 PID 1 网络命名空间测试");
  namespaceAssert.notEqual(current.mnt, init.mnt, "拒绝在 PID 1 挂载命名空间测试");
  namespaceAssert.deepEqual(namespaceInterfaces(), ["lo"], "隔离网络必须仅有回环接口");
  namespaceAssert.deepEqual(namespaceFs.readdirSync(namespaceProcRoot).sort(), ["all", "default", "lo"], "IPv6 控制目录不得包含宿主接口");
  namespaceAssert.ok(namespaceFs.lstatSync("/etc/sysctl.d").isDirectory(), "测试需要已有的 /etc/sysctl.d，不在宿主创建目录");

  // 先在独立挂载空间递归设为私有，防止 mount/umount 事件向宿主传播。
  namespaceCommand("mount", ["--make-rprivate", "/"]);
  namespaceCommand("mount", ["-t", "tmpfs", "-o", "mode=0755,nosuid,nodev,noexec,size=1m", "nexus-ipv6-test", "/etc/sysctl.d"]);
  try {
    const mounts = namespaceFs.readFileSync("/proc/self/mountinfo", "utf8").split("\n");
    namespaceAssert.ok(mounts.some(line => line.split(" ")[4] === "/etc/sysctl.d" && line.includes(" - tmpfs nexus-ipv6-test ")), "策略目录必须是隔离 tmpfs");
    namespaceAssert.equal(namespaceReadPolicy(), null, "临时策略目录必须为空");

    const before = await inspectHostIpv6();
    namespaceAssert.deepEqual(before.interfaces.map(item => item.name), ["lo"]);
    const disabled = await setHostIpv6Enabled(false);
    namespaceAssert.equal(disabled.state, "disabled");
    namespaceAssert.equal(disabled.defaultEnabled, false);
    namespaceAssert.equal(disabled.persistedEnabled, false);
    namespaceAssert.deepEqual(namespaceReadControls(), { all: "1\n", default: "1\n", lo: "1\n" });
    const disabledPolicy = namespaceReadPolicy()!;
    namespaceAssert.match(disabledPolicy, /net\.ipv6\.conf\.all\.disable_ipv6 = 1/);
    namespaceAssert.match(disabledPolicy, /net\.ipv6\.conf\.default\.disable_ipv6 = 1/);
    namespaceAssert.equal(namespaceFs.statSync(namespacePolicyPath).mode & 0o777, 0o644);
    namespaceAssert.equal(namespaceFs.statSync(namespacePolicyPath).uid, 0);

    // 手动清除隔离内核开关后加载生成的文件，验证文件能被真实 sysctl 消费。
    namespaceFs.writeFileSync(`${namespaceProcRoot}/all/disable_ipv6`, "0\n", { flag: "r+" });
    namespaceCommand("sysctl", ["-p", namespacePolicyPath]);
    namespaceAssert.equal((await inspectHostIpv6()).state, "disabled");
    namespaceAssert.deepEqual(namespaceReadControls(), { all: "1\n", default: "1\n", lo: "1\n" });

    const enabled = await setHostIpv6Enabled(true);
    namespaceAssert.equal(enabled.state, "enabled");
    namespaceAssert.equal(enabled.defaultEnabled, true);
    namespaceAssert.equal(enabled.persistedEnabled, true);
    namespaceAssert.deepEqual(namespaceReadControls(), { all: "0\n", default: "0\n", lo: "0\n" });
    namespaceAssert.match(namespaceReadPolicy()!, /net\.ipv6\.conf\.all\.disable_ipv6 = 0/);
    namespaceFs.writeFileSync(`${namespaceProcRoot}/all/disable_ipv6`, "1\n", { flag: "r+" });
    namespaceCommand("sysctl", ["-p", namespacePolicyPath]);
    namespaceAssert.equal((await inspectHostIpv6()).state, "enabled");
    namespaceAssert.deepEqual(namespaceIds("self"), current, "整个测试期间命名空间身份必须保持");
    console.log("Linux IPv6 隔离测试通过：真实 procfs 禁用/开启及持久化配置重载。");
  } finally {
    namespaceCommand("umount", ["/etc/sysctl.d"]);
  }
}

/** 外层入口建立新命名空间，等待子进程并核对宿主的 sysctl/配置未被更改。 */
async function namespaceMain(): Promise<void> {
  if (process.platform !== "linux") throw new Error("此集成测试仅可在 Linux 运行，未执行任何系统修改。");
  if (process.getuid?.() !== 0) throw new Error("请用 sudo 调用 Bun 执行此隔离测试；需要创建 mount/net namespace 的权限。");
  const args = process.argv.slice(2);
  if (args[0] === "--inside") {
    if (args.length !== 2 || !/^[1-9][0-9]*$/.test(args[1]!)) throw new Error("隔离子测试缺少合法父进程 ID。");
    await namespaceInside(Number(args[1])); return;
  }
  if (args.length) throw new Error("请直接运行此测试，由外层入口负责安全地创建命名空间。");
  const before = namespaceIds("self"), controls = namespaceReadControls(), policy = namespaceReadPolicy();
  const result = namespaceCp.spawnSync("unshare", ["--mount", "--net", "--fork", "--kill-child=SIGKILL", "--propagation", "private", "--", process.execPath,
    namespaceUrl.fileURLToPath(import.meta.url), "--inside", String(process.pid)], { stdio: "inherit", timeout: 30000 });
  namespaceAssert.deepEqual(namespaceIds("self"), before, "宿主命名空间不得变化");
  namespaceAssert.deepEqual(namespaceReadControls(), controls, "宿主 IPv6 开关不得变化");
  namespaceAssert.equal(namespaceReadPolicy(), policy, "宿主持久化策略不得变化");
  if (result.error || result.status !== 0) throw new Error(`隔离 IPv6 子测试失败：${result.error?.message || `退出码 ${result.status}`}`);
  console.log("宿主 IPv6 开关与持久化文件保持原值；隔离进程已退出。");
}

await namespaceMain();
