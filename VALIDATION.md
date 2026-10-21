# NexusEdge 2.3.0 验证报告

验证日期：2026-10-21。对象：模块源码、测试及由 `scripts/build.ts` 生成的单文件 `nexus-edge.ts`。

## 1. 本轮结果

环境：**Linux x64、Bun 1.4.3、TypeScript 5.9.3**。Windows 脚本的执行测试额外使用微软官方 **PowerShell 7.4.6 Linux 版**，所有 NetSecurity cmdlet 均由内存模拟器替代。

| 验证 | 结果 | 范围 |
| --- | --- | --- |
| 最终完整 TypeScript 测试 | **495 pass / 0 fail / 30 skip，2812 次断言，18 个文件** | 启用 PowerShell 模拟执行；该轮没有设置真实协议核心样本变量 |
| 真实 sing-box 更新与回退 | **1 pass / 0 fail，55 次断言** | 单独补跑官方 sing-box 的真实 worker / core-host / 更新 / 回退 |
| UI PTY | **4 组通过** | 键盘、输入、取消、终端恢复 |
| 高级节点面板 PTY | **4 组通过** | 多协议、隧道、REALITY、保存与取消 |
| 简易节点面板 PTY | **13 组通过** | 两次选择创建、自动地址、保留高级配置、导出和隧道转换 |
| 2.3.0 单文件冒烟 | **通过** | 中文及空格路径、不同 cwd、版本、非法 helper 请求、内核与防火墙菜单、正常退出 |
| `tsc --noEmit` | **通过** | 同时检查源码、测试、构建器及生成文件 |
| 单文件构建与差异检查 | **通过** | 无相对源码依赖，版本为 2.3.0，`git diff --check` 无错误 |

完整运行的 30 个跳过项均依赖未提供的完整官方样本；其中真实更新用例随后单独通过，**本轮去重实际执行 496 个 TypeScript 测试，29 个已登记样本用例未执行**。额外的 35 个 VLESS 扩展矩阵场景没有开启，也不计入本轮执行数。不能把跳过项计为真实协议通过。

上述测试没有修改宿主机的真实防火墙，没有建立公网隧道、发送真实通知或注册 WARP 设备。防火墙命令均通过注入模拟器执行；原生进程测试只监听测试自己创建的回环端口。

## 2. 防火墙专项覆盖

| 文件 | 通过数 | 重点 |
| --- | ---: | --- |
| `tests/firewall.test.ts` | **28** | 20 项公共/Windows 测试，加 8 项真正执行 PowerShell 的模拟接口测试 |
| `tests/firewall-linux.test.ts` | **26** | UFW、firewalld、iptables / ip6tables、nft 冲突、归属迁移和锁 |
| `tests/firewall-control.test.ts` | **33** | UAC / sudo 请求、权限、取消、并发配置、请求与回执验证、后台行为 |
| `tests/firewall-integration.test.ts` | **21** | 默认设置、旧配置兼容、保存/启动/停止顺序、失败保留和规则恢复 |
| **专项合计** | **108** | **全部包含在最终 495 pass 中，不重复累计** |

既有 `tests/daemon.test.ts` 增加 2 项真实 worker 故障注入，当前共 30 项；`tests/migration.test.ts` 增加 5 项迁移顺序/恢复测试，当前共 23 项。这 7 项同样已包含在完整运行中。

### 端口计划

- 只处理已启用、开启直连、非回环监听的节点；仅隧道节点不开放入站端口。
- Shadowsocks 同时规划 TCP / UDP；Hysteria2、TUIC 规划 UDP；其他协议规划 TCP。SOCKS5 动态 UDP 转发只提示，不放行所有临时端口。
- 使用本机 `node.port`，不会把 NAT 的 `publicPort` 误作本机端口。
- 覆盖 IPv4、IPv6、双栈 `::`、具体监听地址，以及 IPv4 映射的 IPv6 回环地址。
- 安装目录 scope、稳定排序、确定性指纹、去重、最多 128 条有限规则；拒绝跨目录计划、任意端口范围和非规范地址。

### Windows

PowerShell 脚本通过真实解析与执行，并使用模拟的 Get/New/Set/Remove-NetFirewallRule 及各过滤器接口验证：

- 第一次新增、再次幂等同步、损坏规则修复、改端口、清理、所有网络配置文件。
- Name / Group / Description 三重归属核对；其他软件、手工规则与伪造同名规则不被接管。
- 新规则在 PersistentStore 与 ActiveStore 中都通过过滤器核对后，才移除过期规则。
- 新建中途失败、有效规则缺失、权限不足、服务停止、本地规则合并被组织策略禁止等情况。
- 完全适用的全局阻止规则会阻止自动应用；来源 IP 封禁、局部地址/接口、IPsec 等限制给出适当提示，不把局部限制误判成所有节点无法启动。
- 当前所选内核的程序阻止规则给出程序路径和端口提示；历史缓存版本的阻止规则不会妨碍新版本启动。
- 大量普通节点提示不会挤掉关键系统诊断。完整计划通过 stdin JSON 传输，不越过 Windows 命令行长度限制。
- 同一安装的修改由命名 mutex 串行处理；规则查询不依赖上次成功记录。

该执行测试发现并修复了 Bun 1.4.3 下 `String.raw` 中文模板变为字面量转义序列的问题。正式 PowerShell 程序改用普通模板，中文诊断可正确往返。

**没有真实 Windows NetSecurity provider，未对 Windows `.exe`、真正的 UAC、GPO、Windows 重启和远端入站流量做现场测试。PowerShell 模拟执行通过不等于 Windows 真机防火墙验收。**

### Linux

- **UFW：**使用与官方输出一致的命令模拟器，验证安装 comment、IPv4 / IPv6、保留等价手工规则、按完整内容删除、新增失败保留旧规则。还核对实际用户链规则，避免只因 `ufw status` 有记录就宣称同步。明确适用的前置拒绝规则与局部 IP 封禁分别处理。
- **UFW 迁移：**仅在源/目标有限端口计划一致、原规则确实属于源安装时更新 comment；保留规则顺序。失败恢复只处理已确认转移的子集；规则被其他操作改写时不强行接管。
- **firewalld：**运行时和永久 rich rules 分别写入和验证；不全局 reload。单活动区域自动选择，多候选区域明确报错。端口或区域变更先验证全部新规则，再清理旧归属；损坏记录、无归属碰撞、部分写入和恢复路径均覆盖。
- **iptables：**IPv4 / IPv6 独立链和跳转，完整标记验证、幂等、新增失败不清旧规则、无关链保留。分别判断 legacy / nf_tables 变体，拒绝原生 nft input 策略冲突；不 flush 全局规则，不改默认策略，不覆盖整个系统规则文件。
- **并发和记录：**修改使用有界 SQLite 锁，记录存于已有受保护目录，不改变目录归属；拒绝损坏、符号链接和不匹配 scope。

这些是命令模拟与文件系统测试，**没有实际修改 Linux 主机的 UFW / firewalld / iptables**。UFW 自定义 before/after 规则、其他 firewalld policy、第三方过滤器及云安全组仍可能限制公网连通性。raw iptables 自动放行需要 `nft` 命令完成只读冲突检查，运行时规则在重启后由有权限的 worker 重新同步。

## 3. 权限和应用生命周期

普通用户的提权请求只包含有限端口计划、scope、nonce、时间和保存配置的指纹，没有 UUID、密码、证书私钥、Tunnel Token 或 WARP 私钥。helper 在系统副本跳转前处理，严格限制请求 ID、字段、文件大小和有效期。

父进程预建回执文件，提权子进程通过同一文件描述符原位写回，保留原 inode、uid/gid 和权限；拒绝符号链接和硬链接替换。子进程不调用可能迁移配置或重置 Windows ACL 的 `readConfig`。测试检查实际 inode、权限及所有者保持；未将其描述为跨 Windows 账号 UAC 的实机验证。

配置预检和防火墙检查在保存、停止原后台之前执行。取消 UAC、配置并发变化、明确的防火墙错误会保留原配置及后台；文件保存失败时尝试恢复旧端口计划。防火墙未启用或管理器不支持时明确提示，不把提示伪装成已经放行。

显式“停止全部节点”在后台停止后清理本安装规则；普通重启、内核升级与回退的共用停止步骤不会先清空规则。手动模式不自动修改规则。节点仅保存时不修改当前运行策略，下次应用再同步。

后台启动使用原安装目录 scope，不使用每次启动生成的临时运行目录。后台不会弹出 UAC / sudo；防火墙错误作为单独状态和日志返回，本机核心仍可启动。`ready` 只表示本机监听和所选隧道就绪，不代表整个公网链路已完成验收。

系统安装迁移在原后台运行时先预检目标并准备规则；目标就绪、激活后才清理源规则。失败时先确认目标停止，再恢复原规则归属及后台；不能确认目标停止时，不删除其规则或制造第二套争用端口的后台。复制/准备期间源配置改变会中止切换。

## 4. 真实核心回归

使用固定官方 **sing-box 1.14.3 Linux amd64**。下载后，压缩包及解出的 `sing-box`、`libcronet.so`、`LICENSE` 全部匹配 `NETWORK_RELEASES` 中的 SHA-256 清单，然后才执行。

压缩包 SHA-256：

```text
e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
```

`tests/real-updates.test.ts` 在 `127.0.0.1` 上创建 Shadowsocks 节点，运行真实下载器/校验器、配置预检、worker、core-host、认证 IPC、停止、独立目录版本选择、启动及回退。验证每阶段 worker/core 的实际身份和可执行文件路径、旧进程退出，以及配置、凭据、链接内容保持不变。

该测试的两个目录使用同一官方版本，验证的是实际路径切换和生命周期；不将其解释为跨上游版本协议兼容性。测试禁止意外外部 fetch，使用新临时目录和回环监听，因此防火墙 hook 走空计划路径；没有修改宿主机防火墙。

先前 2.2.1 的 59 项完整协议数据转发、官方 Windows 压缩包校验、稳定版默认和历史预发布选择记录，保留在[对应提交的历史验证报告](https://github.com/figozhu/nexus-edge/blob/5251f73844ce36835d64844944d7891e5f0d5c3e/VALIDATION.md)。本轮没有改写协议配置生成器或内核版本选择逻辑，没有把历史结果计为本轮执行。

## 5. 重跑方法

需要 Bun >= 1.4.3；PTY 测试另需 Python 3 和 POSIX PTY。开发依赖安装后：

```bash
bun install --frozen-lockfile
bun run build
bun run typecheck
NEXUS_FIREWALL_PWSH=/absolute/path/to/pwsh bun test

python3 tests/ui-pty.py --bun /absolute/path/to/bun
python3 tests/panel-pty.py --bun /absolute/path/to/bun
python3 tests/simple-pty.py --bun /absolute/path/to/bun
python3 tests/release-smoke.py --bun /absolute/path/to/bun
```

不设置 `NEXUS_FIREWALL_PWSH` 时，8 个 PowerShell 执行用例跳过；20 个常规 Windows/计划测试仍运行。PowerShell 测试会替换所有相关系统 cmdlet，不调用真实 NetSecurity provider。

真实内核切换可单独重跑：

```bash
NEXUS_EDGE_TEST_SINGBOX_ARCHIVE=/absolute/official/sing-box-1.14.3-linux-amd64.tar.gz \
NEXUS_EDGE_SINGBOX_TEST_BINARY=/absolute/official/sing-box-1.14.3-linux-amd64/sing-box \
bun test tests/real-updates.test.ts
```

真实样本测试需要允许测试自有的回环监听和子进程。单文件冒烟应在没有已激活 NexusEdge 系统安装的环境运行，避免自动跳转已有安装。重跑须同时核对通过、失败和跳过数。

## 6. Windows / Linux 现场验收建议

以下为目标机器上的后续验收，不是本报告已经执行的结果：

| 场景 | 通过标准 |
| --- | --- |
| Windows 普通用户新建 SS | 保存并应用时必要的 UAC 生效，TCP / UDP 节点端口出现在 NexusEdge 入站规则中 |
| 已有节点补放行 | 进入防火墙菜单立即同步，不重建 UUID、密码或隧道 |
| UAC 取消 | 原配置、原后台保持；重新操作可以完成同步 |
| Windows 公用 / 专用 / 域配置 | 规则的配置文件正确，有效策略确实允许本地规则 |
| Windows 之前拒绝联网 | 能看到程序阻止规则诊断；按实际策略处理后从另一设备验证 |
| 改端口、停用及停止 | 新端口先放行，旧的本工具规则被清理；手工和其他软件规则保留 |
| IPv6 / 双栈 / UDP | 从另一机器用匹配客户端验证真实入站和协议握手 |
| UFW / firewalld / iptables | 核对实际加载规则及来源归属，服务重启/系统重启后按对应持久化机制恢复 |
| 系统自启迁移 | 目标就绪后源规则清理；失败恢复不删除仍运行的实例规则 |
| 仅隧道 / 手动模式 | 仅隧道无多余入站放行；手动模式不会自动修改现有策略 |
| 云服务器 / NAT | 系统规则、云安全组、路由器映射与真实客户端连通性分别确认 |

本项目目前支持 Windows x64、Linux x64 / arm64。本轮执行环境为 Linux x64，不能把本报告当作 Windows 或 ARM64 真机验收。
