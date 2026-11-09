# NexusEdge 3.0.0 独立程序与自动 Release 验证

验证日期：2026-11-09。环境为 Windows x64、Bun 1.4.4、TypeScript 5.9.3、Python 3.12 / pywinpty 3.1.2。以下记录发布前的本地检查；GitHub 原生三平台执行及发布结果见 [Release workflow](https://github.com/figozhu/nexus-edge/actions/workflows/release.yml)。

| 检查 | 结果 |
| --- | --- |
| 固定依赖安装、类型检查、单文件生成 | 通过；Bun 版本由 `.bun-version` 固定，源码与 package.json 版本均为 3.0.0 |
| 全量单元 / 本机进程测试 | **534 通过、79 跳过、0 失败**；613 项、2916 断言 |
| 三平台 `bun build --compile` | Windows x64、Linux x64 baseline、Linux arm64 均构建成功；PE/ELF 机器类型核对通过 |
| Windows 发布程序，无外部 Bun PATH | help/version、无效参数拒绝、中文路径、不同 cwd、core-host 再启动自身、detached worker 空配置退出、SQLite 锁释放、保留/删除配置卸载均通过 |
| 编译后的完整进程链路 | 编译 worker → 编译 core-host → 编译回环 HTTP 核心实际就绪、传输字节、认证 IPC 停止；核心 PID 确认结束；PATH 不含 Bun |
| Windows 发布程序原生 ConPTY | 完整真实面板：IPv6 设置仅保存、返回主菜单、取消卸载、正常退出；没有网络或系统设置写入 |
| 原有原生终端回归 | UI **6/6**、高级面板 **29/29**、简易面板 **15/15**、生成单文件高级面板 **29/29** 全部通过 |
| 发布汇总与失败拒绝 | 三份产物汇总、8 个附件逐个 SHA-256 验证通过；错误 tag、损坏摘要均拒绝 |
| Workflow 静态检查 | 两份 YAML 均通过 actionlint 1.7.12；未把静态检查当作 GitHub Actions 实际运行 |
| 自动发布逻辑 | 6 项离线 API 回归通过：main 自动版本发布、已发布版本保留、失败草稿、同提交重试、提交/tag 冲突、触发来源约束 |
| TUI 截图 | 三张真实 ConPTY 终端帧已重新生成并逐张检查；主菜单本机路径已替换为打码标记，无真实节点、地址或凭据；PNG 无文本/EXIF 元数据及尾随数据，捕获进程正常退出 |
| 截图隐私回归 | 6 项通过；覆盖中文/空格/跨行/UNC/POSIX 路径、界面边界变化拒绝、其他路径拒绝、原始界面保持、PNG 像素与隐藏路径无关及失败不落盘；已纳入 Windows CI |
| 平台适配回归 | 固定双布局、跨格式升级拒绝、UAC 空参数、任务/systemd 参数、二进制字节保留、占用保护及退出清理共 10 项通过 |

新增终端回归发现 Bun 1.4.4 / Windows 连续菜单及 Readline 切换后，`stdin.pause()/resume()` 与反复 raw/cooked 切换可能不再投递原始 `data`，同时 JavaScript 状态仍显示 raw/flowing 正常。源码版和编译版均可复现。Windows 菜单使用 `unref()/ref()` 管理事件循环引用，真实完整交互通过 `withUiInputSession` 保持菜单间输入模式，会话结束、异常或取消时统一恢复并 pause，交接其他程序前释放输入。无活动菜单/Readline 时保留 Ctrl+C 退出能力。独立菜单调用及 POSIX 保持原模式恢复契约。含 Readline 保存与纯菜单返回的两条完整序列、全部原生交互回归和截图捕获均通过，没有加入延时绕过。

系统二进制安装沿用固定受保护根目录和现有配置格式。Windows 程序被占用时不能覆盖升级，明确要求先停止后台并关闭系统面板；失败保持原文件。脚本与独立程序之间的系统格式转换在任何写入前拒绝，需备份并保留配置卸载后显式迁移。相关测试使用临时目录和受控 PowerShell 替身，没有更改生产系统副本、任务、防火墙、网卡或用户节点。

**本地验证边界：** 本机没有 WSL / Linux 运行环境，Linux 两种架构仅完成交叉构建及文件格式核对，未执行其二进制。Release workflow 已要求在 Windows x64、Linux x64、Linux arm64 各自 runner 上完成单元测试、无 Bun 冒烟及原生 PTY，且依赖原跨平台测试全部成功后才发布。真实 Linux/systemd 安装、Windows 系统二进制安装升级全流程以及真实公网协议仍需对应环境验收；79 个跳过项不计为通过。编译回环核心是测试替身，不代表重新验收上游代理协议。

本地产物：`dist/release/`；包含三个可执行文件、完整单文件源码、README、项目许可、Bun 许可说明及统一 `SHA256SUMS`。中间产物和编译缓存由 `.gitignore` 排除。测试与调试进程均在完成后清理。

---

# NexusEdge 2.3.3 验证报告（此前记录）

验证日期：2026-11-09。执行环境为 Windows x64、Bun 1.4.4、TypeScript 5.9.3；原生终端使用 Python 3.12.14 / ConPTY / pywinpty 3.1.2。

| 本轮检查 | 结果 |
| --- | --- |
| 全量单元 / 本机进程测试 | **517 通过、79 跳过、0 失败**；596 项、2848 断言 |
| TypeScript、单文件构建、CLI help/version、Git 空白检查 | **通过**；单文件版本 **2.3.3** |
| Windows 原生基础输入与卸载确认 | **6 / 6 通过**；含 `j` / `K` 第十/十一项直达、大小写、33 项分页、保留/删除/取消及默认值 |
| Windows 高级分组编辑 | **29 / 29 通过**；实际菜单按字母标签选择 |
| Windows 简易节点编辑 | **15 / 15 通过**；既有协议场景全部使用字母快捷键 |
| 生成单文件的高级分组编辑 | **29 / 29 通过** |
| 额外显式启用的真实 Windows 用户计划任务测试 | **1 / 1 通过**；临时任务注册、启动、关闭自启、重新启用、卸载注销及重复卸载 |
| 进程及任务清理 | **通过**；未遗留本轮测试 worker、核心、专用 Bun、ConPTY 子进程或临时计划任务 |

卸载回归覆盖配置与备份逐字节保留、删除配置、重复卸载、损坏配置、后台/注销/防火墙失败时保留数据、目录 junction 拒绝、更新锁/后台锁冲突、持锁清理程序、释放时其他进程重新取得锁后仍保留原锁文件、新便携入口提权处理旧系统副本、固定系统目录运行时不匹配拒绝。

真实测试 worker、core-host 与合成回环核心验证了卸载确实等待核心停止，再删除运行文件。Windows PowerShell 使用替身验证任务归属冲突与仍运行时不能注销；专用 Bun 测试复制当前 Bun 到独立临时目录，实际启动并验证执行文件占用期间保留、进程退出后删除。另一个独立临时用户计划任务通过真实 Task Scheduler API 验证注销，不使用生产任务。

Linux 空防火墙计划新增 5 个跨平台命令模拟回归：无工具且无归属、默认 ACCEPT 空规则、原生 nftables 不影响纯清理、历史归属但缺工具时拒绝、孤立链清理，以及停用 UFW 保留持久规则（部分场景合并在同一用例）。所有防火墙测试均使用命令替身，不修改宿主防火墙。

本轮未在 Linux/systemd 真机执行卸载，也未修改生产系统安装、现有节点或防火墙。79 个默认跳过项涉及平台限定、真实核心样本及显式启用的系统集成，不计为通过；上表真实 Windows 用户任务是另行显式运行的一项。Linux POSIX PTY 发布冒烟仍由既有 Linux CI 执行，本机无 WSL，未将它计入本轮通过结果。

保留两份不含凭据的 SQLite 锁文件是刻意设计：避免卸载释放锁后，其他面板取得原锁时又被删除路径，导致 Linux 新旧 inode 同时持锁。

---

# NexusEdge 2.3.2 验证报告（历史记录）

验证日期：2026-11-08。现场环境为 Windows x64、Bun 1.4.4、TypeScript 5.9.3；原生终端测试使用 ConPTY / pywinpty 3.1.2。

| 本轮检查 | 结果 |
| --- | --- |
| Windows 全量单元 / 本机进程测试 | **490 通过、79 跳过、0 失败**；569 项、2758 断言 |
| TypeScript、单文件构建、Git 空白检查 | **通过**，单文件版本为 **2.3.2** |
| Windows 原生基础输入 | **4 / 4 通过**；中文、方向键、密文不回显、菜单 Esc、Ctrl+C 与终端恢复 |
| Windows 简易节点流程 | **15 / 15 通过**；含认证分组回滚及进入高级编辑前的并发冲突检查 |
| Windows 高级分组编辑 | **29 / 29 通过**；九协议创建及自定义参数、取消、并发保存 |
| 生成单文件的高级分组编辑 | **同一组 29 / 29 通过**；直接导入发布文件，不运行主入口或跳转系统安装 |
| 用户现有节点保护 | **通过**；系统安装和旧便携目录的配置 SHA-256 均与开始时完全相同 |
| 测试清理 | **通过**；临时目录、测试节点及测试子进程均已清理，现有后台保持运行 |

高级流程覆盖 REALITY 单次域名输入同步目标/SNI、无效输入重试、独立 IPv4/IPv6 目标与 SNI、握手端口、已有空 Short ID 与密钥保留、只改名称、按协议隐藏认证字段、必选 TLS 跳过单选菜单、端口自动跟随与独立 NAT 保留、VMess 三种隧道模式、VLESS 隧道直连的 ENC、VMess 加密恢复、Hysteria2/TUIC 参数、协议更换及取消、保留并发修改的无关节点和拒绝覆盖当前节点。

所有交互夹具在独立临时目录创建节点，禁止网络请求、核心启动和端口监听；TLS/ENC 使用公开测试材料注入。以上结果验证实际终端按键、配置保存和客户端/服务端导出语义，不代表本轮重新执行了公网代理、Cloudflare 或 WARP 连通性验证。79 个跳过项涉及未启用的真实核心样本、系统集成及平台限定用例，不计为通过。

菜单内 Esc 撤销当前分组，文本输入沿用 Ctrl+C 退出面板。没有保留会导致 Windows/Bun 连续输入失去响应的文本 Esc 实验代码。

本机系统安装和旧便携目录的配置 SHA-256 均与测试前一致；本轮不升级系统副本、不重启现有服务。

Windows 重跑（Python 需 UTF-8 模式；pywinpty 仅为测试依赖）：

```powershell
bun run build
bun run typecheck
bun test
python -m pip install pywinpty==3.1.2
python -X utf8 tests/ui-pty.py
python -X utf8 tests/simple-pty.py
python -X utf8 tests/panel-pty.py
$env:NEXUS_EDGE_PTY_STANDALONE = '1'
python -X utf8 tests/panel-pty.py
```

Linux 可使用同一组 Python 脚本的标准库 POSIX PTY。CI 同时覆盖两种操作系统及生成单文件的 29 个分组场景；推送后的结果以对应 GitHub Actions 运行为准。

---

# NexusEdge 2.3.1 验证报告（历史记录）

验证日期：2026-11-08。当前开发与现场环境为 Windows x64、Bun 1.4.4、TypeScript 5.9.3；下方 2.3.0 报告属于历史记录，不计入本次结果。

## 当前结果

| 检查 | 结果 |
| --- | --- |
| Windows 全量测试（启用固定官方核心和真实任务测试） | **522 通过、47 跳过、0 失败**；569 项，3045 断言 |
| TypeScript 类型检查、单文件构建、Git 空白检查 | **通过** |
| 本机系统安装迁移 | **通过**；SYSTEM 开机任务已启用且运行，后台 ready，旧后台全部退出 |
| 配置和安装保护 | **通过**；节点/凭据保持，安装路径 ACL 验证通过 |
| 本机 IPv6 策略 | **通过**；真实运行配置强制 IPv4、IPv4 DNS、显式 IPv6 阻断，REALITY 运行目标为 IPv4 |
| Linux CI 全量测试 | **520 通过、49 跳过、0 失败**；构建和类型检查通过 |
| Windows CI 全量测试 | **490 通过、79 跳过、0 失败**；构建和类型检查通过 |
| Linux PTY / 单文件发布冒烟 | **通过**；交互菜单 4 + 4 + 13 组及单文件发布检查 |
| Linux IPv6 真实内核与持久化测试 | **通过**；隔离命名空间内关闭、开启、sysctl 重载，宿主状态保持 |

Windows 全量运行已包含真实协议回环、REALITY IPv4 运行目标和计划任务测试，不重复累计之前单独运行的数量。47 个跳过项为 Linux/POSIX、未设置的 PowerShell 模拟器或缺少额外官方压缩包样本的用例。测试结束仅保留实际用户服务的 worker、core-host 和 Xray，无调试进程或临时任务遗留。

双平台 CI 记录：[GitHub Actions #42436374094](https://github.com/figozhu/nexus-edge/actions/runs/42436374094)，对应提交 `fe7ce7ba59f8b19ba27a14ab1f9206eb58197250`。CI 未设置真实核心样本和 Windows 计划任务集成开关，因此跳过数量与本机专项全量运行不同；跳过项不计为通过。

## 验证范围

- 新旧配置的核心 IPv6 默认关闭、显式双栈开关、运行指纹和凭据保留。
- sing-box / Xray 实际回环 IPv4 转发、只查询 A 记录、默认阻断 IPv6 字面量及开启后 IPv6 转发；两种设置下的 REALITY / WARP 官方配置预检。
- Windows / Linux 接口状态、切换、持久化、权限、取消与部分失败回滚。Windows 使用真实 PowerShell 解析脚本和模拟 NetAdapter provider，本机网卡只做只读检查。
- 真实 Windows PowerShell 5.1 在继承不兼容模块目录时的故障复现与修复；真实用户登录任务、SYSTEM 开机任务注册和运行，测试任务在 finally 中清理。
- 跨平台构建、类型检查、单元/进程测试，以及 Linux PTY 菜单和单文件发布冒烟。

未进行公网 WARP / Cloudflare 隧道端到端验证，也未为了测试改变开发机器的 IPv6 接口。SYSTEM 任务实测运行不等同于重启整台机器后的验收。

## 重跑方法

```powershell
bun install --frozen-lockfile
bun run build
bun run typecheck
bun test

# 仅 Windows：临时真实任务将自动注销，不替换 NexusEdge-System。
$env:NEXUS_PLATFORM_WINDOWS_INTEGRATION = '1'
bun test tests/platform-windows.test.ts
```

真实核心测试需提供与 `NETWORK_RELEASES` 固定清单匹配的官方二进制：

```powershell
$env:NEXUS_EDGE_SINGBOX_TEST_BINARY = 'C:\path\to\sing-box.exe'
$env:NEXUS_EDGE_XRAY_TEST_BINARY = 'C:\path\to\xray.exe'
bun test tests/network.test.ts tests/real-proxy.test.ts tests/core-ipv6-real.test.ts
```

跨平台自动测试见 `.github/workflows/test.yml`。Linux 防火墙文件权限与锁测试只在 Linux 运行，Windows 的 POSIX 跳过不代表覆盖已通过。样本缺失导致的跳过数应与通过数分别报告。

Linux 真实接口与持久化测试可独立运行：

```bash
sudo "$(command -v bun)" tests/fixtures/ipv6-linux-namespace.ts
```

该脚本建立独立网络/挂载命名空间，确认只有回环接口后挂载临时 sysctl.d，调用生产开关并用 `sysctl -p` 重载；退出后核对宿主开关和持久化文件完全不变。不要直接在生产机器执行 helper 来代替此隔离测试。

---

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
