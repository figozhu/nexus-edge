# NexusEdge 2.2.1 验证报告

验证日期：2026-10-21。对象：最终模块源码、测试及生成的单文件 `nexus-edge.ts`。

## 1. 最终结果

环境为 **Linux x64、Bun 1.4.3、TypeScript 5.9.3**。启用官方 Linux / Windows 样本和扩展 VLESS 矩阵后：

**合计 445 pass / 0 fail / 0 skip，2759 次断言，14 个测试文件。**

结果来自四组互不重复的执行：基础回归及真实切换集成共 **260 pass、1594 次断言**；版本与网络测试 **67 pass、418 次断言**；内核面板与更新生命周期 **59 pass、314 次断言**；真实协议矩阵 **59 pass、433 次断言**。各组均使用最终稳定版默认配置，不将并行执行的耗时相加或描述为一次完整运行。

| 测试文件 | 通过数 | 重点 |
| --- | ---: | --- |
| `tests/core.test.ts` | 92 | 9 协议、schema 2、凭据、TLS / REALITY、SS2022、URI / JSON、过期证书修复路径、旧版迁移和脱敏 |
| `tests/network.test.ts` | 25 | 按需下载、多核心配置、独立 WARP 路由、CF 参数、官方文件哈希、缓存修复、TLS / ENC 生成、Windows ZIP |
| `tests/daemon.test.ts` | 28 | 多核心 / 多隧道、无隧道启动、独立故障、TCP / UDP、IPC、单例、退出清理、配置快照、v1 后台兼容、大响应 |
| `tests/platform.test.ts` | 21 | Windows 参数 / 任务定义 / 归属、系统路径与保护边界、版本识别、systemd 解析 |
| `tests/migration.test.ts` | 18 | 安装切换、各阶段故障注入、部分成功后的回滚、原自启状态及防止双实例争用 |
| `tests/real-proxy.test.ts` | 59 | 官方核心运行服务端和导出的客户端，实际双向数据及 SHA-256 校验 |
| `tests/address.test.ts` | 28 | IPv4 优先、IPv6 回退、取消 / 超时、环境代理隔离、响应限制、地址范围与网卡候选 |
| `tests/presets.test.ts` | 31 | 9 种简易预设、隧道显式转换、直连 / 凭据保留、合法空 Short ID |
| `tests/simple.test.ts` | 23 | 地址与监听族、缺地址和取消行为、新旧运行指纹、真实 TCP / UDP 端口占用 |
| `tests/runtime-metadata.test.ts` | 18 | IP / 对外端口更新不重启、不丢临时域名、不重复通知；真实服务端变化仍隔离 |
| `tests/core-releases.test.ts` | 42 | 默认均为官方稳定版、保留历史预发布选择、版本发现与比较、摘要与来源约束、安全解包、完整文件校验、首次版本持久化及并发锁 |
| `tests/updates.test.ts` | 49 | 下载与预检先于停机、停止状态保持、更新失败恢复、回退、配置与版本并发变化、启动身份确认 |
| `tests/core-panel.test.ts` | 10 | 稳定版简易入口、只更新使用中的内核、预发布与指定版本、确认后的过期候选及回退保护 |
| `tests/real-updates.test.ts` | 1 | 官方 sing-box 的真实后台停止、独立目录切换、重新启动与回退，核对实际进程路径和凭据保持 |
| **合计** | **445** | **无失败、无跳过** |

另外已完成以下验证。前三项的 21 组 PTY 场景沿用 2.2.0 同日已通过的结果；本轮没有修改相应交互实现，未重复执行。2.2.1 的单文件发布冒烟、类型检查、构建和表内全部 TypeScript 测试均已重新执行。

- `tests/ui-pty.py`：**4 组通过**，菜单循环、中文输入、密钥不回显、Ctrl+C / Esc、终端状态和光标恢复。
- `tests/panel-pty.py`：**4 组通过**，连续建立 VLESS / VMess / SS 无隧道节点，隧道 quick → fixed → none 切换及双入口，REALITY / Vision 参数，取消不保存。检查自定义 UUID、域名、Host 端口、密码，以及编辑后凭据保持。
- `tests/simple-pty.py`：**13 组通过**。实际终端内验证 SS / VMess / VLESS / Trojan 新建只需协议和保存两次选择；旧复杂节点原样保存；IP 失败就地填写并拒绝通配地址；新 IPv6 配套监听；quick / fixed / none；VLESS 自动 ENC；VMess TLS 转换保留加密；取消无持久更改；旧 SS 导出自动补 IP 并解析实际 URI；半组 TLS 材料不被覆盖。固定 Token 不回显。服务替身只模拟下载、探测及应用等外部动作，编辑器、校验和持久化代码均真实执行。
- `tests/release-smoke.py`：**通过**。真正运行生成的 2.2.1 单文件，检查 `--help` / `--version`，在中文和空格路径、不同工作目录下打开面板，进入“8. 内核管理”、返回并正常退出；默认 schema 2 空节点，没有下载核心、写入版本选择或创建后台 / 隧道。
- `tsc --noEmit`：**通过**，同时检查模块、测试、构建脚本和生成的单文件。
- 单文件构建：**通过**。合并产物不再依赖本地源码模块。
- systemd 自身的 `systemd-analyze verify`：**通过**，已包含在 platform 测试中；没有注册真实服务。

合计 **21 组终端交互回归**，另有完整单文件发布入口冒烟。IP 探测的网络响应由 mock 提供，没有把当前测试机的出口 IP 当成用户 VPS 的实际 IP，也没有把这些测试宣称为公网入站验收。

## 2. 真实协议测试做了什么

使用官方稳定版固定文件：**Xray 26.3.27、sing-box 1.14.3**。安装测试另使用 **cloudflared 2026.10.2** 文件；没有建立真实 Cloudflare 隧道。旧 **Xray 26.10.17** 样本单独保留，用于验证历史版本选择不会因新默认值而被改写。

每个数据测试调用本项目的服务端构建器及 `generateClientConfig`，使用其导出的 SOCKS / mixed 客户端配置，仅把本地入口端口换成测试可用端口。实际启动两个核心进程，通过 SOCKS 入口向本机 HTTP 回显服务发送含中文、随机 nonce 和二进制零字节的约 35 KB POST 数据，并验证返回状态、nonce、长度和 SHA-256。

| 协议 | 用例数 | 场景 |
| --- | ---: | --- |
| VLESS | 43 | 8 个基本场景，以及 TCP / WS / gRPC / XHTTP × TLS / REALITY / none × Vision / ENC 的 35 个合法组合 |
| VMess | 3 | TCP、WS、gRPC + TLS |
| SS | 4 | 经典 AEAD、SS2022 AES128、AES256、ChaCha20 |
| Trojan | 2 | TLS、WS + TLS |
| Hysteria2 | 2 | TLS、Salamander 混淆 |
| TUIC | 1 | TLS |
| AnyTLS | 2 | TLS、REALITY |
| SOCKS5 | 1 | 用户名 / 密码 |
| Naive | 1 | HTTP/2，客户端信任自签证书 |
| **合计** | **59** | **真实本机转发** |

REALITY 使用测试自己拥有的本机 TLS 握手目标，没有依赖公网网站。HY2 / TUIC 的传输真实经过 QUIC / UDP，但转发业务为 TCP 字节流；**没有将这项测试扩大解释为所有协议 UDP relay、所有客户端软件、全部 ALPN / XHTTP mode 或公网链路均已验证。**

本轮 Xray 26.3.27 真实协议矩阵使用生产构建器生成的出站配置，未添加额外的私网访问规则。测试夹具仅在使用 26.10.17 及更高版本时，才为其默认私网限制添加 `127.0.0.1/32` 测试例外；该分支在本轮稳定版矩阵中没有执行。全部业务请求仍只访问测试自己创建的本机回显服务。

测试实际发现并修复了以下兼容问题：

- VLESS 自签客户端使用叶证书 SHA-256 pin，URI 和 JSON 均验证；这一做法也保留了此前对不再接受 `allowInsecure:true` 的较新 Xray 预发布版的兼容处理。
- 无 ENC 的 Vision 仅接受 TCP + TLS / REALITY；有 ENC 的其他合法组合通过真实转发，不能只依靠 `run -test` 判断。
- TLS 生成输出规范化为 PKCS#8，并检查证书与私钥匹配。
- Naive 使用官方包内 libcronet；自签客户端导出公开证书信任材料。
- SOCKS 只固定监听 TCP，UDP 由 ASSOCIATE 动态建立，守护不再等待不存在的固定 UDP 监听。
- HY2 配置以服务端方向为准，客户端上下行交换；非对称带宽另有模型回归。

## 3. 内核更新的验证

版本查询既有确定性测试，也实际调用了官方 GitHub Releases 接口。2.2.1 在 2026-10-21 重新请求三个官方 `/releases/latest`：sing-box 1.14.3、Xray 26.3.27、cloudflared 2026.10.2，三者均为 `draft=false`、`prerelease=false`，与本版默认值一致。新 Xray 三个平台的官方包均重新下载、核对官方摘要并生成完整文件清单。

同日 2.2.0 已完成的预发布查询返回 sing-box 1.15.0-alpha.12、Xray 26.10.17、cloudflared 2026.10.2，指定 Xray `v26.10.17` 查询也成功；本轮没有为了默认值调整重复这两种外部查询。其解析与选择逻辑继续通过本轮自动化回归。官方标签与发布渠道可能继续变化，这些数值只记录查询时的响应。

新回归明确断言三个初始选择均为稳定版，并使用旧 26.10.17 官方清单单独构造已保存的预发布选择：真实下载、哈希校验、版本探测、配置预检及缓存复用通过，版本记录原始字节保持不变。稳定版检查不会把该历史选择自动降级；预发布序号继续按数值比较，例如 alpha.12 高于 alpha.9。手工指定旧版属于显式降级，面板会显示版本变化并要求确认。

自动化测试还覆盖：

- GitHub 仓库、标签、平台文件名和 HTTPS 下载地址绑定；缺失或不合法的官方 SHA-256 摘要拒绝下载；查询失败按内核分别显示，限流和响应大小有界。
- 在核对官方压缩包摘要之后解包；拒绝路径穿越、符号链接、设备文件及异常包结构；核对全部缓存文件，保留运行库、数据及许可证文件；受损缓存按同一已选版本修复。
- 首次实际使用内核时持久保存版本选择，后续脚本默认版本变化不会悄悄替换选择；只查看面板或检查更新不写入选择文件。
- 全部候选完成下载、实际版本命令检查和当前配置预检后，才停止原后台。候选预检不发布运行配置、链接或固定隧道 Token。
- 更新锁、确认前版本快照、停止前后配置复查和后台实例核对。确认期间被其他操作改变的选择会中止，避免误降级或回退到非预期版本。
- 原来停止的后台保持停止；运行中的后台切换后必须报告正确的配置与内核指纹。启动失败尝试恢复原版本和后台，无法确认清理或恢复时如实报错。

### 真实进程切换测试

`tests/real-updates.test.ts` 使用已验证的官方 **sing-box 1.14.3** 文件，以及仅绑定 `127.0.0.1` 的 Shadowsocks 节点。实际执行下载器、版本探测、配置预检、版本选择持久化、worker / core-host、认证 IPC、停止、启动及回退。

测试路线为：**初始默认目录 → 带官方摘要标识的独立目录 → 原默认目录**。两个目录使用同一官方版本，目的是直接验证所选路径控制真实进程及回退行为，没有把它宣称为跨两个上游版本的兼容性测试。每阶段核对 TCP / UDP 监听、独立的 worker 实例 ID / PID、实际核心 PID、`/proc/<pid>/exe` 与 `coreReleaseHash`；同时确认配置原始字节、凭据、导出链接和链接文件内容不变，两个缓存目录均保留，测试拥有的进程最终全部退出。

该集成用例只替换系统自启发现，避免触碰原生服务。测试夹具透明记录实际 spawn 返回的子进程 PID，仍以原参数调用原始进程创建方法；下载响应提供官方原始样本，子进程阻止意外的外部请求。未创建公网隧道、WARP、真实通知或系统服务。

自动恢复覆盖程序捕获到的错误。更新期间强制结束进程、断电或系统崩溃可能留下停止状态，需要手动启动或回退；此版本没有实现断电恢复事务日志。核心的配置检查和监听就绪也不等于所有客户端或公网链路均兼容未来版本。

## 4. 守护、平台和外部能力的边界

守护测试实际运行本项目 worker、core-host、SQLite 锁和认证 IPC；协议核心与 cloudflared 在这些故障注入用例中是可控模拟进程。它们验证生命周期，上一节的测试负责真实协议转发，两者用途分别记录。

已覆盖：无隧道时不创建 cloudflared 或其指标请求；单个隧道失效不停止其他节点，双入口节点保留直连；一种共享核心退出不影响另一核心；父后台强制退出清理其核心；重复启动受锁保护；不依赖陈旧 PID 杀进程；`/status` 超过 1 MiB 时保留状态和认证停止能力；已加载服务端配置不因磁盘编辑变化；旧 v1 状态仍可识别并停止。

2.1 的元数据例外只允许 `address` / `publicPort`：整个配置的运行指纹完全匹配后，才更新状态链接及 `node-link.txt`，不改 UUID、路径、证书、监听、隧道或任何核心参数。任何节点或共享设置有真实变更，拒绝采纳该份新元数据。配置损坏或短暂缺失时保留上次接受的链接，不自动重建配置。

地址更新不补发 direct 通知；首次就绪通知和 Quick 域名真正变化时的原有通知行为保留。相关测试全部捕获到本机临时文件，没有真实发送。

本地控制通过本机假代理回归，确认 `/ready`、`/status`、`/stop` 不经过环境代理。通知与注册接口使用模拟响应，没有发送真实节点链接或注册真实 WARP 设备。

WARP 已验证导入格式、DNS / 路由结构、两个官方核心的配置检查。**未执行真实 WARP 握手、出口地址或公网可用性验收。**

Windows 官方 ZIP 已在 Linux 上解析并核对完整文件哈希，包括 sing-box 的嵌套路径和稳定版 Xray 的九个文件；正确保留其 `LICENSE-wintun.txt` 和随包脚本，未沿用预发布版的不同文件名清单。**没有执行 Windows `.exe`，不能据此宣称 Windows 原生运行测试通过。** Windows 参数、任务定义、电池和时间限制、身份归属及路径保护有源码测试；真实任务注册、UAC、登录前运行和重启均未执行。

系统安装迁移使用注入操作测试顺序和回滚，没有真实修改 `/opt`、systemd 或 Windows 计划任务。系统脚本升级分支经过代码审阅和版本识别 / v1 IPC 兼容回归，尚未在真实系统安装目录进行升级。升级机制保存配对的旧脚本和旧配置；打开新版后回退 1.0 时必须恢复两者。2.2 保持 schema 2，2.0 / 2.1 的既有节点不会重新套用简易预设。

## 5. 重跑方法

从项目根目录执行，需要 Bun >= 1.4.3、Python 3，以及允许本机监听、子进程和 POSIX PTY 的环境。

```bash
bun install --frozen-lockfile
bun run build
bun run typecheck
```

准备 `src/network.ts` 固定清单匹配的官方文件，并为历史选择回归另备一份 Xray 26.10.17 对应平台 ZIP。解压后的 sing-box 保留 libcronet 等随包文件。替换下面的绝对路径：

```bash
NEXUS_EDGE_SINGBOX_TEST_BINARY="/absolute/official/sing-box" \
NEXUS_EDGE_XRAY_TEST_BINARY="/absolute/official/xray-26.3.27/xray" \
NEXUS_EDGE_TEST_SINGBOX_ARCHIVE="/absolute/official/sing-box-1.14.3-linux-amd64.tar.gz" \
NEXUS_EDGE_TEST_XRAY_ARCHIVE="/absolute/official/xray-26.3.27/Xray-linux-64.zip" \
NEXUS_EDGE_TEST_CLOUDFLARED_BINARY="/absolute/official/cloudflared-linux-amd64" \
NEXUS_EDGE_TEST_SINGBOX_WINDOWS_ARCHIVE="/absolute/official/sing-box-1.14.3-windows-amd64.zip" \
NEXUS_EDGE_TEST_XRAY_WINDOWS_ARCHIVE="/absolute/official/xray-26.3.27/Xray-windows-64.zip" \
NEXUS_EDGE_TEST_LEGACY_XRAY_ARCHIVE="/absolute/official/xray-26.10.17/Xray-linux-64.zip" \
NEXUS_EDGE_TEST_EXTENDED_MATRIX=1 \
bun test

python3 tests/ui-pty.py --bun /absolute/path/to/bun
python3 tests/panel-pty.py --bun /absolute/path/to/bun
python3 tests/simple-pty.py --bun /absolute/path/to/bun
python3 tests/release-smoke.py --bun /absolute/path/to/bun
```

不设置样本环境变量时，对应真实核心 / 安装 / 更新集成测试会跳过。未打开扩展矩阵时不运行额外 35 个 VLESS 组合。systemd 工具不可用时该解析测试会跳过。真实更新集成用例还需要 Linux 的 `/proc` 进程信息；它在其他系统上会跳过。重跑要同时看通过数、失败数和跳过项。

发布入口冒烟测试应在没有已激活 NexusEdge 系统副本的环境执行，避免其自动跳转现有管理面板。

## 6. Windows 真机验收表

下表是后续现场验收项目，**不是本报告已完成结果**。

| 项目 | 操作与通过标准 |
| --- | --- |
| PowerShell / cmd / Windows Terminal | 中文与空格目录打开脚本，菜单多轮输入、密钥不回显、退出恢复终端 |
| 简易模式与地址探测 | 新增时只选协议并保存；实际公网 IPv4 / IPv6 探测、NAT 映射、系统 VPN 下手动覆盖；不将 0.0.0.0 当连接地址 |
| 多协议无隧道 | 建 VLESS、VMess、SS 三节点并启动，查看只有所需 Xray / sing-box，无 cloudflared；从另一设备导入并访问 |
| TLS / REALITY | 导入或生成证书、配置目标与密钥，用匹配版本客户端完成实际链路 |
| UDP 节点 | HY2 / TUIC 允许正确 UDP 端口和 NAT 映射，从外部客户端验证 |
| 临时隧道 | 为一个 WS 节点额外开启，取得临时域名；保留其他直连节点，验证隧道停止时其仍可用 |
| 固定隧道 | 配 Token 和公共主机名映射，核对 Host / SNI / 路径，从客户端实际访问；并测试双入口 |
| 后台持久运行 | 退出面板并关闭终端，重新打开能看到同一后台和节点 |
| 2.1 地址修复 | 旧缺地址节点导出时补 IP，保留 UUID / SNI / 映射端口；只改元数据不重启，不失去运行中的临时域名 |
| 2.2 内核更新与回退 | 运行节点时检查并更新指定内核，实际切换到独立目录中的 `.exe`；原文件仍在，UUID / 密钥保持；回退后旧核心恢复 |
| 更新失败与竞争 | 下载或预检失败时原节点继续运行；确认后其他面板修改配置或选择时安全中止；模拟候选启动失败并检查恢复结果 |
| UAC 取消与安装 | 取消不破坏原后台；接受后实际执行受保护系统目录的 Bun / 脚本 |
| SYSTEM 登录前运行 | 重启停留登录界面，从另一设备验证节点；不能用登录后才可用代替 |
| 电池与时限 | 任务允许电池启动、切换电源不断开、没有默认最长运行时限 |
| 关闭自启和停止 | 关闭自启保留当前后台；停止结束当前实例、保留当时的自启选择 |
| 1.0 系统升级 | 新文件打开旧系统副本，升级保留 UUID / 密钥；显式重启后多节点生效；回退同时恢复脚本和 schema 1 配置 |
| WARP | 使用有效配置，分别在 sing-box 和 Xray 节点验证真实握手、出口及业务域名解析 |

本报告不把 Linux 上的验证结果等同于 Windows / ARM64 真机或公网环境验收。
