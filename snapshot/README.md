# TUI 界面截图

这些 PNG 来自 NexusEdge 3.0.0 独立程序的真实 Windows ConPTY 输出帧，经 ANSI 终端解析器按原布局和颜色渲染，并在发布前遮盖本机路径。不是生成式示意图，也不包含桌面、账号或生产配置。

- `main-menu.png`：新安装的主菜单，无节点、后台或系统自启。
- `protocols.png`：实际新增节点流程的协议选择页，未选择协议或生成凭据。
- `network-settings.png`：IPv6 / 防火墙设置入口，未切换本机网络或防火墙状态。

捕获过程使用临时空目录，只读取菜单并返回；结束后退出进程，删除演示配置。**临时目录同样可能包含用户名、工作目录和机器信息，必须打码。** 主菜单截图将完整数据路径（含换行部分）替换为 `[已打码]\.nexus-edge`，只保留通用目录名；真实程序仍显示完整路径，方便用户定位配置。

截图脚本在渲染前处理终端帧的副本；无法确认路径边界或发现其他绝对路径时拒绝生成图片。超时日志不输出原始终端全文，PNG 不附带原始文本或路径元数据。发布前仍须逐张检查本机路径、用户名、主机名、真实地址、UUID、密码、Token、私钥及用户配置，不能只因使用空配置或临时目录就视为安全。

Windows 开发者可以复现：

```powershell
bun run build:release --target windows-x64
python -m pip install pywinpty==3.1.2 pyte==0.8.2 Pillow
python -X utf8 tests/snapshot-privacy.py
python -X utf8 scripts/capture-snapshots.py dist/windows-x64/nexus-edge-windows-x64.exe
```

截图脚本使用系统自带 Consolas / Microsoft YaHei 字体。只需要发布者安装这些测试依赖，使用 NexusEdge 的用户不需要 Python 或 Bun。
