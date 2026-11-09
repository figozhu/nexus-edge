# TUI 界面截图

这些 PNG 是 NexusEdge 3.0.0 独立程序的真实 Windows ConPTY 输出帧，经 ANSI 终端解析器按原文本、布局和颜色渲染。不是生成式示意图，也不包含桌面、账号或生产配置。

- `main-menu.png`：新安装的主菜单，无节点、后台或系统自启。
- `protocols.png`：实际新增节点流程的协议选择页，未选择协议或生成凭据。
- `network-settings.png`：IPv6 / 防火墙设置入口，未切换本机网络或防火墙状态。

捕获过程使用临时空目录，只读取菜单并返回；结束后退出进程，删除演示配置。主菜单显示的是该临时目录，不是实际安装路径。发布前须逐张检查没有真实地址、UUID、密码、Token、私钥或用户配置。

Windows 开发者可以复现：

```powershell
bun run build:release --target windows-x64
python -m pip install pywinpty==3.1.2 pyte==0.8.2 Pillow
python -X utf8 scripts/capture-snapshots.py dist/windows-x64/nexus-edge-windows-x64.exe
```

截图脚本使用系统自带 Consolas / Microsoft YaHei 字体。只需要发布者安装这些测试依赖，使用 NexusEdge 的用户不需要 Python 或 Bun。
