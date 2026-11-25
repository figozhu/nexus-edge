import { type AppPaths } from "./core.ts";
import { readTrafficReport } from "./traffic-store.ts";
import { startTrafficDashboard } from "./traffic-web.ts";
import { selectMenu } from "./ui.ts";

/** Shared Windows/Linux user entry; finally closes the listener on Back, Ctrl+C, or errors. */
export async function runTrafficPanel(paths: AppPaths): Promise<void> {
  for (;;) {
    const report = readTrafficReport(paths);
    const count = report.nodes.length;
    const choice = await selectMenu("流量统计 / 分析", [
      `近 24 小时有 ${count} 个节点 / 端口记录；${report.oldest === null ? "尚无采集数据" : "最早现存记录：" + new Date(report.oldest).toLocaleString()}`,
      "新版后台启动后每 10 秒采集，按 5 分钟归档，最多保留 30 天；旧记录无法补算。",
      "Xray 按节点账号计数；sing-box 节点与来源为观察下限；IP 是来源线索，不是设备身份。",
      "应用层字节不等于 Windows 进程用量或云商账单。查看页面不会启停节点或修改防火墙。",
    ].join("\n"), ["启动临时只读网页", "返回"]);
    if (choice === 1) return;
    const dashboard = startTrafficDashboard(paths);
    try {
      await selectMenu("流量分析网页已启动", [
        "在这台电脑的浏览器打开以下完整链接（包括 # 后的访问码）：", dashboard.url,
        "仅监听 127.0.0.1；30 分钟后自动到期。保留此菜单时可查看，关闭页面服务不停止后台采集。",
        `通过 SSH 查看时，在自己电脑转发同一端口：ssh -L ${dashboard.port}:127.0.0.1:${dashboard.port} 用户@服务器`,
        "然后在自己电脑打开同一链接。不要开放公网端口或分享临时链接。",
      ].join("\n"), ["关闭临时网页并返回"]);
    } finally { await dashboard.close(); }
  }
}
