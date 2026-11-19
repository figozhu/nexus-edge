import * as backupPanelPath from "node:path";
import { type AppPaths, readConfig } from "./core.ts";
import { getDaemonStatus } from "./daemon.ts";
import { exportConfigBackup, prepareConfigImport, commitConfigImport, validateBackupPassword } from "./backup.ts";
import { selectMenu, promptInput, uiValidatedInput, UserCancelledError } from "./ui.ts";

export interface BackupPanelServices { running: (paths: AppPaths) => Promise<boolean> }
const backupPanelNotice = "包含 UUID、密码、证书私钥、Tunnel Token 和 WARP 凭据；文件以密码加密。\n请妥善保存文件，密码通过另一渠道传递；丢失密码无法恢复。不会自动上传备份。";

/** Shared Windows/Linux terminal flow. Confirmed imports only save, never apply. */
export async function runBackupPanel(paths: AppPaths, overrides: Partial<BackupPanelServices> = {}): Promise<void> {
  const service: BackupPanelServices = { running: async paths => Boolean(await getDaemonStatus(paths)), ...overrides };
  const action = await selectMenu("配置备份 / 迁移", `${backupPanelNotice}\n迁移整个节点配置；客户端配置仍在“查看链接 / 导出客户端配置”。`, ["导出加密备份", "导入加密备份", "返回"]);
  if (action === 2) return;
  if (action === 0) {
    const defaultName = backupPanelPath.join(paths.root, `nexus-edge-${new Date().toISOString().replace(/[:.]/g, "-")}.nexus-backup`);
    const filename = (await promptInput("保存备份文件路径（新文件）", defaultName)).replace(/^"(.*)"$/, "$1");
    const password = await uiValidatedInput("备份密码（至少 12 个字符）", "", validateBackupPassword, { secret: true });
    const repeated = await promptInput("再次输入备份密码", "", { secret: true });
    if (repeated !== password) throw new Error("两次密码不一致，未导出文件。");
    exportConfigBackup(readConfig(paths), filename, password);
    console.log(`加密备份已保存：${filename}\n请将该文件与密码分别安全传到新服务器。`);
    return;
  }
  if (await service.running(paths)) throw new Error("请先从主菜单停止全部节点，再导入配置。导入不会停止服务或修改防火墙。");
  const filename = (await promptInput("待导入的 .nexus-backup 文件路径")).replace(/^"(.*)"$/, "$1");
  const password = await promptInput("备份密码", "", { secret: true });
  const preview = prepareConfigImport(paths, filename, password);
  const choice = await selectMenu("确认导入配置", [
    `来源版本：${preview.appVersion}；备份时间：${preview.createdAt}`,
    `节点：${preview.config.nodes.length} 个；WARP：${preview.config.warp ? "包含" : "无"}`,
    `目标：${paths.config}`,
    preview.expected === null ? "将在当前目录创建配置。" : "将替换当前配置（不合并）；覆盖前保存独立的原配置恢复副本。",
    "全部节点停用；旧服务器 IP 清空，域名保留但须核对 DNS / NAT / 端口及 TLS 证书。",
    "专用网卡监听改为同族通配地址；原通配 / 回环监听保留；隧道连接覆盖地址清空。",
    "防火墙改为手动、通知关闭、核心出站 IPv6 关闭；原机器服务和防火墙规则不迁移。",
    "导入后在节点管理检查并启用节点，再手动启动；不会自动启动、安装核心或开放端口。",
  ].join("\n"), ["取消，保留当前配置", "确认替换并导入"]);
  if (choice !== 1) throw new UserCancelledError();
  if (await service.running(paths)) throw new Error("后台已启动，请停止全部节点后重新导入；原配置未改变。");
  const result = commitConfigImport(paths, preview);
  console.log(`配置已导入，全部节点保持停用。${result.recovery ? `\n原配置恢复副本：${result.recovery}` : ""}\n请检查连接地址、监听端口、证书、DNS 和防火墙设置，再启用及启动节点。`);
}
