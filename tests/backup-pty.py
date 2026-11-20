#!/usr/bin/env python3
"""Verify migration with real Windows ConPTY / Linux PTY, isolated synthetic data only."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("panel_pty", ROOT / "tests" / "panel-pty.py")
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
PASSWORD = "synthetic migration password"


def exercise(t, scenario):
    start = t.event("start")
    config = Path(t.scratch.name, ".nexus-edge", "config.json")
    before = config.read_bytes()
    if scenario == "running":
        panel.choose(t, "配置备份 / 迁移", "导入加密备份")
        t.expect("请先从主菜单停止全部节点")
        assert t.event("failed")["hash"] == start["hash"]
        return
    panel.choose(t, "配置备份 / 迁移", "导出加密备份")
    panel.enter(t, "保存备份文件路径", "migration.nexus-backup")
    panel.enter(t, "备份密码（至少 12 个字符）", PASSWORD, secret=True)
    panel.enter(t, "再次输入备份密码", PASSWORD if scenario != "mismatch" else "different password", secret=True)
    if scenario == "mismatch":
        assert t.event("failed")["hash"] == start["hash"]
        assert not Path(t.scratch.name, "migration.nexus-backup").exists()
        return
    assert t.event("exported")["hash"] == start["hash"]
    backup = Path(t.scratch.name, "migration.nexus-backup")
    encrypted = backup.read_bytes()
    assert PASSWORD.encode() not in encrypted and b"198.51.100.28" not in encrypted
    if scenario == "corrupt":
        backup.write_bytes(encrypted[:80])
    panel.choose(t, "配置备份 / 迁移", "导入加密备份")
    panel.enter(t, "待导入的 .nexus-backup 文件路径", "migration.nexus-backup")
    if scenario == "ctrlc":
        t.expect("备份密码")
        t.send(b"\x03")
        assert t.event("exited")["hash"] == start["hash"]
    else:
        panel.enter(t, "备份密码", "incorrect long password" if scenario == "wrong-password" else PASSWORD, secret=True)
        if scenario in ("wrong-password", "corrupt"):
            assert t.event("failed")["hash"] == start["hash"]
        else:
            content = panel.screen(t, "确认导入配置")
            assert "全部节点停用" in content and "防火墙改为手动" in content
            assert config.read_bytes() == before
            if scenario == "cancel":
                t.send(b"\r")  # Safe default
                assert t.event("cancelled")["hash"] == start["hash"]
            else:
                panel.pick(t, content, "确认替换并导入")
                done = t.event("imported")
                assert done["enabled"] is False and done["address"] == "" and done["forbidden"] == 0
                recovery = list(config.parent.glob("config.json.pre-import.*.bak"))
                assert len(recovery) == 1 and recovery[0].read_bytes() == before
    if scenario != "roundtrip":
        assert config.read_bytes() == before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"))
    args = parser.parse_args()
    bun = shutil.which(args.bun)
    if not bun:
        parser.error("Bun not found")
    failures = 0
    cases = ["roundtrip", "cancel", "wrong-password", "corrupt", "ctrlc", "mismatch", "running"]
    for case in cases:
        terminal = panel.ui.Terminal(str(Path(bun).resolve()), case, ROOT / "tests" / "fixtures" / "backup-entry.ts")
        try:
            exercise(terminal, case)
            terminal.finish(allow_files=True)
            print(f"PASS backup {case}: private input, config persistence, no external operations", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL backup {case}: {error}", file=sys.stderr, flush=True)
        finally:
            terminal.close()
    print(f"Backup PTY: {len(cases)} scenarios, {failures} failures")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
