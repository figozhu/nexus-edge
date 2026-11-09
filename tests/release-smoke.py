#!/usr/bin/env python3
"""Run the generated single file from a different working directory in a PTY.

Requires a POSIX PTY and an environment without an activated system NexusEdge
installation. Does not create a node, download a core, or start a daemon.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import time

if os.name != "posix":
    raise SystemExit("This test needs a POSIX PTY; see VALIDATION.md for Windows checks.")
import fcntl
import pty
import termios

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"))
args = parser.parse_args()
bun = shutil.which(args.bun)
if not bun:
    parser.error("Bun executable not found")
bun = str(Path(bun).resolve())
source = Path(__file__).resolve().parent.parent / "nexus-edge.ts"
with tempfile.TemporaryDirectory(prefix="nexus-release-smoke-") as directory:
    root = Path(directory)
    script_dir = root / "发布 中文 空格"
    work_dir = root / "不同 工作目录"
    script_dir.mkdir()
    work_dir.mkdir()
    entry = script_dir / "nexus-edge.ts"
    shutil.copyfile(source, entry)
    version = subprocess.run([bun, str(entry), "--version"], cwd=work_dir, capture_output=True, text=True, check=True)
    assert version.stdout.strip() == "2.3.3", version.stdout
    help_result = subprocess.run([bun, str(entry), "--help"], cwd=work_dir, capture_output=True, text=True, check=True)
    assert "隧道按节点可选" in help_result.stdout and "Shadowsocks" not in help_result.stderr
    assert not (script_dir / ".nexus-edge").exists(), "Help/version should not initialize configuration"
    bad_helper = subprocess.run([bun, str(entry), "--firewall-request", "../escape"], cwd=work_dir, capture_output=True, text=True)
    assert bad_helper.returncode != 0, "Invalid firewall helper request was accepted"
    for invalid_args in [[], ["status"], ["enable", "../escape"]]:
        bad_ipv6 = subprocess.run([bun, str(entry), "--host-ipv6", *invalid_args], cwd=work_dir, capture_output=True, text=True)
        assert bad_ipv6.returncode != 0, "Invalid IPv6 helper arguments were accepted"
        assert "仅接受 enable 或 disable" in bad_ipv6.stderr, bad_ipv6.stderr
    assert not (script_dir / ".nexus-edge").exists(), "Invalid helper must not initialize configuration or a firewall"
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([bun, str(entry)], cwd=work_dir, stdin=slave, stdout=slave, stderr=slave,
                               env=dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8"), start_new_session=True)
    output = bytearray()

    def send_expect(keys, text, timeout=10):
        """发送 keys 字节并等待随后出现的 text；超时抛出完整终端输出，不复用旧画面。"""
        start = len(output)
        os.write(master, keys)
        deadline = time.monotonic() + timeout
        wanted = text.encode()
        while wanted not in output[start:]:
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(output.decode("utf-8", errors="replace"))
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))

    try:
        deadline = time.monotonic() + 15
        marker = "退出面板（保留后台）".encode()
        while marker not in output:
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(output.decode("utf-8", errors="replace"))
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output.extend(os.read(master, 65536))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
        assert "隧道默认关闭".encode() in output
        # 单文件内核菜单仅查询已有状态，返回后使用字母快捷键退出。
        os.write(master, b"8")
        deadline = time.monotonic() + 10
        core_marker = "检查更新（稳定版，推荐）".encode()
        while core_marker not in output:
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(output.decode("utf-8", errors="replace"))
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        assert b"sing-box" in output and b"cloudflared" in output
        checkpoint = len(output)
        os.write(master, b"4")
        deadline = time.monotonic() + 10
        while marker not in output[checkpoint:]:
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(output.decode("utf-8", errors="replace"))
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        data = script_dir / ".nexus-edge"
        initial = json.loads((data / "config.json").read_text())
        assert initial == {"schema": 2, "nodes": [], "webhook": {"kind": "none", "url": ""}}, initial
        send_expect(b"9", "IPv6 / 防火墙设置")
        # 核心设置只保存往返，不启动节点；验证持久化开关和返回路径。
        for selection, expected in [(b"2", True), (b"1", False)]:
            send_expect(b"1", "开启 IPv6（双栈）")
            send_expect(selection, "仅保存，稍后重启")
            send_expect(b"2", "按 Enter 返回面板")
            saved = json.loads((data / "config.json").read_text())
            assert saved["coreIpv6"] is expected, saved
            send_expect(b"\r", "IPv6 / 防火墙设置")
        # 系统接口菜单只读进入后立即返回，不选择启用或禁用，不请求提权。
        send_expect(b"2", "刷新状态")
        send_expect(b"4", "IPv6 / 防火墙设置")
        checkpoint = len(output)
        send_expect(b"3", "立即检查 / 放行已启用节点端口")
        assert "自动管理".encode() in output[checkpoint:]
        assert "无须开放入站端口".encode() in output[checkpoint:]
        send_expect(b"\x1b", "退出面板（保留后台）")
        send_expect(b"j", "是否保留配置文件")
        send_expect(b"c", "退出面板（保留后台）")
        os.write(master, b"k")
        process.wait(timeout=5)
        assert process.returncode == 0
        assert termios.tcgetattr(slave) == original, "Terminal mode was not restored"
        data = script_dir / ".nexus-edge"
        config = json.loads((data / "config.json").read_text())
        assert config == {"schema": 2, "nodes": [], "coreIpv6": False, "webhook": {"kind": "none", "url": ""}}, config
        assert not (data / "runtime.json").exists() and not (data / "node-link.txt").exists()
        assert not (data / "firewall-state.json").exists() and not (data / "firewall-linux-state.json").exists()
        assert not (data / "bin").exists() or not list((data / "bin").iterdir())
        assert not list(work_dir.iterdir()), "Application used cwd instead of the script directory"
        print("PASS generated single file: help/version, invalid helpers, Unicode paths, IPv6 save roundtrip, read-only interface/firewall menus, empty default, no system changes, clean PTY exit")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        termios.tcsetattr(slave, termios.TCSANOW, original)
        os.close(master)
        os.close(slave)
