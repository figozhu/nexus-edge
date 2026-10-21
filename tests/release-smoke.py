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
    assert version.stdout.strip() == "2.2.1", version.stdout
    help_result = subprocess.run([bun, str(entry), "--help"], cwd=work_dir, capture_output=True, text=True, check=True)
    assert "隧道按节点可选" in help_result.stdout and "Shadowsocks" not in help_result.stderr
    assert not (script_dir / ".nexus-edge").exists(), "Help/version should not initialize configuration"
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([bun, str(entry)], cwd=work_dir, stdin=slave, stdout=slave, stderr=slave,
                               env=dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8"), start_new_session=True)
    output = bytearray()
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
        # The new version menu must work in the generated single file, stay
        # read-only on entry, and return to the correct nine-item main menu.
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
        os.write(master, b"9")
        process.wait(timeout=5)
        assert process.returncode == 0
        assert termios.tcgetattr(slave) == original, "Terminal mode was not restored"
        data = script_dir / ".nexus-edge"
        config = json.loads((data / "config.json").read_text())
        assert config == {"schema": 2, "nodes": [], "webhook": {"kind": "none", "url": ""}}, config
        assert not (data / "runtime.json").exists() and not (data / "node-link.txt").exists()
        assert not (data / "bin").exists() or not list((data / "bin").iterdir())
        assert not list(work_dir.iterdir()), "Application used cwd instead of the script directory"
        print("PASS generated single file: help/version, Unicode paths, read-only core menu, empty default, no tunnel/core, clean PTY exit")
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
