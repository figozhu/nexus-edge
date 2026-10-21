#!/usr/bin/env python3
"""Real Bun PTY regression tests for the two UI input primitives, no services.

Usage:
  python3 tests/ui-pty.py --bun /absolute/path/to/bun
  NEXUS_EDGE_BUN=/absolute/path/to/bun python3 tests/ui-pty.py

Uses only Python's standard library. Linux/macOS test harness; the application
itself still targets Windows/Linux. No download, account registration, proxy
listener, daemon, system service, or production configuration is created.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

if os.name != "posix":
    raise SystemExit("This regression harness requires a POSIX PTY. Run it on Linux with Bun.")

import fcntl
import pty
import termios


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "ui-entry.ts"
EVENT = re.compile(rb"__NEXUS_PTY__(\{[^\r\n]*\})")
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)")


class Terminal:
    def __init__(self, bun: str, scenario: str, fixture: Path = FIXTURE):
        self.scenario = scenario
        self.scratch = tempfile.TemporaryDirectory(prefix="nexus-ui-pty-")
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        self.original_attributes = termios.tcgetattr(self.slave)
        self.output = bytearray()
        self.position = 0
        env = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8", NO_COLOR="1")
        self.process = subprocess.Popen(
            [bun, str(fixture), scenario],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            cwd=self.scratch.name,
            env=env,
            start_new_session=True,
            close_fds=True,
        )

    def diagnostic(self) -> str:
        clean = ANSI.sub(b"", bytes(self.output[-6000:]))
        return clean.decode("utf-8", errors="replace")

    def read(self, wait: float = 0.1) -> bool:
        if not select.select([self.master], [], [], wait)[0]:
            return False
        try:
            data = os.read(self.master, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        self.output.extend(data)
        return bool(data)

    def expect(self, value: str | bytes, timeout: float = 5.0) -> None:
        expected = value.encode("utf-8") if isinstance(value, str) else value
        deadline = time.monotonic() + timeout
        while True:
            at = self.output.find(expected, self.position)
            if at >= 0:
                self.position = at + len(expected)
                return
            if time.monotonic() >= deadline or self.process.poll() is not None:
                self.read(0)
                at = self.output.find(expected, self.position)
                if at >= 0:
                    self.position = at + len(expected)
                    return
                raise AssertionError(f"{self.scenario}: missing {expected!r}\n{self.diagnostic()}")
            self.read(min(0.1, max(0, deadline - time.monotonic())))

    def event(self, name: str, timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            match = EVENT.search(self.output, self.position)
            if match:
                self.position = match.end()
                value = json.loads(match.group(1).decode("utf-8"))
                if value.get("event") != name:
                    raise AssertionError(f"{self.scenario}: expected event {name}, got {value}\n{self.diagnostic()}")
                if value.get("raw"):
                    raise AssertionError(f"{self.scenario}: raw mode remained active after {name}")
                return value
            if time.monotonic() >= deadline or self.process.poll() is not None:
                self.read(0)
                if EVENT.search(self.output, self.position):
                    continue
                raise AssertionError(f"{self.scenario}: missing event {name}\n{self.diagnostic()}")
            self.read(min(0.1, max(0, deadline - time.monotonic())))

    def send(self, value: str | bytes) -> None:
        data = value.encode("utf-8") if isinstance(value, str) else value
        while data:
            data = data[os.write(self.master, data):]

    def assert_no_echo(self) -> None:
        attributes = termios.tcgetattr(self.slave)
        if attributes[3] & termios.ECHO:
            raise AssertionError(f"{self.scenario}: the terminal would echo secret input")

    def finish(self, allow_files: bool = False) -> None:
        self.event("done")
        self.process.wait(timeout=5)
        while self.read(0):
            pass
        if self.process.returncode:
            raise AssertionError(f"{self.scenario}: fixture exited {self.process.returncode}\n{self.diagnostic()}")
        attributes = termios.tcgetattr(self.slave)
        if attributes != self.original_attributes:
            raise AssertionError(f"{self.scenario}: terminal attributes were not restored")
        output = bytes(self.output)
        if b"\x1b[?25l" in output and output.rfind(b"\x1b[?25h") < output.rfind(b"\x1b[?25l"):
            raise AssertionError(f"{self.scenario}: cursor was left hidden")
        if not allow_files and list(Path(self.scratch.name).iterdir()):
            raise AssertionError(f"{self.scenario}: primitive UI fixture unexpectedly wrote files")

    def close(self) -> None:
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)
        termios.tcsetattr(self.slave, termios.TCSANOW, self.original_attributes)
        os.close(self.master)
        os.close(self.slave)
        self.scratch.cleanup()


def run_cycles(terminal: Terminal) -> None:
    actions = [b"\r", b"j\r", b"3"]
    for round_number in range(1, 4):
        terminal.expect(f"循环菜单 {round_number}")
        terminal.send(actions[round_number - 1])
        selected = terminal.event("selected")
        assert selected["round"] == round_number and selected["selected"] == round_number - 1, selected
        terminal.expect(f"中文输入 {round_number}")
        text = f"你好，世界 第{round_number}轮 ✓"
        terminal.send(text + "\r")
        answer = terminal.event("input")
        assert answer["round"] == round_number and answer["text"] == text, answer
        terminal.expect(f"返回菜单 {round_number}")
        terminal.send(b"\x1b[B\r")
        returned = terminal.event("returned")
        assert returned["round"] == round_number and returned["selected"] == 1, returned
        assert returned["keypressListeners"] == 0, returned


def run_secret(terminal: Terminal) -> None:
    secret = "PTY_SECRET_7c19a_机密_+/="
    terminal.expect("请输入测试密钥")
    terminal.assert_no_echo()
    terminal.send(secret + "\r")
    result = terminal.event("secret")
    assert result["length"] == len(secret), result
    assert result["sha256"] == hashlib.sha256(secret.encode("utf-8")).hexdigest(), result
    terminal.expect("请输入可见中文")
    terminal.send("可见输入恢复正常\r")
    visible = terminal.event("visible")
    assert visible["text"] == "可见输入恢复正常", visible
    for forbidden in [secret.encode("utf-8"), b"PTY_SECRET_7c19a", "机密".encode("utf-8")]:
        assert forbidden not in terminal.output, "secret input was echoed"


def run_ctrlc(terminal: Terminal) -> None:
    terminal.expect("CtrlC 菜单")
    terminal.send(b"\x03")
    menu_cancelled = terminal.event("menu-cancelled")
    assert menu_cancelled["cancelled"] is True and menu_cancelled["exitRequested"] is True
    terminal.expect("菜单取消后输入")
    terminal.send("取消之后仍可输入\r")
    assert terminal.event("after-menu-cancel")["text"] == "取消之后仍可输入"
    terminal.expect("CtrlC 密钥输入")
    terminal.assert_no_echo()
    terminal.send("partial-secret")
    terminal.send(b"\x03")
    input_cancelled = terminal.event("input-cancelled")
    assert input_cancelled["cancelled"] is True and input_cancelled["exitRequested"] is True
    terminal.expect("取消后的菜单")
    terminal.send(b"2")
    assert terminal.event("after-input-cancel")["selected"] == 1
    assert b"partial-secret" not in terminal.output, "cancelled secret input was echoed"


def run_escape(terminal: Terminal) -> None:
    terminal.expect("协议选择测试")
    terminal.send(b"\x1b")
    cancelled = terminal.event("escape-cancelled")
    assert cancelled["cancelled"] is True and cancelled["exitRequested"] is False
    terminal.expect("Esc 取消后输入")
    terminal.send("保留原协议\r")
    assert terminal.event("after-escape")["text"] == "保留原协议"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"), help="Bun executable (>= 1.4.3)")
    parser.add_argument("--scenario", choices=["all", "cycles", "secret", "ctrlc", "escape"], default="all")
    args = parser.parse_args()
    bun = shutil.which(args.bun)
    if not bun:
        parser.error(f"Bun executable not found: {args.bun}")
    bun = str(Path(bun).resolve())
    scenarios = {"cycles": run_cycles, "secret": run_secret, "ctrlc": run_ctrlc, "escape": run_escape}
    failures = 0
    for name, action in scenarios.items():
        if args.scenario not in ("all", name):
            continue
        terminal = Terminal(bun, name)
        try:
            started = terminal.event("start")
            assert started["stdinTTY"] and started["stdoutTTY"], started
            action(terminal)
            terminal.finish()
            print(f"PASS {name}: keyboard flow, cooked-mode restoration, cursor, and clean exit", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {error}", file=sys.stderr, flush=True)
        finally:
            terminal.close()
    print(f"PTY UI tests: {len(scenarios) if args.scenario == 'all' else 1} scenarios, {failures} failures.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
