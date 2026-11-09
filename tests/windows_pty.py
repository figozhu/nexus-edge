"""Windows 原生 ConPTY 适配，仅供临时目录内的 TUI 回归测试使用。

安装可选测试依赖：python -m pip install pywinpty。
不使用 shell，不启动代理核心或系统服务，也不访问现有节点配置。
"""

from __future__ import annotations

import os
import signal
import subprocess
import time

try:
    from winpty import PTY
except ImportError as error:
    raise SystemExit("Windows PTY 测试需要 pywinpty：python -m pip install pywinpty") from error


class WindowsPtyProcess:
    """以 subprocess 所需的最小接口封装原生 ConPTY，全部读取都有时间上限。"""

    def __init__(self, argv: list[str], cwd: str, env: dict[str, str]):
        """启动 argv 指定的测试进程；cwd 为临时目录，env 为该进程的环境副本。"""
        self.pty = PTY(120, 40, backend=0)
        self.pid: int | None = None
        self.returncode: int | None = None
        try:
            spawned = self.pty.spawn(
                argv[0], cmdline=" " + subprocess.list2cmdline(argv[1:]), cwd=cwd,
                env="\0".join(f"{key}={value}" for key, value in env.items()) + "\0",
            )
            if not spawned:
                raise RuntimeError("ConPTY 未能启动测试进程。")
            self.pid = self.pty.pid
        except Exception:
            self.close()
            raise

    def poll(self) -> int | None:
        """返回测试进程退出码；仍在运行时返回 None，不阻塞调用方。"""
        if self.returncode is None and not self.pty.isalive():
            self.returncode = self.pty.get_exitstatus()
        return self.returncode

    def read(self, wait: float) -> bytes:
        """在 wait 秒内读取一批 UTF-8 终端输出；无输出时返回空字节串。"""
        deadline = time.monotonic() + wait
        while True:
            text = self.pty.read(blocking=False)
            if text:
                return text.encode("utf-8")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b""
            time.sleep(min(0.01, remaining))

    def write(self, value: bytes) -> None:
        """将 UTF-8 按键数据写入 ConPTY；调用方传入完整字符，避免截断中文。"""
        self.pty.write(value.decode("utf-8"))

    def wait(self, timeout: float) -> int:
        """等待测试进程结束并返回退出码，超时抛出 subprocess.TimeoutExpired。"""
        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("ConPTY fixture", timeout)
            time.sleep(0.01)
        return self.returncode

    def close(self) -> None:
        """只终止此适配器创建的测试进程并释放 ConPTY；临时文件由调用方清理。"""
        if self.pty is None:
            return
        try:
            if self.pid is not None and self.poll() is None:
                os.kill(self.pid, signal.SIGTERM)
                self.wait(timeout=2)
        finally:
            # 已退出的 ConPTY 可能没有待取消的 I/O；Windows 返回的此特定状态不代表进程未清理。
            exited = self.poll() is not None
            try:
                self.pty.cancel_io()
            except Exception as error:
                if not exited or str(error).strip() != "Element not found.":
                    raise
            finally:
                self.pty = None
