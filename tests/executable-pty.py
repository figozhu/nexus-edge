"""在原生终端验收发布程序；无 Bun PATH，不接触已有系统安装或网络配置。"""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

if os.name == "nt":
    from windows_pty import WindowsPtyProcess
else:
    import pty
    import termios


def verify(binary: Path, bun: str | None = None) -> None:
    """复制 binary 到中文临时目录，验证真实菜单、配置持久化、取消卸载和退出；始终清理进程。"""
    with tempfile.TemporaryDirectory(prefix="nexus-executable-pty-") as directory:
        root = Path(directory)
        portable, cwd = root / "程序 中文 空格", root / "工作目录"
        portable.mkdir()
        cwd.mkdir()
        entry = portable / ("nexus-edge.ts" if bun else "nexus-edge.exe" if os.name == "nt" else "nexus-edge")
        shutil.copy2(binary, entry)
        entry.chmod(0o755)
        env = {key: value for key, value in os.environ.items() if key.upper() not in ("PATH", "BUN_BE_BUN")}
        env["PATH"] = os.pathsep.join(part for part in os.environ.get("PATH", "").split(os.pathsep)
                                      if part and not (Path(part) / ("bun.exe" if os.name == "nt" else "bun")).exists())
        env.update(TERM="xterm-256color", LANG="C.UTF-8")
        assert shutil.which("bun", path=env["PATH"]) is None
        command = ([bun] if bun else []) + [str(entry), "--local"]
        if os.name == "nt":
            child = WindowsPtyProcess(command, str(cwd), env)
        else:
            master, slave = pty.openpty()
            original = termios.tcgetattr(slave)
            child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                     cwd=cwd, env=env, start_new_session=True)
        output = bytearray()
        position = 0

        def expect(text: str) -> None:
            """在 15 秒内等待尚未消费的菜单文案；超时打印本测试终端输出。"""
            nonlocal position
            target = text.encode()
            deadline = time.monotonic() + 15
            while target not in output[position:]:
                if time.monotonic() >= deadline:
                    raise AssertionError(f"未显示 {text}: {output.decode(errors='replace')}")
                if os.name == "nt":
                    output.extend(child.read(0.1))
                elif select.select([master], [], [], 0.1)[0]:
                    output.extend(os.read(master, 65536))
            position = output.index(target, position) + len(target)

        def send(keys: bytes, text: str) -> None:
            """发送真实按键后等待目标界面，防止连续输入吞键掩盖交互错误。"""
            if os.name == "nt":
                child.write(keys)
            else:
                os.write(master, keys)
            expect(text)

        try:
            expect("退出面板（保留后台）")
            # 覆盖无 Readline 的连续菜单返回，再进入其他菜单；Windows 曾在此停止投递按键。
            send(b"c", "新增节点（简易模式）")
            send(b"a", "选择节点协议 · 简易模式")
            send(b"\x1b", "新增节点（简易模式）")
            send(b"g", "退出面板（保留后台）")
            send(b"i", "IPv6 / 防火墙设置")
            send(b"a", "开启 IPv6（双栈）")
            send(b"b", "仅保存，稍后重启")
            send(b"b", "按 Enter 返回面板")
            config = portable / ".nexus-edge" / "config.json"
            assert json.loads(config.read_text(encoding="utf-8"))["coreIpv6"] is True
            send(b"\r", "IPv6 / 防火墙设置")
            send(b"\x1b", "退出面板（保留后台）")
            send(b"j", "是否保留配置文件")
            send(b"c", "退出面板（保留后台）")
            send(b"k", "已退出面板")
            assert child.wait(timeout=10) == 0
            saved = json.loads(config.read_text(encoding="utf-8"))
            assert saved["nodes"] == [] and saved["coreIpv6"] is True
            assert not list(cwd.iterdir())
            assert not (portable / ".nexus-edge" / "runtime.json").exists()
            if os.name != "nt":
                assert termios.tcgetattr(slave) == original
            print("PASS 独立程序原生 PTY：无 Bun、中文目录、保存设置、取消卸载、退出及终端恢复")
        finally:
            if os.name == "nt":
                child.close()
            else:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                termios.tcsetattr(slave, termios.TCSANOW, original)
                os.close(master)
                os.close(slave)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--bun", help="仅用于对照源码形式，传入 Bun 的绝对路径")
    args = parser.parse_args()
    verify(args.binary.resolve(), args.bun)
