"""捕获独立程序的真实 ConPTY 输出并渲染 PNG，只操作空的演示目录。

开发依赖：pywinpty==3.1.2、pyte==0.8.2、Pillow。不会创建节点、探测公网、下载核心或修改系统设置。
截图是实际终端帧的重绘，不是虚构界面，也不采集用户桌面或既有配置。
"""
import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from windows_pty import WindowsPtyProcess


def render(screen: pyte.Screen, destination: Path) -> None:
    """按终端单元格、ANSI 颜色和全角字符宽度输出 PNG；不修改终端内容。"""
    rows = [row for row in range(screen.lines) if any(cell.data.strip() for cell in screen.buffer[row].values())]
    height = (max(rows, default=0) + 2) * 27 + 40
    image = Image.new("RGB", (120 * 12 + 48, height), "#10151f")
    draw = ImageDraw.Draw(image)
    fonts = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Fonts"
    latin = ImageFont.truetype(str(fonts / "consola.ttf"), 20)
    chinese = ImageFont.truetype(str(fonts / "msyh.ttc"), 20)
    colors = {"default": "#dce3ee", "white": "#e6edf3", "cyan": "#46d9e8", "yellow": "#f9d779",
              "green": "#84dd9a", "red": "#fb828c", "blue": "#81a9f4", "magenta": "#dba0e8", "black": "#10151f"}
    for y in range(max(rows, default=0) + 1):
        for x in range(screen.columns):
            cell = screen.buffer[y][x]
            if not cell.data or cell.data.isspace():
                continue
            color = colors.get(cell.fg, "#" + cell.fg if len(cell.fg) == 6 else colors["default"])
            font = chinese if any(ord(char) > 127 for char in cell.data) else latin
            draw.text((24 + x * 12, 20 + y * 27), cell.data, fill=color, font=font)
    image.save(destination, optimize=True)


def capture(binary: Path, output: Path) -> None:
    """复制真实发布程序到临时空目录并捕获三个菜单；关闭进程后清理全部演示配置。"""
    if os.name != "nt":
        raise RuntimeError("该截图脚本需要 Windows 原生 ConPTY。")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nexus-snapshot-") as temporary:
        demo = Path(temporary)
        entry = demo / "nexus-edge.exe"
        shutil.copy2(binary, entry)
        child = WindowsPtyProcess([str(entry), "--local"], str(demo), dict(os.environ, TERM="xterm-256color"))
        screen = pyte.Screen(120, 40)
        stream = pyte.Stream(screen)
        text = ""

        def wait_for(marker: str, start: int = 0) -> None:
            """等待实际菜单及完整输出帧；超时报告当前文本，不执行后续按键。"""
            nonlocal text
            deadline = time.monotonic() + 20
            while marker not in text[start:]:
                data = child.read(0.1).decode("utf-8")
                text += data
                stream.feed(data)
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"等待菜单失败：{marker}\n{text[start:]}")
            while True:
                data = child.read(0.25).decode("utf-8")
                if not data:
                    break
                text += data
                stream.feed(data)

        def key(value: bytes, marker: str) -> None:
            """向当前真实 TUI 发送一个菜单按键并等待新的界面。"""
            start = len(text)
            child.write(value)
            wait_for(marker, start)

        try:
            wait_for("退出面板（保留后台）")
            render(screen, output / "main-menu.png")
            key(b"c", "新增节点（简易模式）")
            key(b"a", "选择节点协议 · 简易模式")
            render(screen, output / "protocols.png")
            key(b"\x1b", "新增节点（简易模式）")
            key(b"g", "退出面板（保留后台）")
            key(b"i", "本机 IPv6 网络接口")
            render(screen, output / "network-settings.png")
            key(b"\x1b", "退出面板（保留后台）")
            key(b"k", "已退出面板")
            if child.wait(timeout=10) != 0:
                raise RuntimeError("截图用程序未正常退出。")
        finally:
            child.close()
    print(f"已捕获真实 TUI 终端帧：{output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "snapshot")
    arguments = parser.parse_args()
    capture(arguments.binary.resolve(), arguments.output.resolve())
