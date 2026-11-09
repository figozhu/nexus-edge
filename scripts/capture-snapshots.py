"""捕获独立程序的真实 ConPTY 输出并渲染 PNG，只操作空的演示目录。

开发依赖：pywinpty==3.1.2、pyte==0.8.2、Pillow。不会创建节点、探测公网、下载核心或修改系统设置。
截图是实际终端帧的脱敏重绘；发布前遮盖本机目录，不采集用户桌面或既有配置。
"""
import argparse
from copy import deepcopy
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))


def publication_screen(screen: pyte.Screen, *, require_data_path: bool = False) -> pyte.Screen:
    """返回可发布的终端帧副本，保留真实运行界面的完整配置路径。

    参数 screen 是已解析 ANSI 的原始屏幕；require_data_path 为 True 时要求主菜单
    的数据目录字段存在。返回深复制后的 pyte.Screen，不修改调用方的终端状态。
    从“数据”字段遮盖到下一个“防火墙”字段，包含长路径的全部换行；只保留通用
    目录名 .nexus-edge。字段缺失、边界变化或其他绝对路径残留时抛错，禁止落盘，
    错误信息不携带原始终端内容。此函数不替代凭据和地址的人工发布检查。
    """
    safe = deepcopy(screen)
    lines = screen.display
    data_rows = [row for row, line in enumerate(lines) if re.match(r"\s*数据[:：]", line)]
    if len(data_rows) > 1 or (require_data_path and not data_rows):
        raise RuntimeError("截图脱敏失败：主菜单数据目录字段缺失或重复，未生成图片。")
    for row in data_rows:
        end = next((index for index in range(row + 1, screen.lines)
                    if re.match(r"\s*防火墙[:：]", lines[index])), None)
        if end is None or not "".join(lines[row:end]).rstrip().endswith(".nexus-edge"):
            raise RuntimeError("截图脱敏失败：无法确认数据目录边界，未生成图片。")
        # 通过终端列定位冒号，避免中文全角字符的字符串索引与显示列数不一致。
        column = next(index + 1 for index in range(screen.columns)
                      if screen.buffer[row][index].data in (":", "："))
        while column < screen.columns and not screen.buffer[row][column].data:
            column += 1
        for index in range(row, end):
            safe.cursor_position(index + 1, column + 1 if index == row else 1)
            safe.erase_in_line(0)
        safe.cursor_position(row + 1, column + 1)
        safe.select_graphic_rendition(0)
        safe.draw("[已打码]\\.nexus-edge")
    # 当前三个菜单无需公开任何绝对路径；新增路径字段时先拒绝发布再补充脱敏规则。
    if re.search(r"[A-Za-z]:[\\/]|\\\\[^\s\\]+\\|(?<!\w)/(?:[^\s/]+/)", "\n".join(safe.display)):
        raise RuntimeError("截图脱敏失败：检测到未处理的绝对路径，未生成图片。")
    return safe


def render(screen: pyte.Screen, destination: Path, *, require_data_path: bool = False) -> None:
    """将 screen 的脱敏副本按原单元格和颜色写入 destination（Path），无返回值。

    require_data_path 标记主菜单的必需脱敏字段；验证失败时不写入文件。新建 RGB
    图片，不保存原始帧、路径或 EXIF/文本元数据，真实终端缓冲区保持不变。
    """
    screen = publication_screen(screen, require_data_path=require_data_path)
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
    from windows_pty import WindowsPtyProcess

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
            """等待 marker（str）及完整帧；start（int）限定本轮输出，无返回值。

            超时仅报告预期菜单名，避免将包含本机目录的原始终端全文写入日志。
            """
            nonlocal text
            deadline = time.monotonic() + 20
            while marker not in text[start:]:
                data = child.read(0.1).decode("utf-8")
                text += data
                stream.feed(data)
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"等待菜单失败：{marker}（原始终端内容未输出）")
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
            render(screen, output / "main-menu.png", require_data_path=True)
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
