"""截图发布隐私回归：只使用虚构目录和内存终端，不启动应用或访问用户配置。"""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

import pyte
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("capture_snapshots", ROOT / "scripts" / "capture-snapshots.py")
snapshots = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshots)


def menu(path: str) -> pyte.Screen:
    """用 path（str，虚构目录）生成带 ANSI 颜色和自动换行的主菜单，返回内存屏幕。"""
    screen = pyte.Screen(120, 40)
    pyte.Stream(screen).feed(f"\x1b[36mNexusEdge\x1b[0m\r\n数据：{path}\r\n防火墙：自动管理\r\n退出面板")
    return screen


class SnapshotPrivacyTests(unittest.TestCase):
    """验证发布图片不依赖个人目录内容、长路径不残留，且原始产品界面保持完整。"""

    def test_paths_are_hidden_without_changing_live_screen(self) -> None:
        """短、中文、空格、UNC、POSIX 及多行路径全部隐藏；返回副本不改变原始屏幕。"""
        for path in [r"C:\private-demo\.nexus-edge", r"D:\演示 用户\内部目录\.nexus-edge",
                     "C:\\" + "private-demo\\" * 25 + ".nexus-edge",
                     "C:\\" + "演示 用户\\" * 25 + ".nexus-edge",
                     r"\\demo-host\private-share\.nexus-edge", "/home/demo-user/.nexus-edge"]:
            with self.subTest(kind="目录遮盖"):
                screen = menu(path)
                original = screen.display[:]
                safe = snapshots.publication_screen(screen, require_data_path=True)
                visible = "\n".join(safe.display)
                self.assertIn("数据：[已打码]\\.nexus-edge", visible)
                self.assertIn("防火墙：自动管理", visible)
                for part in ("private-demo", "演示 用户", "内部目录", "demo-host", "private-share", "demo-user"):
                    self.assertNotIn(part, visible)
                self.assertEqual(screen.display, original)
                self.assertEqual(safe.buffer[0][0].fg, screen.buffer[0][0].fg)

    def test_other_menus_keep_their_content(self) -> None:
        """无路径的协议和网络菜单应保持文字与颜色；参数和返回值均由测试框架管理。"""
        screen = pyte.Screen(120, 40)
        pyte.Stream(screen).feed("\x1b[36mVLESS · TCP + REALITY\x1b[0m\r\nIPv6 / 防火墙设置")
        safe = snapshots.publication_screen(screen)
        self.assertEqual(screen.display, safe.display)
        self.assertEqual(screen.buffer[0][0], safe.buffer[0][0])

    def test_unknown_or_incomplete_layout_is_rejected(self) -> None:
        """字段消失、路径截断或下一个字段变化时拒绝发布；错误中不得包含原始内容。"""
        for raw in ("新目录：C:\\private-demo", "数据：C:\\private-demo\\.nexus-edge",
                    "数据：C:\\private-demo\\截断\r\n防火墙：自动管理",
                    "数据：C:\\private-demo\\.nexus-edge\r\n数据：重复\r\n防火墙：自动管理"):
            screen = pyte.Screen(120, 40)
            pyte.Stream(screen).feed(raw)
            with self.assertRaises(RuntimeError) as caught:
                snapshots.publication_screen(screen, require_data_path=True)
            self.assertNotIn("private-demo", str(caught.exception))

    def test_unhandled_paths_in_other_fields_are_rejected(self) -> None:
        """其他字段新增 Windows、UNC 或 POSIX 绝对路径时，也不能生成未经处理的截图。"""
        for path in (r"C:\private-demo\file", r"\\demo-host\share\file", "/home/demo-user/file"):
            screen = pyte.Screen(120, 40)
            pyte.Stream(screen).feed(f"配置备份：{path}")
            with self.assertRaises(RuntimeError):
                snapshots.publication_screen(screen)

    @unittest.skipUnless(os.name == "nt", "像素验证使用 Windows 系统字体")
    def test_png_pixels_do_not_depend_on_hidden_path(self) -> None:
        """两个长度不同的虚构路径必须生成相同 PNG，且图片无元数据，无原始像素残留。"""
        with tempfile.TemporaryDirectory(prefix="snapshot-privacy-") as temporary:
            first, second = Path(temporary) / "first.png", Path(temporary) / "second.png"
            snapshots.render(menu(r"C:\private-demo\.nexus-edge"), first, require_data_path=True)
            snapshots.render(menu(r"D:\演示 用户\内部目录\.nexus-edge"), second, require_data_path=True)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with Image.open(first) as image:
                self.assertEqual(image.info, {})

    def test_failed_redaction_does_not_write_png(self) -> None:
        """无法确认脱敏字段时，在创建图片文件前失败，避免留下可发布的泄露产物。"""
        with tempfile.TemporaryDirectory(prefix="snapshot-privacy-") as temporary:
            output = Path(temporary) / "rejected.png"
            with self.assertRaises(RuntimeError):
                snapshots.render(pyte.Screen(120, 40), output, require_data_path=True)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
