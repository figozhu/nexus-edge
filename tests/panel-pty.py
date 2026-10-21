#!/usr/bin/env python3
"""Exercise actual multi-node configuration workflows under a Bun PTY.

No core process, tunnel, external account, public listener, or network call is
created. All configuration files live in a temporary directory. Linux/macOS
harness; Windows requires the real-machine checks documented in VALIDATION.md.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("nexus_ui_pty", ROOT / "tests" / "ui-pty.py")
assert spec and spec.loader
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
FIXTURE = ROOT / "tests" / "fixtures" / "panel-entry.ts"


def choose(t, prompt, value=1):
    t.expect(prompt)
    t.send(str(value))


def enter(t, prompt, value=""):
    t.expect(prompt)
    t.send(str(value) + "\r")


def address(t, port=None, host=None, public=None, listen="127.0.0.1"):
    enter(t, "监听 IP", listen)
    enter(t, "本地监听端口", "" if port is None else port)
    enter(t, "客户端连接的公网 / 局域网 IP 或域名", "" if host is None else host)
    enter(t, "客户端连接端口", "" if public is None else public)


def finish_editor(t, save=1):
    choose(t, "此节点的出口")
    choose(t, "保存后的节点状态")
    choose(t, "保存节点", save)


def ss_editor(t, save=1):
    choose(t, "选择节点协议", 3)
    enter(t, "节点名称", "中文 SS 节点")
    address(t, 28380, "192.0.2.55", 38480)
    choose(t, "Shadowsocks 加密方法", 4)
    t.expect("密码（回车保留")
    t.assert_no_echo()
    t.send("SS_SECRET_not_echoed_9f+/=\r")
    finish_editor(t, save)


def run_multi_direct(t):
    ss_editor(t)
    ss = t.event("saved-1")["nodes"][0]
    assert ss["protocol"] == "shadowsocks" and ss["method"] == "aes-128-gcm", ss
    assert ss["address"] == "192.0.2.55" and ss["port"] == 28380 and ss["publicPort"] == 38480, ss
    assert ss["passwordHash"] == hashlib.sha256(b"SS_SECRET_not_echoed_9f+/=").hexdigest(), ss
    assert ss["tunnel"]["mode"] == "none" and ss["direct"], ss

    choose(t, "选择节点协议", 2)
    enter(t, "节点名称", "VMess 可选隧道关闭")
    choose(t, "传输方式", 2)
    enter(t, "传输路径", "/test-ws")
    enter(t, "传输 Host", "ws.example.test:8443")
    choose(t, "是否额外开启隧道", 1)
    address(t, 28086, "vmess.example.test", 38086)
    enter(t, "节点 UUID", "88888888-1111-4222-8333-444444444444")
    choose(t, "VMess 客户端加密方式")
    choose(t, "节点安全层", 1)
    finish_editor(t)
    nodes = t.event("saved-2")["nodes"]
    assert len(nodes) == 2 and nodes[0] == ss, nodes
    vmess = nodes[1]
    assert vmess["uuid"] == "88888888-1111-4222-8333-444444444444", vmess
    assert vmess["transport"]["type"] == "ws" and vmess["transport"]["path"] == "/test-ws", vmess
    assert vmess["transport"]["host"] == "ws.example.test:8443" and vmess["tunnel"]["mode"] == "none", vmess

    choose(t, "选择节点协议", 1)
    enter(t, "节点名称", "VLESS TCP 无隧道")
    choose(t, "传输方式", 1)
    address(t, 21080, "vless.example.test", 41080)
    enter(t, "节点 UUID", "99999999-1111-4222-8333-444444444444")
    choose(t, "节点安全层", 1)
    choose(t, "VLESS Encryption", 1)
    finish_editor(t)
    nodes = t.event("saved-3")["nodes"]
    assert len(nodes) == 3 and nodes[:2] == [ss, vmess], nodes
    assert nodes[2]["protocol"] == "vless" and nodes[2]["uuid"] == "99999999-1111-4222-8333-444444444444", nodes
    assert all(n["direct"] and n["tunnel"]["mode"] == "none" for n in nodes), nodes
    assert b"Tunnel Token" not in t.output and "隧道公共主机名".encode() not in t.output
    assert b"SS_SECRET_not_echoed" not in t.output, "Password appeared in terminal output"


def edit_vmess_start(t, mode):
    choose(t, "选择节点协议", 2)
    enter(t, "节点名称")
    choose(t, "传输方式", 2)
    enter(t, "传输路径")
    enter(t, "传输 Host")
    choose(t, "是否额外开启隧道", mode)


def edit_vmess_end(t, with_tls_menu=False):
    enter(t, "节点 UUID")
    choose(t, "VMess 客户端加密方式")
    if with_tls_menu:
        choose(t, "节点安全层", 1)
    finish_editor(t)


def run_tunnel_modes(t):
    original = t.event("seed")["nodes"][0]
    edit_vmess_start(t, 2)
    choose(t, "节点接入方式", 1)
    enter(t, "隧道客户端连接 IP / 域名")
    choose(t, "隧道连接传输", 2)
    enter(t, "本地监听端口")
    edit_vmess_end(t)
    quick = t.event("saved-1")["nodes"][0]
    assert quick["tunnel"]["mode"] == "quick" and quick["tunnel"]["protocol"] == "http2", quick
    assert not quick["direct"] and quick["listen"] == "127.0.0.1", quick
    assert quick["uuid"] == original["uuid"] and quick["id"] == original["id"], quick

    edit_vmess_start(t, 3)
    choose(t, "节点接入方式", 2)
    t.expect("完整 Tunnel Token")
    t.assert_no_echo()
    t.send("FIXED_TOKEN_not_echoed_0123456789\r")
    enter(t, "隧道公共主机名", "fixed.example.test")
    enter(t, "隧道客户端连接 IP / 域名", "edge.example.test")
    choose(t, "隧道连接传输", 1)
    address(t, listen="0.0.0.0")
    edit_vmess_end(t)
    fixed = t.event("saved-2")["nodes"][0]
    assert fixed["tunnel"]["mode"] == "fixed" and fixed["direct"], fixed
    assert fixed["tunnel"]["domain"] == "fixed.example.test" and fixed["tunnel"]["connectAddress"] == "edge.example.test", fixed
    assert fixed["listen"] == "0.0.0.0" and fixed["tunnel"]["hasToken"], fixed
    assert fixed["uuid"] == original["uuid"] and fixed["id"] == original["id"], fixed

    edit_vmess_start(t, 1)
    address(t, listen="0.0.0.0")
    edit_vmess_end(t, with_tls_menu=True)
    direct = t.event("saved-3")["nodes"][0]
    assert direct["tunnel"]["mode"] == "none" and direct["direct"], direct
    assert direct["uuid"] == original["uuid"] and direct["id"] == original["id"], direct
    assert b"FIXED_TOKEN_not_echoed" not in t.output, "Tunnel token appeared in terminal output"


def run_reality(t):
    choose(t, "选择节点协议", 1)
    enter(t, "节点名称", "REALITY Vision")
    choose(t, "传输方式", 1)
    address(t, 24443, "198.51.100.25", 34443)
    enter(t, "节点 UUID", "aaaaaaaa-1111-4222-8333-444444444444")
    choose(t, "节点安全层", 3)
    enter(t, "TLS / REALITY 服务器名称", "target.example.test")
    enter(t, "REALITY 握手目标主机", "target.example.test")
    enter(t, "REALITY 握手目标端口", 443)
    choose(t, "REALITY 密钥", 1)
    enter(t, "REALITY Short ID", "1234abcd")
    enter(t, "ALPN", "h2,http/1.1")
    choose(t, "VLESS Encryption", 1)
    choose(t, "VLESS Flow", 2)
    finish_editor(t)
    node = t.event("saved")["nodes"][0]
    assert node["tlsMode"] == "reality" and node["serverName"] == "target.example.test", node
    assert node["flow"] == "xtls-rprx-vision" and len(node["realityPublicKey"]) == 43, node
    assert node["tunnel"]["mode"] == "none", node


def run_cancel(t):
    ss_editor(t, save=2)
    assert t.event("cancelled")["nodes"] == [], "Cancelled draft was persisted"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"))
    args = parser.parse_args()
    bun = shutil.which(args.bun)
    if not bun:
        parser.error(f"Bun executable not found: {args.bun}")
    cases = {"multi-direct": run_multi_direct, "tunnel-modes": run_tunnel_modes,
             "reality": run_reality, "cancel": run_cancel}
    failures = 0
    for name, action in cases.items():
        terminal = ui.Terminal(str(Path(bun).resolve()), name, FIXTURE)
        try:
            started = terminal.event("start")
            assert started["stdinTTY"] and started["stdoutTTY"]
            action(terminal)
            terminal.finish(allow_files=True)
            print(f"PASS {name}: real editor, persisted configuration, terminal restoration", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {error}", file=sys.stderr, flush=True)
        finally:
            terminal.close()
    print(f"Panel PTY tests: {len(cases)} scenarios, {failures} failures.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
