#!/usr/bin/env python3
"""在真实 POSIX PTY / Windows ConPTY 中验收高级分组编辑；全部节点、文件均在临时目录。

证书生成使用公开测试材料；夹具禁止网络、代理核心、监听及后台。Windows 需要 pywinpty。
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("nexus_ui_pty", ROOT / "tests" / "ui-pty.py")
assert spec and spec.loader
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
FIXTURE = ROOT / "tests" / "fixtures" / "panel-entry.ts"
SUMMARY = "节点摘要 · 高级模式"
TOKEN = "FIXED_TOKEN_not_echoed_0123456789"
PROTOCOLS = ["vless", "vmess", "shadowsocks", "trojan", "hysteria2", "tuic", "anytls", "socks", "naive"]
PROTOCOL_LABELS = ["VLESS", "VMess", "Shadowsocks / SS2022", "Trojan", "Hysteria2", "TUIC", "AnyTLS", "SOCKS5", "NaiveProxy"]


def screen(t, title):
    """等待完整菜单并返回去除 ANSI 的当前屏文本；不依赖易变的菜单序号。"""
    start = t.position
    t.expect(title)
    t.expect("Ctrl+C 退出面板")
    return ui.ANSI.sub(b"", bytes(t.output[start:t.position])).decode("utf-8", errors="replace")


def pick(t, content, label):
    """从已读菜单按前缀寻找唯一选项并发送对应字母；歧义或缺项直接失败。"""
    options = re.findall(r"(?:^|[\r\n])\s*(?:›\s*)?([a-z])\.\s*([^\r\n]+)", content)
    matches = [(number, text) for number, text in options if text.startswith(label)]
    assert len(matches) == 1, (label, options)
    t.send(matches[0][0])


def choose(t, title, label):
    """等待指定菜单后选择标签，返回完整屏文本供文案与隐藏项断言使用。"""
    content = screen(t, title)
    pick(t, content, label)
    return content


def enter(t, prompt, value="", secret=False):
    """向实际文本输入发送完整 UTF-8 值；secret=True 时检查终端不会回显秘密。"""
    t.expect(prompt)
    if secret:
        t.assert_no_echo()
    t.send(str(value) + "\r")


def saved(t, seed, event="saved"):
    """读取保存快照，核对旁路节点和禁止操作计数，返回被编辑的节点。"""
    result = t.event(event)
    assert result["nodes"][0] == seed["nodes"][0], "保存覆盖了无关节点"
    assert result["calls"]["forbiddenIO"] == 0, result
    return result["nodes"][-1]


def open_reality(t):
    """从高级摘要进入 REALITY 组；不触发任何其他分组。"""
    choose(t, SUMMARY, "安全设置")
    choose(t, "节点安全层", "REALITY")


def finish_reality(t):
    """提交安全分组草稿，再保存节点。"""
    choose(t, "REALITY 设置", "完成")
    choose(t, SUMMARY, "保存节点")


def run_default(t, protocol):
    """验证九种协议都只选协议和保存即可创建，不强迫填写无关字段。"""
    seed = t.event("seed")
    choice = PROTOCOL_LABELS[PROTOCOLS.index(protocol)]
    choose(t, "选择节点协议 · 高级模式", choice)
    content = choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    assert node["protocol"] == protocol and node["enabled"] and node["direct"], node
    assert node["port"] == node["publicPort"] and node["tunnel"]["mode"] == "none", node
    for prompt in ["节点安全层", "TLS 设置", "REALITY 设置", "本地监听端口", "名称与认证"]:
        assert prompt.encode() not in t.output, prompt
    if protocol in ["shadowsocks", "socks"]:
        assert "安全设置" not in content and "UUID" not in content, content
    elif protocol in ["trojan", "hysteria2", "anytls", "naive"]:
        assert "UUID" not in content, content
    if protocol == "vless":
        assert node["tls"]["mode"] == "reality" and node["flow"] == "xtls-rprx-vision", node
        assert node["tls"]["serverName"] == node["tls"]["reality"]["handshakeServer"] == "apple.com", node
    if protocol in ["trojan", "hysteria2", "tuic", "anytls", "naive"]:
        assert node["tls"]["certificateHash"] != hashlib.sha256(b"").hexdigest(), node


def run_reality_common(t, invalid=False):
    """单次有效域名输入同时更新目标/SNI；可选先输入非法 URL 验证原位重试。"""
    seed = t.event("seed")
    old = seed["nodes"][-1]
    open_reality(t)
    choose(t, "REALITY 设置", "修改目标域名")
    if invalid:
        enter(t, "REALITY 目标域名（同时用作 SNI）", "https://wrong.example.test/path")
        t.expect("输入有误")
    enter(t, "REALITY 目标域名（同时用作 SNI）", "target.example.test")
    finish_reality(t)
    node = saved(t, seed)
    assert node["tls"]["serverName"] == node["tls"]["reality"]["handshakeServer"] == "target.example.test", node
    for field in ["publicKey", "privateKeyHash", "shortId", "handshakePort"]:
        assert node["tls"]["reality"][field] == old["tls"]["reality"][field], field
    assert bytes(t.output).count("REALITY 目标域名（同时用作 SNI）".encode()) == (2 if invalid else 1)
    assert "服务器连接的握手目标（域名或 IP）".encode() not in t.output
    assert "名称与认证".encode() not in t.output and "连接设置".encode() not in t.output


def run_reality_separate(t, target):
    """独立目标支持 IPv4/IPv6、自定义端口和证书域名；服务端/客户端导出由夹具复核。"""
    seed = t.event("seed")
    open_reality(t)
    choose(t, "REALITY 设置", "分别设置")
    enter(t, "服务器连接的握手目标（域名或 IP）", target)
    enter(t, "握手目标端口（不是节点监听端口）", 9443)
    enter(t, "客户端 SNI（目标证书支持的域名", "cert.example.test")
    content = choose(t, "REALITY 设置", "完成")
    assert "独立设置" in content and "cert.example.test" in content, content
    choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    assert node["tls"]["reality"]["handshakeServer"] == target.strip("[]"), node
    assert node["tls"]["reality"]["handshakePort"] == 9443 and node["tls"]["serverName"] == "cert.example.test", node


def run_reality_preserve(t):
    """进入已有独立 SNI 配置并直接返回，不重置密钥、空 Short ID 或端口。"""
    seed = t.event("seed")
    open_reality(t)
    finish_reality(t)
    node = saved(t, seed)
    assert node == seed["nodes"][-1], "只看设置改变了已有 REALITY 参数"


def run_cancel(t, final=False, at_input=False):
    """菜单 Esc、文本 Ctrl+C 或最终取消均不写入配置；核对磁盘字节保持不变。"""
    seed = t.event("seed")
    before = Path(t.scratch.name, ".nexus-edge", "config.json").read_bytes()
    open_reality(t)
    choose(t, "REALITY 设置", "修改目标域名")
    if at_input:
        t.expect("REALITY 目标域名（同时用作 SNI）")
        t.send(b"\x03")
    else:
        enter(t, "REALITY 目标域名（同时用作 SNI）", "discard.example.test")
        if final:
            choose(t, "REALITY 设置", "完成")
        else:
            screen(t, "REALITY 设置")
            t.send(b"\x1b")
    if not at_input:
        choose(t, SUMMARY, "取消，不保存" if final else "保存节点")
    result = t.event("exited" if at_input else "cancelled" if final else "saved")
    assert result["configHash"] == seed["configHash"] and result["nodes"] == seed["nodes"], result
    assert Path(t.scratch.name, ".nexus-edge", "config.json").read_bytes() == before


def run_ports(t):
    """首次端口修改同步对外端口，独立 NAT 映射设置后后续修改保留映射。"""
    seed = t.event("seed")
    for index, port in enumerate([28501, 28502, 28503], 1):
        choose(t, SUMMARY, "连接地址与端口")
        if index == 2:
            choose(t, "连接设置", "独立设置对外端口")
            enter(t, "客户端连接端口（NAT 映射）", 38501)
        choose(t, "连接设置", "本机监听端口")
        enter(t, "本地监听端口", port)
        choose(t, "连接设置", "完成")
        choose(t, SUMMARY, "保存节点")
        node = saved(t, seed, f"saved-{index}")
        assert node["port"] == port and node["publicPort"] == (port if index == 1 else 38501), node
        assert node["uuid"] == seed["nodes"][-1]["uuid"] and node["tls"] == seed["nodes"][-1]["tls"], node
    assert bytes(t.output).count("客户端连接端口（NAT 映射）".encode()) == 1


def run_auth_password(t):
    """Shadowsocks 认证不出现 UUID/用户名，只改密码且输入不可见。"""
    seed = t.event("seed")
    content = choose(t, SUMMARY, "名称与密码")
    assert "UUID" not in content, content
    content = choose(t, "名称与认证", "修改 / 重新生成密码")
    assert "UUID" not in content and "修改用户名" not in content, content
    # SS2022 固定长度密码用 new 生成，以哈希变化验证实际修改。
    enter(t, "密码（回车保留；new 生成新值）", "new", secret=True)
    choose(t, "名称与认证", "返回摘要")
    choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    assert node["passwordHash"] != seed["nodes"][-1]["passwordHash"], node
    assert node["uuid"] == seed["nodes"][-1]["uuid"], node


def run_rename(t):
    """只改名称无需重填地址、认证或安全设置，保存后其余字段保持原值。"""
    seed = t.event("seed")
    choose(t, SUMMARY, "名称与 UUID")
    choose(t, "名称与认证", "修改节点名称")
    enter(t, "节点名称", "中文单字段修改")
    choose(t, "名称与认证", "返回摘要")
    choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    old = dict(seed["nodes"][-1])
    assert node["name"] == "中文单字段修改", node
    for item in [old, node]:
        item.pop("name"); item.pop("fingerprint")
    assert node == old
    assert "节点安全层".encode() not in t.output and "连接设置".encode() not in t.output


def run_tls_only(t):
    """必须使用 TLS 的协议直接进入 TLS 分组，保留现有证书并修改 ALPN。"""
    seed = t.event("seed")
    choose(t, SUMMARY, "安全设置")
    choose(t, "TLS 设置", "修改 ALPN")
    enter(t, "ALPN（英文逗号分隔", "http/1.1")
    choose(t, "TLS 设置", "完成")
    choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    assert node["tls"]["alpn"] == ["http/1.1"], node
    assert node["tls"]["certificateHash"] == seed["nodes"][-1]["tls"]["certificateHash"], node
    assert "节点安全层".encode() not in t.output and "REALITY 设置".encode() not in t.output


def run_tunnel_modes(t):
    """同一 VMess 节点依次测试临时/固定/关闭，保留凭据并验证回环/对外监听。"""
    seed = t.event("seed")
    for index, mode in enumerate(["临时隧道", "固定隧道", "关闭隧道"], 1):
        choose(t, SUMMARY, "传输与隧道")
        choose(t, "传输方式", "ws")
        enter(t, "传输路径")
        enter(t, "传输 Host")
        choose(t, "是否额外开启隧道", mode)
        if index < 3:
            choose(t, "节点接入方式", "仅通过隧道接入" if index == 1 else "保留直连接入")
            if index == 2:
                enter(t, "完整 Tunnel Token", TOKEN, secret=True)
                enter(t, "隧道公共主机名", "fixed.example.test")
            enter(t, "隧道客户端连接 IP / 域名", "" if index == 1 else "edge.example.test")
            choose(t, "隧道连接传输", "HTTP2" if index == 1 else "自动")
        if index == 1:
            choose(t, SUMMARY, "连接地址与端口")
            content = choose(t, "连接设置", "完成")
            assert "客户端连接地址" not in content and "独立设置对外端口" not in content, content
        choose(t, SUMMARY, "保存节点")
        node = saved(t, seed, f"saved-{index}")
        assert node["uuid"] == seed["nodes"][-1]["uuid"] and node["passwordHash"] == seed["nodes"][-1]["passwordHash"], node
        assert node["tunnel"]["mode"] == ["quick", "fixed", "none"][index - 1], node
        assert node["direct"] == (index > 1) and node["listen"] == ("127.0.0.1" if index == 1 else "0.0.0.0"), node
        if index == 2:
            assert node["tunnel"]["domain"] == "fixed.example.test" and node["tunnel"]["connectAddress"] == "edge.example.test", node
            assert node["tunnel"]["tokenHash"] == hashlib.sha256(TOKEN.encode()).hexdigest(), node
    assert TOKEN.encode() not in t.output


def run_concurrent(t, same=False):
    """编辑期间模拟另一进程写自己的临时配置，验证合并无关改动及拒绝覆盖本节点。"""
    seed = t.event("seed")
    content = screen(t, SUMMARY)
    config_path = Path(t.scratch.name, ".nexus-edge", "config.json")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["nodes"][1 if same else 0]["name"] = "另一窗口已保存的名称"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    concurrent_bytes = config_path.read_bytes()
    pick(t, content, "保存节点")
    if same:
        t.expect("这个节点已在另一处修改或删除")
        choose(t, SUMMARY, "取消，不保存")
        result = t.event("cancelled")
        assert config_path.read_bytes() == concurrent_bytes, "拒绝覆盖后仍修改了配置"
        assert result["nodes"][1]["name"] == "另一窗口已保存的名称", result
    else:
        result = t.event("saved")
        assert result["nodes"][0]["name"] == "另一窗口已保存的名称", result
        assert result["nodes"][1] == seed["nodes"][1], result
    assert result["calls"]["forbiddenIO"] == 0, result


def run_tunnel_encryption(t, vless=True):
    """从安全直连切换 WS 隧道并保留直连，验证 VLESS 自动 ENC / VMess 恢复加密。"""
    seed = t.event("seed")
    choose(t, SUMMARY, "传输与隧道")
    choose(t, "传输方式", "ws")
    enter(t, "传输路径")
    enter(t, "传输 Host")
    choose(t, "是否额外开启隧道", "临时隧道")
    choose(t, "节点接入方式", "保留直连接入")
    enter(t, "隧道客户端连接 IP / 域名")
    choose(t, "隧道连接传输", "自动")
    choose(t, SUMMARY, "保存节点")
    result = t.event("saved")
    node = result["nodes"][-1]
    assert result["nodes"][0] == seed["nodes"][0] and result["calls"]["forbiddenIO"] == 0, result
    assert node["uuid"] == seed["nodes"][-1]["uuid"] and node["tls"]["mode"] == "none", node
    assert node["direct"] and node["tunnel"]["mode"] == "quick", node
    if vless:
        assert node["hasEncryption"] and result["calls"]["encryption"] == 1, result
        assert node["encryptionHash"] != node["decryptionHash"], node
        assert node["tls"]["reality"] == seed["nodes"][-1]["tls"]["reality"], node
    else:
        assert node["vmessSecurity"] == "auto" and result["calls"]["encryption"] == 0, node


def run_protocol_options(t, hy2=True):
    """验证 Hysteria2 / TUIC 专属参数仍可修改，而无需重走证书及认证。"""
    seed = t.event("seed")
    choose(t, SUMMARY, "协议专属选项")
    if hy2:
        enter(t, "Salamander 混淆密码", "HY2_SECRET_not_echoed", secret=True)
        enter(t, "服务端上行 Mbps", 250)
        enter(t, "服务端下行 Mbps", 150)
    else:
        choose(t, "TUIC 拥塞控制", "cubic")
        choose(t, "TUIC 0-RTT", "开启")
    choose(t, SUMMARY, "保存节点")
    node = saved(t, seed)
    if hy2:
        assert node["hy2"] == {"upMbps": 250, "downMbps": 150, "obfsHash": hashlib.sha256(b"HY2_SECRET_not_echoed").hexdigest()}, node
    else:
        assert node["tuic"] == {"congestionControl": "cubic", "zeroRttHandshake": True}, node
    assert node["tls"] == seed["nodes"][-1]["tls"] and node["passwordHash"] == seed["nodes"][-1]["passwordHash"], node
    assert "TLS 设置".encode() not in t.output and "名称与认证".encode() not in t.output


def run_protocol_change(t):
    """先取消协议切换，再明确转换 VLESS→Trojan；保存前不写磁盘，保存时才准备新证书。"""
    seed = t.event("seed")
    original = seed["nodes"][-1]
    config_path = Path(t.scratch.name, ".nexus-edge", "config.json")
    before = config_path.read_bytes()
    choose(t, SUMMARY, "更换节点协议")
    choose(t, "更换节点协议", "Trojan")
    choose(t, "确认更换协议", "返回，保留当前协议")
    content = screen(t, SUMMARY)
    assert "VLESS" in content and "握手目标：apple.com:443" in content, content
    assert config_path.read_bytes() == before, "取消切换时写入了配置"
    pick(t, content, "更换节点协议")
    choose(t, "更换节点协议", "Trojan")
    choose(t, "确认更换协议", "更换协议并重新配置")
    content = screen(t, SUMMARY)
    assert "Trojan" in content and "安全层：tls" in content, content
    assert config_path.read_bytes() == before, "仅更改草稿时写入了配置"
    pick(t, content, "保存节点")
    node = saved(t, seed)
    assert node["protocol"] == "trojan" and node["id"] == original["id"] and node["name"] == original["name"], node
    assert node["tls"]["certificateHash"] != hashlib.sha256(b"").hexdigest() and node["tls"]["mode"] == "tls", node
    assert node["uuid"] != original["uuid"], node


CASES = {f"default-{protocol}": (lambda t, protocol=protocol: run_default(t, protocol)) for protocol in PROTOCOLS}
CASES.update({
    "reality-common": run_reality_common,
    "reality-invalid": lambda t: run_reality_common(t, invalid=True),
    "reality-ipv4": lambda t: run_reality_separate(t, "192.0.2.17"),
    "reality-ipv6": lambda t: run_reality_separate(t, "2001:db8::17"),
    "reality-preserve": run_reality_preserve,
    "cancel-section": run_cancel,
    "exit-input": lambda t: run_cancel(t, at_input=True),
    "cancel-final": lambda t: run_cancel(t, final=True),
    "ports": run_ports,
    "auth-password": run_auth_password,
    "rename-only": run_rename,
    "tls-only": run_tls_only,
    "tunnel-modes": run_tunnel_modes,
    "concurrent-unrelated": run_concurrent,
    "concurrent-same": lambda t: run_concurrent(t, same=True),
    "vless-tunnel-enc": run_tunnel_encryption,
    "vmess-tunnel-encryption": lambda t: run_tunnel_encryption(t, vless=False),
    "options-hy2": run_protocol_options,
    "options-tuic": lambda t: run_protocol_options(t, hy2=False),
    "protocol-change": run_protocol_change,
})


def main():
    """按可选场景筛选执行，任何断言失败返回 1；finally 终止自有进程并删除临时节点。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"))
    parser.add_argument("--scenario", choices=["all", *CASES], default="all")
    args = parser.parse_args()
    bun = shutil.which(args.bun)
    if not bun:
        parser.error(f"Bun executable not found: {args.bun}")
    failures = count = 0
    for name, action in CASES.items():
        if args.scenario not in ("all", name):
            continue
        count += 1
        terminal = ui.Terminal(str(Path(bun).resolve()), name, FIXTURE)
        try:
            started = terminal.event("start")
            assert started["stdinTTY"] and started["stdoutTTY"]
            action(terminal)
            terminal.finish(allow_files=True)
            print(f"PASS {name}: real grouped editor, persisted configuration, isolated cleanup", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {error}", file=sys.stderr, flush=True)
        finally:
            terminal.close()
    print(f"Panel PTY tests: {count} scenarios, {failures} failures.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
