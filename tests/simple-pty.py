#!/usr/bin/env python3
"""Exercise real simple-mode menus and persistence in a Bun PTY, entirely offline.

Uses the standard-library Terminal harness from ui-pty.py. All address probes,
port selection, certificate/ENC generation and apply operations are injected
local mocks. No core, tunnel, daemon, external connection or account is created.
This PTY harness is for Linux/macOS; Windows still needs native-machine checks.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("nexus_ui_pty", ROOT / "tests" / "ui-pty.py")
assert spec and spec.loader
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
FIXTURE = ROOT / "tests" / "fixtures" / "simple-entry.ts"
SUMMARY = "节点摘要 · 简易模式"
PROTOCOLS = "选择节点协议 · 简易模式"
TOKEN = "FIXED_TOKEN_no_echo_0123456789+/="


def choose(t, prompt, value=1):
    t.expect(prompt)
    t.send(str(value))


def enter(t, prompt, value):
    t.expect(prompt)
    t.send(str(value) + "\r")


def clean(t):
    return ui.ANSI.sub(b"", bytes(t.output)).decode("utf-8", errors="replace")


def only_node(event):
    assert len(event["nodes"]) == 1, event
    assert event["calls"]["forbiddenIO"] == 0, event
    return event["nodes"][0]


def no_detailed_prompts(t):
    # These are prompt labels, not harmless mentions in summary/menu copy.
    for label in ["节点 UUID（", "UUID（回车保留；new", "TLS / REALITY 服务器名称：", "REALITY 握手目标主机", "监听 IP（", "本地监听端口（", "传输路径（"]:
        assert label.encode() not in t.output, f"Unexpected detailed input: {label}"


def run_default(t, protocol, choice, port, apply):
    # Exactly two selections: choose a protocol and accept the summary.
    choose(t, PROTOCOLS, choice)
    choose(t, SUMMARY, 1 if apply else 2)
    event = t.event("saved")
    node = only_node(event)
    assert node["protocol"] == protocol and node["enabled"], node
    assert node["address"] == "45.32.22.10" and node["listen"] == "0.0.0.0", node
    assert node["port"] == port and node["publicPort"] == port, node
    assert node["direct"] and node["tunnel"]["mode"] == "none", node
    assert event["calls"] == dict(detect=1, local=0, port=1, certificate=0, encryption=0,
                                 apply=int(apply), advanced=0, forbiddenIO=0), event
    assert re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", node["uuid"]), node
    if protocol == "shadowsocks":
        assert node["method"] == "2022-blake3-aes-128-gcm", node
        assert node["passwordHash"] != hashlib.sha256(b"").hexdigest(), node
    elif protocol == "vmess":
        assert node["transport"]["type"] == "ws" and node["vmessSecurity"] == "auto", node
    else:
        assert node["transport"]["type"] == "tcp" and node["tls"]["mode"] == "reality", node
        assert node["flow"] == "xtls-rprx-vision" and node["tls"]["serverName"] == "apple.com", node
        assert len(node["tls"]["reality"]["publicKey"]) == 43, node
    assert bytes(t.output).count(PROTOCOLS.encode()) == 1
    assert bytes(t.output).count(SUMMARY.encode()) == 1
    no_detailed_prompts(t)


def run_existing_complex(t):
    seed = t.event("seed")
    before = only_node(seed)
    choose(t, SUMMARY, 2)
    saved = t.event("saved")
    assert only_node(saved) == before, "Saving reset a field, credential or dormant advanced option"
    assert saved["configHash"] == seed["configHash"], "An unchanged save rewrote configuration values"
    assert all(value == 0 for value in saved["calls"].values()), saved
    assert PROTOCOLS.encode() not in t.output, "Existing nodes should open at their summary"
    no_detailed_prompts(t)


def run_default_trojan(t):
    expected = t.event("expected-material")
    choose(t, PROTOCOLS, 4)
    choose(t, SUMMARY, 1)
    saved = t.event("saved")
    node = only_node(saved)
    assert node["protocol"] == "trojan" and node["enabled"] and node["direct"], node
    assert node["address"] == "45.32.22.10" and node["listen"] == "0.0.0.0", node
    assert node["port"] == node["publicPort"] == 8450 and node["tunnel"]["mode"] == "none", node
    assert node["tls"]["mode"] == "tls" and node["tls"]["insecure"] is True, node
    assert node["tls"]["serverName"] == "nexus.local", "Certificate generation changed the chosen TLS name"
    assert node["tls"]["certificateHash"] == expected["certificateHash"], "Generated certificate was not persisted"
    assert node["tls"]["keyHash"] == expected["keyHash"], "Generated private key was not persisted"
    assert saved["calls"] == dict(detect=1, local=0, port=1, certificate=1, encryption=0,
                                 apply=1, advanced=0, forbiddenIO=0), saved
    assert bytes(t.output).count(PROTOCOLS.encode()) == 1
    assert bytes(t.output).count(SUMMARY.encode()) == 1
    no_detailed_prompts(t)


def run_disabled_partial_tls(t):
    seed = t.event("seed")
    original = only_node(seed)
    empty = hashlib.sha256(b"").hexdigest()
    assert original["enabled"] is False and original["tls"]["mode"] == "tls", original
    assert original["tls"]["certificateHash"] != empty and original["tls"]["keyHash"] == empty, original
    choose(t, SUMMARY, 2)
    saved = t.event("saved")
    node = only_node(saved)
    assert node == original and saved["configHash"] == seed["configHash"], "Saving a disabled draft replaced its partial TLS materials"
    assert node["enabled"] is False and node["tls"]["keyHash"] == empty, node
    assert all(value == 0 for value in saved["calls"].values()), saved
    assert PROTOCOLS.encode() not in t.output
    no_detailed_prompts(t)


def run_ip_failure_manual(t):
    choose(t, PROTOCOLS, 3)
    choose(t, SUMMARY, 1)
    choose(t, "补齐客户端连接地址", 2)
    enter(t, "客户端实际连接的 IP / 域名", "0.0.0.0")
    t.expect("不能用于连接")
    enter(t, "客户端实际连接的 IP / 域名", "45.77.12.34")
    saved = t.event("saved")
    node = only_node(saved)
    assert node["address"] == "45.77.12.34" and node["listen"] == "0.0.0.0", node
    assert node["port"] == 8395 and node["publicPort"] == 8395, node
    assert saved["calls"]["detect"] == 1 and saved["calls"]["apply"] == 1, saved
    assert node["tunnel"]["mode"] == "none", node
    no_detailed_prompts(t)


def run_new_ipv6(t):
    choose(t, PROTOCOLS, 2)
    t.expect(SUMMARY)
    assert b"[2a01:4f9:3b:1234::2]:10093" in t.output, "IPv6 endpoint lacks brackets or correct port"
    t.send("1")
    saved = t.event("saved")
    node = only_node(saved)
    assert node["address"] == "2a01:4f9:3b:1234::2" and node["listen"] == "::", node
    assert node["port"] == node["publicPort"] == 10093, node
    assert saved["portChecks"] == [{"protocol": "vmess", "listen": "::", "port": 10086}], saved
    assert saved["calls"]["detect"] == 1 and saved["calls"]["apply"] == 1, saved
    no_detailed_prompts(t)


def run_vmess_tunnel_modes(t):
    original = only_node(t.event("seed"))
    assert original["tunnel"]["mode"] == "none" and original["direct"], original
    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 2)
    choose(t, SUMMARY, 2)
    quick = only_node(t.event("saved-1"))
    assert quick["tunnel"]["mode"] == "quick" and quick["direct"], quick
    assert not quick["tunnel"]["hasToken"] and not quick["tunnel"]["domain"], quick
    assert quick["uuid"] == original["uuid"] and quick["transport"] == original["transport"], quick
    assert "固定隧道公共主机名（例如".encode() not in t.output and b"Tunnel Token" not in t.output

    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 3)
    enter(t, "固定隧道公共主机名", "fixed.example.test")
    t.expect("Cloudflare 提供的完整 Tunnel Token")
    t.assert_no_echo()
    t.send(TOKEN + "\r")
    choose(t, SUMMARY, 2)
    fixed = only_node(t.event("saved-2"))
    assert fixed["tunnel"]["mode"] == "fixed" and fixed["tunnel"]["domain"] == "fixed.example.test", fixed
    assert fixed["tunnel"]["tokenHash"] == hashlib.sha256(TOKEN.encode()).hexdigest(), fixed
    assert fixed["uuid"] == original["uuid"] and fixed["id"] == original["id"], fixed
    assert fixed["port"] == 18086 and fixed["publicPort"] == 28086 and fixed["direct"], fixed

    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 1)
    choose(t, SUMMARY, 2)
    last = t.event("saved-3")
    direct = only_node(last)
    assert direct["tunnel"]["mode"] == "none" and direct["direct"], direct
    assert direct["uuid"] == original["uuid"] and direct["passwordHash"] == original["passwordHash"], direct
    assert direct["transport"] == original["transport"], direct
    assert all(value == 0 for value in last["calls"].values()), last
    assert TOKEN.encode() not in t.output and b"FIXED_TOKEN_no_echo" not in t.output, "Tunnel token was echoed"
    no_detailed_prompts(t)


def run_vless_tunnel_enc(t):
    original = only_node(t.event("seed"))
    assert original["tls"]["mode"] == "reality" and not original["hasEncryption"], original
    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 2)
    choose(t, SUMMARY, 1)
    saved = t.event("saved")
    node = only_node(saved)
    assert node["transport"]["type"] == "ws" and node["tls"]["mode"] == "none" and node["flow"] == "", node
    assert node["direct"] and node["tunnel"]["mode"] == "quick" and node["listen"] == original["listen"], node
    assert node["hasEncryption"] and node["hasDecryption"] and node["encryptionHash"] != node["decryptionHash"], node
    assert node["uuid"] == original["uuid"] and node["tls"]["reality"] == original["tls"]["reality"], node
    assert saved["calls"]["encryption"] == 1 and saved["calls"]["apply"] == 1, saved
    assert saved["calls"]["detect"] == saved["calls"]["port"] == saved["calls"]["certificate"] == 0, saved
    assert b"Tunnel Token" not in t.output, "Quick tunnel requested a token"
    no_detailed_prompts(t)


def run_vmess_tls_to_tunnel(t):
    original = only_node(t.event("seed"))
    assert original["tls"]["mode"] == "tls" and original["vmessSecurity"] == "zero", original
    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 2)
    choose(t, SUMMARY, 2)
    saved = t.event("saved")
    node = only_node(saved)
    assert node["direct"] and node["tunnel"]["mode"] == "quick" and node["tls"]["mode"] == "none", node
    assert node["vmessSecurity"] == "auto", "Removing TLS exposed the preserved direct route without VMess encryption"
    assert node["uuid"] == original["uuid"] and node["tls"]["certificateHash"] == original["tls"]["certificateHash"], node
    assert node["tls"]["keyHash"] == original["tls"]["keyHash"] and node["transport"] == original["transport"], node
    assert all(value == 0 for value in saved["calls"].values()), saved
    no_detailed_prompts(t)


def run_cancel(t):
    seed = t.event("seed")
    choose(t, SUMMARY, 3)
    choose(t, "可选隧道", 2)
    choose(t, SUMMARY, 7)
    cancelled = t.event("cancelled-1")
    assert cancelled["configHash"] == seed["configHash"] and cancelled["nodes"] == seed["nodes"], cancelled
    assert all(value == 0 for value in cancelled["calls"].values()), cancelled
    choose(t, PROTOCOLS, 1)
    t.expect(SUMMARY)
    t.send(b"\x1b")
    cancelled = t.event("cancelled-2")
    assert cancelled["configHash"] == seed["configHash"] and cancelled["nodes"] == seed["nodes"], cancelled
    assert cancelled["calls"]["apply"] == cancelled["calls"]["encryption"] == 0, cancelled
    assert cancelled["calls"]["detect"] == cancelled["calls"]["port"] == 1, cancelled


def run_export_missing_ss(t):
    original = only_node(t.event("seed"))
    assert not original["address"], original
    choose(t, "选择要查看 / 导出的节点", 1)
    t.expect("节点链接与客户端配置")
    matches = re.findall(r"ss://[^\s\x1b]+", clean(t))
    assert len(matches) == 1, "A copyable SS URI was not immediately visible before any JSON choice"
    uri = urlsplit(matches[0])
    assert uri.hostname == "45.32.22.10" and uri.port == 48388, matches[0]
    assert unquote(uri.username or "") == "2022-blake3-aes-128-gcm", matches[0]
    assert unquote(uri.password or "") == base64.b64encode(b"0123456789abcdef").decode(), "URI changed the old SS credential"
    assert "旧 SS 缺地址" in unquote(uri.fragment), matches[0]
    t.send("1")  # Default Back, without opening or saving a JSON file.
    exported = t.event("exported")
    node = only_node(exported)
    assert node["address"] == "45.32.22.10", node
    assert node["withoutAddressFingerprint"] == original["withoutAddressFingerprint"], "Address repair reset another field"
    assert node["port"] == 18388 and node["publicPort"] == 48388, node
    assert node["uuid"] == original["uuid"] and node["passwordHash"] == original["passwordHash"], node
    assert node["tls"]["serverName"] == "preserve-sni.example.test", node
    assert exported["calls"] == dict(detect=1, local=0, port=0, certificate=0, encryption=0, apply=0, advanced=0, forbiddenIO=0), exported
    assert "保存路径".encode() not in t.output and "按 Enter 返回面板".encode() not in t.output
    no_detailed_prompts(t)


CASES = {
    "default-ss": lambda t: run_default(t, "shadowsocks", 3, 8395, True),
    "default-vmess": lambda t: run_default(t, "vmess", 2, 10093, False),
    "default-vless": lambda t: run_default(t, "vless", 1, 8450, True),
    "default-trojan": run_default_trojan,
    "disabled-partial-tls": run_disabled_partial_tls,
    "existing-complex": run_existing_complex,
    "ip-failure-manual": run_ip_failure_manual,
    "new-ipv6": run_new_ipv6,
    "vmess-tunnel-modes": run_vmess_tunnel_modes,
    "vless-tunnel-enc": run_vless_tunnel_enc,
    "vmess-tls-to-tunnel": run_vmess_tls_to_tunnel,
    "cancel": run_cancel,
    "export-missing-ss": run_export_missing_ss,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bun", default=os.environ.get("NEXUS_EDGE_BUN", "bun"))
    parser.add_argument("--scenario", choices=["all", *CASES], default="all")
    args = parser.parse_args()
    bun = shutil.which(args.bun)
    if not bun:
        parser.error(f"Bun executable not found: {args.bun}")
    failures, count = 0, 0
    for name, action in CASES.items():
        if args.scenario not in ("all", name):
            continue
        count += 1
        terminal = ui.Terminal(str(Path(bun).resolve()), name, FIXTURE)
        try:
            started = terminal.event("start")
            assert started["stdinTTY"] and started["stdoutTTY"], started
            action(terminal)
            terminal.finish(allow_files=True)
            print(f"PASS {name}: real keys, persisted semantics, zero network/core operations, terminal restored", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {error}", file=sys.stderr, flush=True)
        finally:
            terminal.close()
    print(f"Simple PTY tests: {count} scenarios, {failures} failures.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
