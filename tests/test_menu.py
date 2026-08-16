"""菜单交互识别单元测试 — analyze_menu / _anchor_from_prompt / 注入逻辑"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.menu import analyze_menu, _anchor_from_prompt
from intelpwn.core.exploit import _inject_menu_interaction


def test_anchor_from_prompt_choice():
    assert _anchor_from_prompt("Input your choice!") == "choice!"


def test_anchor_from_prompt_menu_items():
    # rodata 菜单项: 取第一段 (puts 逐行输出)
    assert _anchor_from_prompt("1.Encrypt 2.Decrypt 3.Exit") == "1.Encrypt"


def test_anchor_from_prompt_plain():
    assert _anchor_from_prompt(">>") == ">>"


def test_inject_menu_interaction_after_io():
    script = ('#!/usr/bin/env python3\nfrom pwn import *\n'
              'io = process("./target")\npayload = b"A" * 88\nio.sendline(payload)')
    out = _inject_menu_interaction(script, {"anchor": "choice!", "trigger": "1",
                                            "target_func": "encrypt"})
    assert 'io.recvuntil(b"choice!", timeout=5)' in out
    assert 'io.sendline(b"1")   # → encrypt (漏洞函数)' in out
    # 顺序: io 建立 → 菜单交互 → payload
    assert out.index('io = process(') < out.index('recvuntil') < out.index('payload =')


def test_inject_menu_interaction_no_anchor_sleep():
    script = ('from pwn import *\nio = remote("h", 1)\nio.sendline(b"x")')
    out = _inject_menu_interaction(script, {"anchor": "", "trigger": "2", "target_func": ""})
    assert "time.sleep(0.5)" in out
    assert 'io.sendline(b"2")' in out


def test_analyze_menu_no_menu_challenge():
    """无菜单题 (challenge_ret2win): present=False, 不触发自动交互"""
    r = analyze_menu("challenges/challenge_ret2win",
                     {"overflow": [{"function": "vulnerable", "address": "0x401185"}],
                      "plt": {"gets": "0x401040"}})
    assert r["present"] is False
    assert r["confident"] is False


def test_analyze_menu_no_overflow():
    r = analyze_menu("challenges/challenge_ret2win", {"overflow": [], "plt": {}})
    assert r["present"] is False


def test_analyze_menu_heap_challenge():
    """堆题 (无溢出) 菜单也识别 — options 表供 gen_tcache_dup 使用 (端到端真实二进制)"""
    import os
    b = "challenges/challenge_tcache_dup"
    if not os.path.exists(b):
        return  # 二进制未入库的环境跳过 (如 CI 只拉源码)
    r = analyze_menu(b, {"overflow": [], "plt": {}})
    assert r["present"] is True
    assert r["confident"] is False            # 无溢出函数匹配 → 不注入
    opts = r.get("options") or {}
    handlers = {info.get("handler") for info in opts.values()}
    assert {"add", "delete", "show", "edit"} & handlers, f"堆题 handler 未识别: {handlers}"


def test_menu_stripped_fallback_scanf_scan():
    """stripped (无 main 符号) fallback: 扫第一个含 scanf 调用的匿名函数"""
    import os
    b = "challenges/challenge_tcache_dup"
    if not os.path.exists(b):
        return
    import intelpwn.core.analysis as analysis_pkg
    import intelpwn.core.analysis.menu as menu_mod
    from intelpwn.core.analysis import _build_shared_blackboard
    from intelpwn.core.analysis.overflow import disassemble_text

    pre = disassemble_text(b)
    bb = _build_shared_blackboard(b, pre[0], pre[1])
    # 模拟 stripped: 函数名全部匿名 (func_bounds 无 main)
    stripped_bounds = [(s, e, "") for s, e, n in bb["func_bounds"]]
    stripped_bb = dict(bb)
    stripped_bb["func_bounds"] = stripped_bounds
    stripped_bb["sym_by_addr"] = {}

    orig = analysis_pkg._build_shared_blackboard
    try:
        analysis_pkg._build_shared_blackboard = lambda p, i, bits: stripped_bb
        r = menu_mod.analyze_menu(b, {"overflow": [], "plt": {}})
    finally:
        analysis_pkg._build_shared_blackboard = orig
    # fallback 应仍能识别菜单选项 (第一个含 scanf 分发链的匿名函数)
    opts = r.get("options") or {}
    # stripped 无符号 → handler 为匿名 func_ 名, 断言 4 个选项均被识别
    assert len(opts) >= 4, f"stripped fallback 选项不足: {opts}"
