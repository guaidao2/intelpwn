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
