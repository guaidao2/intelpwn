"""静态链接 libc 符号识别测试 — 纯 pyelftools, Windows 可跑 (不依赖 readelf)"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.static_libc import static_libc_analysis


def test_non_static_returns_empty():
    """非静态链接 → 空 (跳过专项)"""
    r = {"protections": {"static": False}}
    assert static_libc_analysis("challenges/challenge_ret2win", r) == {}


def test_static_no_binsh_returns_empty():
    """静态但二进制无 /bin/sh/无 libc 符号 → 空 (不崩)"""
    r = {"protections": {"static": True}}
    # challenge_ret2text: 无 /bin/sh 字符串
    assert static_libc_analysis("challenges/challenge_ret2text", r) == {}


def test_static_finds_binsh():
    """静态 + 二进制含 /bin/sh → 提取 binsh 地址"""
    r = {"protections": {"static": True}}
    out = static_libc_analysis("challenges/challenge_ret2win", r)
    assert out["binsh_addr"] != "0x0" and int(out["binsh_addr"], 16) > 0
    assert "symbols" in out
