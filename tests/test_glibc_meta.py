"""glibc 版本识别 + tcache 行为表测试 — 纯逻辑, Windows 可跑"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.glibc_meta import tcache_behavior, _version_from_string, detect_glibc_meta


def test_version_regex():
    assert _version_from_string(b"GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39") == (2, 39)
    assert _version_from_string(b"version 2.31") == (2, 31)
    assert _version_from_string(b"no version here") is None


def test_tcache_behavior_old():
    b = tcache_behavior((2, 25))
    assert b["safe_linking"] is False and b["free_hook"] is True
    assert "无 tcache" in b["tcache"]


def test_tcache_behavior_2_31():
    b = tcache_behavior((2, 31))
    assert b["safe_linking"] is False and b["free_hook"] is True
    assert "无 safe-linking" in b["tcache"]


def test_tcache_behavior_2_32_safelink():
    b = tcache_behavior((2, 32))
    assert b["safe_linking"] is True and b["free_hook"] is True


def test_tcache_behavior_modern():
    b = tcache_behavior((2, 40))
    assert b["safe_linking"] is True and b["free_hook"] is False
    assert "tls_dtor_list" in b["攻击面"]


def test_detect_glibc_meta_none():
    """无系统 libc (Windows) → version None + note"""
    m = detect_glibc_meta()
    assert "version" in m and "note" in m
