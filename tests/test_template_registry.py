"""exploit 模板注册表测试 — 路由/优先级/插件扩展, Windows 可跑"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.exploit import (_EXPLOIT_TEMPLATES, register_exploit_template,
                                   _register_builtin_templates, generate,
                                   _find_win)

BIN = os.path.abspath("challenges/challenge_ret2win")
BIN_NO_WIN = os.path.abspath("challenges/challenge_ret2text")  # 无 win 常见符号名


def _results(overflow=True, canary=False, win=True, fmtstr=False, nx=True,
             system=False, binsh=False, libc_path=None, heap=False, angr=False):
    r = {"path": BIN if win else BIN_NO_WIN,
         "protections": {"bits": 64, "canary": canary, "nx": nx,
                         "pie": False, "relro": "partial"}}
    if overflow:
        r["overflow"] = [{"address": "0x401185", "function": "vulnerable",
                          "dangerous_call": "read@plt (0x401050) size=256",
                          "calculated_padding": 72, "stack_size": 64}]
    if win and overflow:
        # challenge_ret2win 有 win 符号 (ELF 可解析)
        pass
    if fmtstr:
        r["format_string"] = {"vulnerable": True, "best_offset": 6}
    if system:
        r["plt"] = {"system": "0x401040"}
    if binsh:
        r["has_binsh"] = True
    if heap:
        r["heap_analysis"] = {"clues": [{"type": "double_free"}]}
    if angr:
        r["angr_check"] = {"discovered": [{"callee": "strcpy", "padding": 40}]}
    return r


def _first_matching(results, libc_path=None):
    for t in _EXPLOIT_TEMPLATES:
        if t["predicate"](results, libc_path):
            return t["name"]
    return None


def _reset():
    _EXPLOIT_TEMPLATES.clear()
    _register_builtin_templates()


def test_registry_order():
    _reset()
    names = [t["name"] for t in _EXPLOIT_TEMPLATES]
    assert names[0] == "canary_ret2win"
    assert names[1] == "ret2win"
    assert names[-1] == "占位"


def test_canary_win_routes_first():
    _reset()
    assert _first_matching(_results(canary=True)) == "canary_ret2win"


def test_win_no_canary_ret2win():
    _reset()
    assert _first_matching(_results(canary=False)) == "ret2win"


def test_fmtstr_no_overflow():
    _reset()
    assert _first_matching(_results(overflow=False, fmtstr=True)) == "fmtstr"


def test_placeholder_empty():
    _reset()
    assert _first_matching(_results(overflow=False)) == "占位"


def test_ret2system_condition():
    _reset()
    assert _first_matching(_results(system=True, binsh=True, win=False)) == "ret2system"


def test_ret2libc_condition():
    _reset()
    # 无 system/binsh + libc → ret2libc
    assert _first_matching(_results(win=False), "/lib/x86_64-linux-gnu/libc.so.6") == "ret2libc"


def test_tcache_condition():
    _reset()
    assert _first_matching(_results(overflow=False, heap=True),
                           "/lib/x86_64-linux-gnu/libc.so.6") == "tcache dup"


def test_plugin_template_overrides():
    _reset()
    # 插件注册高优先级模板 → 覆盖内置
    def p_plugin(results, libc_path):
        return bool(results.get("overflow"))

    def g_plugin(results, libc_path, host, port):
        return "# PLUGIN EXPLOIT\n"

    register_exploit_template("plugin_test", p_plugin, g_plugin, priority=5)
    assert _first_matching(_results()) == "plugin_test"


def test_generate_uses_registry(tmp_path, monkeypatch):
    _reset()
    monkeypatch.chdir(tmp_path)
    out = generate(_results(), BIN)
    assert os.path.exists(out)
    content = open(out, encoding="utf-8", errors="replace").read()
    # 命中 ret2win 模板: 有 "win = 0x..." 赋值且不是骨架
    assert "win = 0x" in content and "骨架脚本" not in content
