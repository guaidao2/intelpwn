"""函数调用图单元测试 — 纯 pyelftools/capstone, Windows 可跑"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.callgraph import build_call_graph

BIN = "challenges/challenge_ret2win"


def test_basic_graph():
    g = build_call_graph(BIN)
    assert g["error"] is None
    assert g["nodes"], "应有函数节点"
    assert g["edges"], "应有调用边"


def test_vuln_and_danger_marked():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable",
                             "dangerous_call": "read@plt"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n for n in g["nodes"]}
    assert by_name["vulnerable"]["vuln"] is True
    assert by_name["read@plt"]["danger"] is True  # 敏感 PLT
    assert by_name["main"]["entry"] is True


def test_attack_path():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n for n in g["nodes"]}
    # vulnerable 沿入边反向可达: main → vulnerable → read@plt 全在攻击路径上
    assert by_name["vulnerable"]["on_path"] is True
    assert by_name["main"]["on_path"] is True
    assert by_name["read@plt"]["on_path"] is True


def test_edge_main_to_vulnerable():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n["id"] for n in g["nodes"]}
    edge_set = {(e["source"], e["target"]) for e in g["edges"]}
    assert (by_name["main"], by_name["vulnerable"]) in edge_set, "main 应调用 vulnerable"


class _FakeInsn:
    def __init__(self, addr, mnemonic, op_str):
        self.address, self.mnemonic, self.op_str = addr, mnemonic, op_str


def test_indirect_call_skipped():
    """间接调用 (call [rip+...]) 不产生边"""
    insns = [
        _FakeInsn(0x1000, "call", "0x2000"),            # 直接 → 有边
        _FakeInsn(0x1005, "call", "qword ptr [rip + 0x20]"),  # 间接 → 跳过
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target", 0x3000: "read@plt"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    edge = {(e["source"], e["target"]) for e in g["edges"]}
    assert (0x1000, 0x2000) in edge
    assert len(g["edges"]) == 1, "间接调用不应产生边"


def test_cycle_terminates():
    """调用环 (a→b→a) 上反向 BFS 不无限循环, 攻击路径仍正确"""
    insns = [
        _FakeInsn(0x1000, "call", "0x2000"),
        _FakeInsn(0x2000, "call", "0x1000"),
        _FakeInsn(0x2005, "call", "0x3000"),
    ]
    bounds = [(0x1000, 0x1010, "a"), (0x2000, 0x2010, "b")]
    sym = {0x3000: "read@plt"}
    results = {"overflow": [{"address": "0x1000", "function": "a"}]}
    g = build_call_graph("x", results=results, func_bounds=bounds, sym_map=sym, insns=insns)
    by_name = {n["name"]: n for n in g["nodes"]}
    assert by_name["a"]["vuln"] and by_name["a"]["on_path"]
    assert by_name["b"]["on_path"], "a 的调用者 b 应在攻击路径上"
    assert by_name["read@plt"]["on_path"]


def test_plt_func_kind_still_danger():
    """read@plt 以 STT_FUNC 形式在 symtab (kind=func) 时也应标 danger"""
    bounds = [(0x1000, 0x1010, "caller"), (0x2000, 0x2008, "read@plt")]
    sym = {0x2000: "read@plt"}
    insns = [_FakeInsn(0x1000, "call", "0x2000")]
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    by_name = {n["name"]: n for n in g["nodes"]}
    assert by_name["read@plt"]["kind"] == "func"
    assert by_name["read@plt"]["danger"] is True


def test_addr0_placeholder_filtered():
    """dynsym 版本化占位符 (addr=0) 不建节点"""
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x0: "__libc_start_main", 0x2000: "read@plt"}
    insns = [_FakeInsn(0x1000, "call", "0x2000")]
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert all(n["addr"] != 0 for n in g["nodes"]), "0x0 占位符不应建节点"


def test_indirect_got_call_edge():
    """call qword ptr [rip+disp] 经 GOT 解析出边 (无 real GOT map 时跳过)"""
    insns = [_FakeInsn(0x1000, "call", "0x2000"),
             _FakeInsn(0x1005, "call", "qword ptr [rip + 0x2f47]")]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "read@plt"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    edge = {(e["source"], e["target"]) for e in g["edges"]}
    assert (0x1000, 0x2000) in edge
    assert len(g["edges"]) == 1, "无 GOT 信息时间接调用应跳过"


def test_crt_flag():
    bounds = [(0x1000, 0x1010, "frame_dummy"), (0x1020, 0x1030, "real_func")]
    sym = {}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=[])
    by = {n["name"]: n for n in g["nodes"]}
    assert by["frame_dummy"]["crt"] is True
    assert by["real_func"]["crt"] is False
