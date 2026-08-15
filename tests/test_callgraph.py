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


def test_reg_indirect_call_resolved():
    """call rax 前有 mov rax, 常量 → 解析出边 (函数指针场景)"""
    insns = [
        _FakeInsn(0x1000, "mov", "rax, 0x2000"),
        _FakeInsn(0x1007, "call", "rax"),
        _FakeInsn(0x100c, "call", "rbx"),  # 无装载 → 跳过
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    edge = {(e["source"], e["target"]) for e in g["edges"]}
    assert (0x1000, 0x2000) in edge, "call rax (mov rax,0x2000) 应解析出边"
    assert len(g["edges"]) == 1, "无装载的 call rbx 应跳过"


def test_reg_indirect_dead_const_not_resolved():
    """常量装载后 reg 被再次写入 (非常量) → 死值, 不应解析"""
    insns = [
        _FakeInsn(0x1000, "mov", "rax, 0x2000"),   # 旧常量
        _FakeInsn(0x1007, "mov", "rax, rbx"),      # 重新写入 (寄存器来源)
        _FakeInsn(0x100a, "call", "rax"),
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert g["edges"] == [], "死常量不应解析出边"


def test_reg_indirect_mem_disp_not_resolved():
    """lea rax, [rbp-0x20] / [rip+0x2000] 内存位移不应被当常量"""
    insns = [
        _FakeInsn(0x1000, "lea", "rax, [rbp - 0x20]"),
        _FakeInsn(0x1005, "call", "rax"),
        _FakeInsn(0x1010, "lea", "rbx, [rip + 0x2000]"),
        _FakeInsn(0x1017, "call", "rbx"),
    ]
    bounds = [(0x1000, 0x1020, "caller")]
    sym = {0x20: "bogus", 0x2000: "bogus2"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert g["edges"] == [], "内存位移不应解析为常量目标"


def test_reg_indirect_pop_stops_scan():
    """pop rax 写即终止 (操作数是纯寄存器)"""
    insns = [
        _FakeInsn(0x1000, "mov", "rax, 0x2000"),
        _FakeInsn(0x1007, "pop", "rax"),
        _FakeInsn(0x1008, "call", "rax"),
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert g["edges"] == [], "pop rax 后常量已死, 不应解析"


def test_reg_indirect_arith_const_not_target():
    """xor/add/sub reg, 常量 不是地址装载, 不应解析为目标"""
    insns = [
        _FakeInsn(0x1000, "xor", "rax, 0x2000"),
        _FakeInsn(0x1005, "call", "rax"),
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert g["edges"] == [], "xor rax, 0x2000 不是地址, 不应出边"


def test_reg_indirect_other_reg_write_continues():
    """写其他寄存器 (mov rdx, X) 不终止对 rax 的常量回看"""
    insns = [
        _FakeInsn(0x1000, "mov", "rax, 0x2000"),
        _FakeInsn(0x1007, "mov", "rdx, 0x3000"),   # 其他寄存器, 不影响
        _FakeInsn(0x100a, "call", "rax"),
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target", 0x3000: "other"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    edge = {(e["source"], e["target"]) for e in g["edges"]}
    assert (0x1000, 0x2000) in edge, "其他寄存器写入不应中断 rax 常量解析"


def test_reg_indirect_32bit_write_terminates():
    """xor eax, eax (32 位同族清零) 终止扫描 — 防解析到更旧 64 位常量"""
    insns = [
        _FakeInsn(0x1000, "mov", "rax, 0x2000"),
        _FakeInsn(0x1007, "xor", "eax, eax"),      # 32 位同族清零 → 常量已死
        _FakeInsn(0x100a, "call", "rax"),
    ]
    bounds = [(0x1000, 0x1010, "caller")]
    sym = {0x2000: "target", 0x1234: "bogus"}
    g = build_call_graph("x", func_bounds=bounds, sym_map=sym, insns=insns)
    assert g["edges"] == [], "32 位同族清零后旧常量已死"
