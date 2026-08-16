"""跨函数堆 UAF 启发式检测测试 — 数组基址关联 (语义层复用)"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.heap_uaf import _array_base_of, _split_functions


class _I:
    def __init__(self, addr, mnemonic, op_str, size=1):
        self.address, self.mnemonic, self.op_str, self.size = addr, mnemonic, op_str, size


def _mk(seq, base=0x1000):
    return [_I(base + i, m, o) for i, (m, o) in enumerate(seq)]


def test_array_base_direct_rip():
    """mov rdi, [rip+chunks] 直接读全局数组 → 基址"""
    insns = _mk([("mov", "rdi, qword ptr [rip + 0x2000]"), ("call", "0x10")])
    # 0x1000 mov (size 1) + 0x2000 disp → 0x1001 + 0x2000 = 0x3001
    assert _array_base_of(insns, 1, "rdi") == 0x1001 + 0x2000


def test_array_base_indexed():
    """lea rdx,[rax*8] + lea rax,[rip+chunks] + mov rax,[rdx+rax] → 基址"""
    insns = _mk([
        ("lea", "rdx, [rax*8]"),
        ("lea", "rax, [rip + 0x2c87]"),
        ("mov", "rax, qword ptr [rdx + rax]"),
        ("mov", "rdi, rax"),
        ("call", "0x10"),
    ])
    base = _array_base_of(insns, 4, "rdi")
    # lea rax,[rip+0x2c87] @ addr 0x1001, size 1 → 0x1002 + 0x2c87 = 0x3c89
    assert base == 0x1002 + 0x2c87, f"基址 {hex(base)}"


def test_array_base_mov_chain():
    """mov rbx,[rip+chunks]; mov rdi,rbx → 传播追到基址"""
    insns = _mk([
        ("mov", "rbx, qword ptr [rip + 0x100]"),
        ("mov", "rdi, rbx"),
        ("call", "0x10"),
    ])
    assert _array_base_of(insns, 2, "rdi") == 0x1001 + 0x100  # 0x1000 mov + disp


def test_split_functions_endbr64():
    """stripped 函数切分: endbr64 边界"""
    insns = _mk([("push", "rbp"), ("ret", ""), ("endbr64", ""), ("push", "rbp"), ("ret", "")])
    funcs = _split_functions(insns)
    assert len(funcs) >= 2, f"应切分出多个函数: {funcs}"


def test_split_functions_ret_padding():
    """ret 后 padding (地址跳跃) → 函数边界"""
    seq = [("push", "rbp"), ("ret", "")]
    insns = [_I(0x1000, "push", "rbp"), _I(0x1001, "ret", ""),
             _I(0x1020, "push", "rbp"), _I(0x1021, "ret", "")]
    funcs = _split_functions(insns)
    assert len(funcs) == 2, f"ret padding 应切分: {funcs}"


def test_array_base_xor_clobber_rejected():
    """xor rdi,rdi (free(NULL) 清理路径) 覆写候选 → 不误连更早的 [rip+X]"""
    insns = _mk([
        ("mov", "rdi, qword ptr [rip + 0x100]"),  # 更早的无关全局
        ("nop", ""),
        ("xor", "rdi, rdi"),
        ("mov", "rsi, rax"),
        ("call", "0x10"),  # free
    ])
    # xor 覆写 rdi → 候选丢弃 → 不返回 0x100 基址
    assert _array_base_of(insns, 4, "rdi") is None


def test_detect_no_free_no_chains():
    """plt_map 无 free → 无 UAF 链 (非堆题无 FP)"""
    from intelpwn.core.analysis.heap_uaf import detect_cross_function_uaf
    # mock: 显式传空 plt_map → 内部 fallback 失败 → []
    pre = None
    from intelpwn.core.analysis.overflow import disassemble_text
    pre = disassemble_text("challenges/challenge_ret2win")
    assert pre
    chains = detect_cross_function_uaf("challenges/challenge_ret2win",
                                       insns=pre[0], bits=pre[1],
                                       plt_map={"0x401040": "puts"})
    assert chains == [], f"无 free 的二进制不应报 UAF: {chains}"
