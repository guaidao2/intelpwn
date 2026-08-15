"""单元测试 — 栈溢出检测"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.overflow import analyze_assembly_overflow

BIN = "challenges/challenge_ret2win"


class TestAnalyzeOverflow:
    def test_detects_overflow(self):
        """challenge_ret2win 应有明显的栈溢出"""
        results = analyze_assembly_overflow(BIN)
        assert len(results) > 0, "应该检测到栈溢出"

    def test_padding_is_72(self):
        """ret2win 的标准 padding 是 72 (0x40 栈 + 8 rbp)"""
        results = analyze_assembly_overflow(BIN)
        assert results[0]["calculated_padding"] == 72

    def test_function_name(self):
        results = analyze_assembly_overflow(BIN)
        assert results[0]["function"] in ("vulnerable", "main")

    def test_stack_size(self):
        results = analyze_assembly_overflow(BIN)
        assert results[0]["stack_size"] == 64  # 0x40


class _I:
    def __init__(self, addr, mnemonic, op_str):
        self.address, self.mnemonic, self.op_str = addr, mnemonic, op_str


class TestStackBufPassed:
    """x86 32 位 cdecl 栈参数传递检测"""

    def _f(self, insns, call_idx):
        from intelpwn.core.analysis.overflow import _stack_buf_passed
        return _stack_buf_passed(insns, call_idx)

    def test_lea_push_detected(self):
        """lea eax,[ebp-0x28]; push eax; call gets → 栈链接"""
        insns = [_I(0, "lea", "eax, [ebp-0x28]"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is True

    def test_lea_mov_esp_detected(self):
        """lea eax,[ebp-0x28]; mov [esp],eax; call gets → 栈链接"""
        insns = [_I(0, "lea", "eax, [ebp-0x28]"),
                 _I(1, "mov", "[esp], eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is True

    def test_ebp_plus8_param_not_buffer(self):
        """lea eax,[ebp+8] 是参数装载, 不是栈缓冲 → 不判链接"""
        insns = [_I(0, "lea", "eax, [ebp+8]"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is False

    def test_no_stack_lea(self):
        """没有 lea [ebp-X] → 不判链接"""
        insns = [_I(0, "mov", "eax, 0x804a000"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is False
