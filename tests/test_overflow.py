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
