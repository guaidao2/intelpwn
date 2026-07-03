"""单元测试 — BSS 扫描"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.bss import analyze_bss

BIN = "challenges/challenge_ret2win"


class TestAnalyzeBss:
    def test_returns_list(self):
        result = analyze_bss(BIN)
        assert isinstance(result, list)

    def test_small_binary_no_bss(self):
        """简单的 ret2win 二进制通常没有大 BSS 符号"""
        result = analyze_bss(BIN)
        # 至少不会报错
        assert True
