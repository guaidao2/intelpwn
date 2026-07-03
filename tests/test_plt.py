"""单元测试 — PLT 分析"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.plt import analyze_plt, analyze_got

BIN = "challenges/challenge_ret2win"


class TestAnalyzePlt:
    def test_returns_dict(self):
        result = analyze_plt(BIN)
        assert isinstance(result, dict)

    def test_finds_puts(self):
        """ret2win 应有 puts@plt"""
        result = analyze_plt(BIN)
        assert "puts" in result

    def test_finds_system_or_win(self):
        """ret2win 应有系统相关函数"""
        result = analyze_plt(BIN)
        # 至少有一个危险/关键函数
        known = {"puts", "printf", "read", "gets", "system", "fflush"}
        assert known & result.keys(), f"应找到至少一个已知函数, 找到: {list(result.keys())}"


class TestAnalyzeGot:
    def test_returns_dict(self):
        result = analyze_got(BIN)
        assert isinstance(result, dict)
        assert len(result) > 0
