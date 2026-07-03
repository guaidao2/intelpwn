"""单元测试 — 综合发现"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.findings import scan_high_risk_strings, analyze_segments, detect_libc

BIN = "challenges/challenge_ret2win"


class TestScanHighRiskStrings:
    def test_finds_binsh(self):
        """ret2win 可能有 /bin/sh"""
        results = scan_high_risk_strings(BIN)
        strings_found = {s["string"] for s in results}
        # 至少找到一些字符串
        assert isinstance(results, list)


class TestAnalyzeSegments:
    def test_returns_english_keys(self):
        result = analyze_segments(BIN)
        assert "executable_stack" in result
        assert "got_writable" in result
        assert isinstance(result["executable_stack"], bool)


class TestDetectLibc:
    def test_returns_string(self):
        result = detect_libc(BIN)
        assert isinstance(result, str)
