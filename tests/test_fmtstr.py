"""单元测试 — 格式化字符串分析"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.fmtstr import detect_format_string

BIN = "challenges/challenge_fmtstr"
BIN_SAFE = "challenges/challenge_ret2win"


class TestDetectFormatString:
    def test_fmtstr_binary_is_vulnerable(self):
        """challenge_fmtstr 应该有格式化字符串漏洞"""
        result = detect_format_string(BIN)
        assert result["vulnerable"] is True

    def test_safe_binary_not_vulnerable(self):
        """challenge_ret2win (printf 用常量) 不应报漏洞"""
        result = detect_format_string(BIN_SAFE)
        assert result["vulnerable"] is False
