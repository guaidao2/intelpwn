"""单元测试 — 保护状态分析"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.protections import analyze_protections
from intelpwn.utils.binary import parse_checksec, readelf_arch, has_rwx_segment, is_static_binary

# ── 被分析的文件 ────────────────────────────────────────────
BIN = "challenges/challenge_ret2win"


class TestParseChecksec:
    def test_returns_dict(self):
        result = parse_checksec(BIN)
        assert isinstance(result, dict)
        assert "canary" in result
        assert "nx" in result
        assert "pie" in result
        assert "relro" in result
        assert "rwx" in result

    def test_no_canary(self):
        """ret2win 编译时没开 Canary"""
        result = parse_checksec(BIN)
        assert result["canary"] is False, "challenge_ret2win 应无 Canary"


class TestAnalyzeProtections:
    def test_returns_english_keys(self):
        result = analyze_protections(BIN)
        assert "arch" in result
        assert "bits" in result
        assert "canary" in result
        assert "nx" in result
        assert "pie" in result
        assert "relro" in result
        assert "risk_level" in result

    def test_no_canary_detected(self):
        result = analyze_protections(BIN)
        assert result["canary"] is False

    def test_pie_disabled(self):
        result = analyze_protections(BIN)
        assert result["pie"] is False

    def test_risk_high(self):
        """无 Canary → 高危"""
        result = analyze_protections(BIN)
        assert result["risk_level"] == "高危"


class TestReadelfArch:
    def test_x64(self):
        assert readelf_arch(BIN) == "x64"
