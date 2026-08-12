"""单元测试 — 交叉验证四态判定"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.cross_validate import cross_validate


def _results(overflow=None, fmtstr=None, angr=None):
    r = {"overflow": overflow or [], "format_string": fmtstr or {}}
    if angr is not None:
        r["angr_check"] = angr
    return r


class TestCrossValidate:
    def test_confirm_match(self):
        """静态 padding=72 + 动态偏移 72 → 确认"""
        res = _results(overflow=[{"calculated_padding": 72}])
        dyn = {"overflow_crash": {"crash": True, "canary_hit": False,
                                  "cyclic_offset": 72}}
        out = cross_validate(res, dyn)
        assert out["entries"][0]["state"] == "确认"
        assert out["verdict"] == "静态-动态交叉确认"

    def test_conflict_mismatch(self):
        """静态 72 + 动态 100 → 冲突"""
        res = _results(overflow=[{"calculated_padding": 72}])
        dyn = {"overflow_crash": {"crash": True, "canary_hit": False,
                                  "cyclic_offset": 100}}
        out = cross_validate(res, dyn)
        assert out["entries"][0]["state"] == "冲突"
        assert "冲突" in out["verdict"]

    def test_not_reproduced(self):
        """静态报 + 动态未崩溃 → 未复现 (不否定)"""
        res = _results(overflow=[{"calculated_padding": 72}])
        dyn = {"overflow_crash": {"crash": False, "canary_hit": False,
                                  "cyclic_offset": None}}
        out = cross_validate(res, dyn)
        assert out["entries"][0]["state"] == "未复现"

    def test_dynamic_found(self):
        """静态未报 + 动态崩溃 → 动态发现"""
        res = _results(overflow=[])
        dyn = {"overflow_crash": {"crash": True, "canary_hit": False,
                                  "cyclic_offset": 40}}
        out = cross_validate(res, dyn)
        assert out["entries"][0]["state"] == "动态发现"
        assert out["verdict"].startswith("动态发现")

    def test_canary_intercept(self):
        """canary 拦截 → canary 状态, 不打击静态"""
        res = _results(overflow=[{"calculated_padding": 72}])
        dyn = {"overflow_crash": {"crash": True, "canary_hit": True,
                                  "cyclic_offset": None}}
        out = cross_validate(res, dyn)
        assert out["entries"][0]["state"] == "canary"

    def test_fmtstr_match(self):
        """fmtstr 偏移一致 → 确认"""
        res = _results(fmtstr={"vulnerable": True, "best_offset": 6})
        dyn = {"fmtstr_offset": 6}
        out = cross_validate(res, dyn)
        assert any(e["state"] == "确认" for e in out["entries"])

    def test_angr_loop(self):
        """angr 可达 + 动态崩溃 → 确认闭环"""
        res = _results(overflow=[{"calculated_padding": 72}],
                       angr={"available": True,
                             "checks": [{"reachability": {"reachable": True}}]})
        dyn = {"overflow_crash": {"crash": True, "canary_hit": False,
                                  "cyclic_offset": 72}}
        out = cross_validate(res, dyn)
        states = {e["item"]: e["state"] for e in out["entries"]}
        assert states.get("angr 可达性") == "确认"

    def test_skip_no_dynamic(self):
        """动态未跑 → 跳过"""
        res = _results(overflow=[{"calculated_padding": 72}])
        out = cross_validate(res, {})
        assert out["entries"][0]["state"] == "跳过"
