"""单元测试 — 交叉验证四态判定 + gdb 崩溃解析"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.cross_validate import cross_validate
from intelpwn.core.verify import _parse_gdb_crash


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

    def test_fmtstr_skip_no_dynamic(self):
        """动态未跑时 fmtstr 也应为跳过, 不是未复现"""
        res = _results(fmtstr={"vulnerable": True, "best_offset": 6})
        out = cross_validate(res, {})
        assert out["entries"][0]["state"] == "跳过"


class TestParseGdbCrash:
    def test_crash_segv_offset(self):
        """SIGSEGV + rsp 指向 cyclic → crash=True + 偏移"""
        out = ("Program received signal SIGSEGV, Segmentation fault.\n"
               "CRASH-MARK RIP=0x4011f2 RSPVAL=0x616161616161616a RBP=0x6161616161616169\n")
        r = _parse_gdb_crash(out, 0)
        assert r["crash"] is True
        assert r["signal"] == "SIGSEGV"
        assert r["cyclic_offset"] == 72
        assert r["canary_hit"] is False

    def test_normal_exit_not_crash(self):
        """gdb 正常退出 (无 signal) → crash=False, 不能被误判为确认"""
        out = ("Program exited normally.\n"
               "CRASH-MARK RIP=0x4011f2 RSPVAL=0x7fffffffe968 RBP=0x7fffffffe960\n")
        r = _parse_gdb_crash(out, 0)
        assert r["crash"] is False
        assert r["cyclic_offset"] is None
        assert r["canary_hit"] is False

    def test_canary_sigabrt(self):
        """SIGABRT + stack smashing → canary_hit=True"""
        out = ("Program received signal SIGABRT, Aborted.\n"
               "*** stack smashing detected ***: terminated\n"
               "CRASH-MARK RIP=0x7ffff7e40cfc RSPVAL=0x0 RBP=0x7ffff7fbb000\n")
        r = _parse_gdb_crash(out, 0)
        assert r["crash"] is True
        assert r["canary_hit"] is True
        assert r["cyclic_offset"] is None
