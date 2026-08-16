"""黑板基础设施缓存测试 — analyze_all 物化 _shared 后各分析器消费一致"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis import analyze_all


def test_shared_blackboard_materialized():
    """analyze_all 物化 _shared: insns/bits/func_bounds/sym_by_addr/plt_map"""
    r = analyze_all("challenges/challenge_ret2win", None)
    s = r.get("_shared", {})
    assert "insns" in s and "bits" in s
    assert "func_bounds" in s and "sym_by_addr" in s and "plt_map" in s
    assert len(s.get("func_bounds") or []) > 0


def test_overflow_consistent_with_blackboard():
    """黑板路径 (传 func_bounds/plt_map) 与独立路径结果一致; 空 plt_map (静态链接) 触发 fallback"""
    from intelpwn.core.analysis.overflow import analyze_assembly_overflow
    # 独立路径 (None → 自扫)
    standalone = analyze_assembly_overflow("challenges/challenge_ret2win", None, None)
    # 黑板路径: 传空 plt_map 模拟静态链接 (无 PLT) — 必须走 symtab fallback 不丢检测
    r = analyze_all("challenges/challenge_ret2win", None)
    s = r["_shared"]
    via_bb = analyze_assembly_overflow("challenges/challenge_ret2win",
                                       insns=s["insns"], bits=s["bits"],
                                       func_bounds=s["func_bounds"],
                                       plt_map={})
    # 结果形状一致 (危险调用 + padding 相同)
    assert len(standalone) == len(via_bb)
    for a, b in zip(standalone, via_bb):
        assert a.get("function") == b.get("function")
        assert a.get("calculated_padding") == b.get("calculated_padding")


def test_menu_consistent_with_blackboard():
    """menu 从黑板消费 vs 独立自扫结果一致"""
    from intelpwn.core.analysis.menu import analyze_menu
    r = analyze_all("challenges/challenge_ret2win", None)
    via_bb = analyze_menu("challenges/challenge_ret2win", r)          # 黑板路径
    standalone = analyze_menu("challenges/challenge_ret2win",
                              {"overflow": r["overflow"], "plt": r["plt"]})  # 独立自扫
    assert via_bb["present"] == standalone["present"]
    assert via_bb["confident"] == standalone["confident"]
