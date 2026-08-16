"""全局缓冲写入检测 (黄金样本: mini_configd 模拟固件)"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def test_mini_configd_global_write():
    """黄金样本: 模拟固件配置解析 — 全局缓冲写入线索 (off-by-one: key 溢出到 value)"""
    import os
    b = "challenges/mini_configd"
    if not os.path.exists(b):
        return
    from intelpwn.core.analysis import analyze_all
    r = analyze_all(b, None)
    gw = r.get("global_writes", [])
    assert gw, "mini_configd 应有全局写入线索"
    assert any("strcpy" in g.get("call", "") for g in gw), f"应含 strcpy: {gw}"
    assert any("parse_line" in g.get("function", "") for g in gw), f"应在 parse_line: {gw}"
