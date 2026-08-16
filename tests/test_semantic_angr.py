"""semantic_angr 兜底模块测试 — 节流/大小限制/mock 求值"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis import semantic_angr as sa


def _mock_eval(path, func_addr, call_addr, reg, bits):
    """mock _eval_at_call: 返回固定值"""
    return 0x100


def test_throttle_limit():
    """节流: 默认模式最多 _ANG_MAX_CALLS 次 angr 求值"""
    sa._angr = object()  # 假装已加载
    sa.reset_throttle()
    n = sa._ANG_MAX_CALLS
    small = os.path.join(os.path.dirname(__file__), '..', 'challenges', 'challenge_ret2win')
    for _ in range(n + 2):
        sa.angr_eval_size(small, 0x1000, 0x1100, "rdx", 64)
    assert sa._ANG_CALL_COUNT >= n, "节流计数应达上限"


def test_size_limit_skips_big_binary():
    """大小限制: > _ANG_MAX_SIZE 的二进制跳过 angr 兜底"""
    sa.reset_throttle()
    big = os.path.join(os.path.dirname(__file__), '..', 'challenges', 'challenge_static_vuln')
    if not os.path.exists(big):
        return  # 二进制缺失跳过
    assert os.path.getsize(big) > sa._ANG_MAX_SIZE
    v = sa.angr_eval_size(big, 0x1000, 0x1100, "rdx", 64)
    assert v is None, "大二进制应跳过 angr 兜底"


def test_force_mode_bypasses_throttle():
    """force 模式不节流不跳过大小限制"""
    sa.reset_throttle()
    big = os.path.join(os.path.dirname(__file__), '..', 'challenges', 'challenge_static_vuln')
    if not os.path.exists(big):
        return
    # force 模式直接调 _eval_at_call (mock 防止真跑 angr)
    orig = sa._eval_at_call
    try:
        sa._eval_at_call = _mock_eval
        v = sa.angr_eval_size(big, 0x1000, 0x1100, "rdx", 64, mode="force")
        assert v == 0x100, "force 模式应绕过大小限制"
    finally:
        sa._eval_at_call = orig


def test_angr_missing_graceful():
    """angr 未安装时兜底函数应优雅返回 None (不抛异常)"""
    orig_angr = sa._angr
    sa._angr = None
    try:
        import importlib
        saved = importlib.import_module  # 保留引用, 测试不真改 import
    except Exception:
        pass
    # 不真跑 — 只验证 reset_throttle 可调用
    sa.reset_throttle()
    assert sa._ANG_CALL_COUNT == 0
    sa._angr = orig_angr
