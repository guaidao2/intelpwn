"""angr 语义兜底 — 轻量数据流判"未知"时, 符号执行求值 缓冲栈偏移 / 读取大小.

设计:
  - 懒加载 angr (import 极慢, 仅兜底触发时引入)
  - 节流: 每次 analyze 最多 _ANG_MAX_CALLS 次 angr 求值; 二进制 > _ANG_MAX_SIZE 跳过
    (大二进制/静态链接符号执行会打爆内存 — 之前 VM 实测过)
  - 纯 angr 模式 (--semantic=angr): mode='force' 不节流不跳过
"""

import os
import logging

_ANG_MAX_CALLS = 3        # 每次 analyze 兜底最多 angr 求值次数
_ANG_MAX_SIZE = 500_000   # 二进制大小上限 (字节), 超过跳过兜底
_ANG_CALL_COUNT = 0
_angr = None              # 懒加载模块

log = logging.getLogger("intelpwn")


def _load_angr():
    global _angr
    if _angr is None:
        import angr  # noqa: F401 — 懒加载, 触发很慢
        _angr = angr
    return _angr


def _eval_at_call(path: str, func_addr: int, call_addr: int, reg: str, bits: int):
    """从函数入口符号执行到调用点, 求 reg 值 (int | None)"""
    try:
        angr = _load_angr()
        proj = angr.Project(path, auto_load_libs=False)
        # 从函数入口开始 (找最近的函数起点 — 用 capstone 快速定位 or 直接函数地址)
        state = proj.factory.blank_state(addr=func_addr)
        # 调用点所在基本块 — 符号执行到 call 地址
        sm = proj.factory.simulation_manager(state)
        # 限制步数防止发散
        sm.explore(find=call_addr, num_find=1)
        if not sm.found:
            return None
        s = sm.found[0]
        val = s.solver.eval(s.regs.__getattr__(reg), cast_to=int)
        return val
    except Exception as e:
        log.warning("angr 语义求值失败 %s @0x%x: %s", os.path.basename(path), call_addr, e)
        return None


def angr_eval_size(path: str, func_addr: int, call_addr: int, size_reg: str, bits: int,
                   mode: str = "throttled") -> int:
    """angr 求读取大小 — 节流/强制模式"""
    global _ANG_CALL_COUNT
    if mode != "force":
        if _ANG_CALL_COUNT >= _ANG_MAX_CALLS:
            return None
        try:
            if os.path.getsize(path) > _ANG_MAX_SIZE:
                return None
        except OSError:
            return None
        _ANG_CALL_COUNT += 1
    v = _eval_at_call(path, func_addr, call_addr, size_reg, bits)
    return v if isinstance(v, int) else None


def angr_eval_buf_offset(path: str, func_addr: int, call_addr: int, buf_reg: str, bits: int,
                         mode: str = "throttled") -> int:
    """angr 求缓冲栈偏移: 符号执行到调用点求 buf_reg 值, 与函数 rbp 基线比较.

    返回 栈偏移 (rbp - value) 或 None。仅当 value 是 常量栈地址 时有效。
    """
    global _ANG_CALL_COUNT
    if mode != "force":
        if _ANG_CALL_COUNT >= _ANG_MAX_CALLS:
            return None
        try:
            if os.path.getsize(path) > _ANG_MAX_SIZE:
                return None
        except OSError:
            return None
        _ANG_CALL_COUNT += 1
    try:
        angr = _load_angr()
        proj = angr.Project(path, auto_load_libs=False)
        state = proj.factory.blank_state(addr=func_addr)
        sm = proj.factory.simulation_manager(state)
        sm.explore(find=call_addr, num_find=1)
        if not sm.found:
            return None
        s = sm.found[0]
        buf_val = s.solver.eval(s.regs.__getattr__(buf_reg), cast_to=int)
        rbp_val = s.solver.eval(s.regs.rbp, cast_to=int)
        if rbp_val > buf_val:
            return rbp_val - buf_val
        return None
    except Exception as e:
        log.warning("angr 缓冲求值失败 %s @0x%x: %s", os.path.basename(path), call_addr, e)
        return None


def reset_throttle():
    global _ANG_CALL_COUNT
    _ANG_CALL_COUNT = 0
