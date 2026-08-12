"""堆漏洞检测: 函数级静态线索

线索类型 (全部为启发式, 用于提示而非定论):
  - double_free: 同一函数内 ≥2 次 free → tcache dup / fastbin dup 可能
  - malloc_size_arith: malloc/calloc 大小参数来自 imul/shl/lea 等算术
    → 整数溢出或分配过大可能
  - free_in_loop: free 位于循环内 → UAF / double-free 高发场景

兼容旧字段: has_heap / functions / function_count / heap_function_list / complexity
"""

import bisect

from .plt import analyze_plt
from .cfg import analyze_cfg
from .overflow import disassemble_text
from intelpwn.utils.binary import open_elf


_HEAP_FUNCS = ('malloc', 'calloc', 'realloc', 'free', 'mmap', 'brk')
_ARITH = ('imul', 'mul', 'shl', 'sal')


def _func_bounds(path):
    """从符号表取函数边界 [(start, end, name)]"""
    funcs = []
    try:
        with open_elf(path) as elf:
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                        funcs.append((sym['st_value'], sym['st_value'] + sym['st_size'], sym.name))
    except Exception:
        pass
    return funcs


def _detect_clues(path, insns) -> list:
    """函数级堆线索扫描, 返回 [{type, function, severity, detail}]"""
    clues = []
    if not insns:
        return clues

    addrs = [i.address for i in insns]
    try:
        from pwn import ELF
        plt_map = {v: k for k, v in ELF(path, checksec=False).plt.items()}
    except Exception:
        plt_map = {}

    size_regs = ('rdi', 'edi', 'rsi', 'esi', 'rdx', 'edx')

    for f_start, f_end, f_name in _func_bounds(path):
        lo = bisect.bisect_left(addrs, f_start)
        hi = bisect.bisect_right(addrs, f_end - 1)
        fi = insns[lo:hi]
        if len(fi) < 2:
            continue

        free_idxs = []
        size_arith = []
        loop_jumps = 0
        for idx, insn in enumerate(fi):
            if insn.mnemonic == 'call':
                try:
                    callee = plt_map.get(int(insn.op_str, 16), "")
                except (ValueError, TypeError):
                    continue
                if callee == 'free':
                    free_idxs.append(idx)
                elif callee in ('malloc', 'calloc', 'realloc'):
                    # 大小参数在窗口内是否被算术指令计算
                    for prev in fi[max(0, idx - 12):idx]:
                        if prev.mnemonic in _ARITH and any(r in prev.op_str for r in size_regs):
                            size_arith.append((callee, prev))
                            break
            # 循环检测: 向后的条件/无条件跳转
            if insn.mnemonic.startswith('j') and len(insn.operands) >= 1:
                for op in insn.operands:
                    if op.type == 1 and op.imm < insn.address:
                        loop_jumps += 1

        if len(free_idxs) >= 2:
            clues.append({
                "type": "double_free",
                "function": f_name,
                "severity": "高危",
                "detail": f"函数 {f_name} 内有 {len(free_idxs)} 次 free 调用, "
                          "可能存在 double-free (tcache dup / fastbin dup)",
            })
        for callee, prev in size_arith:
            clues.append({
                "type": "malloc_size_arith",
                "function": f_name,
                "severity": "中危",
                "detail": f"{callee} 大小参数来自算术运算 ({prev.mnemonic} {prev.op_str}), "
                          "可能存在整数溢出/堆溢出",
            })
        if free_idxs and loop_jumps > 0:
            clues.append({
                "type": "free_in_loop",
                "function": f_name,
                "severity": "信息",
                "detail": f"free 调用位于循环内 (检测到 {loop_jumps} 处回跳), "
                          "UAF / double-free 高发场景",
            })
    return clues


def detect_heap(path: str) -> dict:
    """检测堆操作函数使用情况 + 静态漏洞线索"""
    plt = analyze_plt(path)
    heap_funcs = [f for f in plt if f in _HEAP_FUNCS]
    if not heap_funcs:
        return {
            "has_heap": False,
            "functions": [],
            "function_count": 0,
            "heap_function_list": [],
            "complexity": 0,
            "clues": [],
        }

    cfg = analyze_cfg(path)
    pre = disassemble_text(path)
    insns = pre[0] if pre else None
    clues = _detect_clues(path, insns)

    return {
        "has_heap": True,
        "functions": heap_funcs,
        "function_count": len(heap_funcs),
        "heap_function_list": heap_funcs,
        "complexity": cfg.get("cyclomatic", 0),
        "clues": clues,
    }
