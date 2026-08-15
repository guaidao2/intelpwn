"""堆漏洞检测: 函数级静态线索

线索类型 (全部为启发式, 用于提示而非定论):
  - double_free: 同一函数内 ≥2 次 free → tcache dup / fastbin dup 可能
  - malloc_size_arith: malloc/calloc 大小参数来自 imul/shl/lea 等算术
    → 整数溢出或分配过大可能
  - free_in_loop: free 位于循环内 → UAF / double-free 高发场景

兼容旧字段: has_heap / functions / function_count / heap_function_list / complexity
"""

import bisect
import re

from .plt import analyze_plt
from .cfg import analyze_cfg
from .overflow import disassemble_text
from intelpwn.utils.binary import open_elf


_HEAP_FUNCS = ('malloc', 'calloc', 'realloc', 'free', 'mmap', 'brk')
_ARITH = ('imul', 'mul', 'shl', 'sal')


def _arg_slot(insns, call_idx: int, reg: str, window: int = 25):
    """调用前窗口内, 参数寄存器 reg 的全局槽地址来源。

    识别常见全局数组访问模式:
      lea rax,[rip+chunks]; mov (%rdx,%rax,1),%rax; mov %rax,%rdi   → 返回 chunks 基址
      mov rdi,[rip+chunks] / mov rdi,<绝对地址>                       → 返回该地址
    非全局来源 (栈/堆/寄存器) 返回 None。
    """
    lo = max(0, call_idx - window)
    # 1) 窗口内指向全局的 lea 基址寄存器 (后写的覆盖先写的)
    bases = {}
    for prev in insns[lo:call_idx]:
        if prev.mnemonic == 'lea':
            m = re.search(r'\[rip\s*\+\s*(0x[0-9a-fA-F]+)\]', prev.op_str)
            if m:
                dst = prev.op_str.split(',')[0].strip()
                bases[dst] = prev.address + prev.size + int(m.group(1), 16)
    # 2) 回溯 reg 的赋值链
    cur = reg
    seen = set()
    for prev in reversed(insns[lo:call_idx]):
        if prev.mnemonic not in ('mov', 'lea', 'pop'):
            continue
        dst = prev.op_str.split(',')[0].strip()
        if dst != cur:
            continue
        if prev.mnemonic == 'lea':
            return None  # lea 本身是栈/局部地址, 非全局槽
        parts = prev.op_str.split(',')
        src = parts[1].strip() if len(parts) >= 2 else ""
        if '[' in src:
            # mov reg, [addr-expr]: 任一地址寄存器来自全局 lea → 该全局基址
            regs_addr = re.findall(r'[a-z][a-z0-9]*', src.replace('(', ' ').replace(')', ' '))
            for r in regs_addr:
                if r in bases:
                    return bases[r]
            if 'rip' in src:
                m = re.search(r'\[rip\s*\+\s*(0x[0-9a-fA-F]+)[^\]]*\]', src)
                if m:
                    return prev.address + prev.size + int(m.group(1), 16)
            return None
        if src in bases:
            return bases[src]
        try:
            return int(src, 16)
        except ValueError:
            pass
        if src not in seen and src.isalpha():
            seen.add(cur)
            cur = src
    return None


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

    # UAF 检测: 全局收集 free 参数来源槽 与 read/write 目标来源槽, 最后取交集
    free_slots = {}   # 槽地址 -> 函数名
    io_slots = {}     # 槽地址 -> 函数名

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
                    slot = _arg_slot(fi, idx, 'rdi')
                    if slot is not None:
                        free_slots.setdefault(slot, f_name)
                elif callee in ('read', 'recv', 'write'):
                    # read/recv 的目标在 rsi (rdi 是 fd); write 的缓冲在 rsi
                    slot = _arg_slot(fi, idx, 'rsi')
                    if slot is not None:
                        io_slots.setdefault(slot, f_name)
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

    # free_then_use (UAF): free 的参数来源全局槽 也被 read/write 用作目标
    shared = sorted(set(free_slots) & set(io_slots))
    for slot in shared:
        clues.append({
            "type": "free_then_use",
            "function": f"{free_slots[slot]}/{io_slots[slot]}",
            "severity": "高危",
            "detail": f"free 的指针来自全局槽 0x{slot:x}, 同一槽仍被 read/write 用作"
                      f"目标 ({io_slots[slot]}) → free 后可能被继续使用 (UAF)",
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

    # glibc 版本 + tcache 行为 (堆助手)
    glibc = {}
    try:
        from .glibc_meta import detect_glibc_meta
        glibc = detect_glibc_meta()
    except Exception:
        pass

    return {
        "has_heap": True,
        "functions": heap_funcs,
        "function_count": len(heap_funcs),
        "heap_function_list": heap_funcs,
        "complexity": cfg.get("cyclomatic", 0),
        "clues": clues,
        "glibc": glibc,
    }
