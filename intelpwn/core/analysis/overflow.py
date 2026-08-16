"""反汇编级栈溢出检测 + 三重 padding 验证"""

import bisect
import os
import re
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from elftools.elf.elffile import ELFFile
from pwn import ELF, cyclic, cyclic_find, p64, p32

from intelpwn.utils.binary import open_elf, run


def disassemble_text(path: str):
    """反汇编 .text 段，返回 (insns列表, bits, 架构字符串, base_addr) 或 None。"""
    try:
        with open_elf(path) as elf:
            e_machine = elf.header.e_machine
            if e_machine == 'EM_X86_64':
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                bits = 64
            elif e_machine in ('EM_386', 'EM_486'):
                md = Cs(CS_ARCH_X86, CS_MODE_32)
                bits = 32
            else:
                return None
            md.detail = True
            text = elf.get_section_by_name('.text')
            if not text:
                return None
            data = text.data()
            base = text['sh_addr']
            insns = list(md.disasm(data, base))
            return insns, bits, e_machine, base
    except Exception:
        return None


def analyze_assembly_overflow(path: str, insns=None, bits=None,
                              func_bounds=None, plt_map=None,
                              semantic_mode: str = "throttled") -> list:
    """反汇编 .text 段, 找 lea + read/gets/scanf 模式 → 算 padding

    Args:
        path: 二进制路径
        insns: 可选预反汇编指令列表（避免重复反汇编）
        bits: 可选预检测位数
        func_bounds: 可选黑板函数边界缓存 (func_bounds/plt_map 复用避免重扫)
        plt_map: 可选黑板 PLT 地址→名称缓存
        semantic_mode: angr 语义兜底 — throttled(默认, 节流+大小限制) / force(纯 angr)
    """
    if insns is None or bits is None:
        try:
            with open_elf(path) as elf:
                return _analyze_overflow_inner(elf, path)
        except Exception:
            return []
    return _analyze_overflow_from_insns(insns, bits, path, func_bounds=func_bounds,
                                        plt_map=plt_map, semantic_mode=semantic_mode)


def _analyze_overflow_inner(elf, path: str) -> list:
    """内部：在 open_elf 上下文中执行反汇编检测"""
    e_machine = elf.header.e_machine
    if e_machine == 'EM_X86_64':
        bits = 64
    elif e_machine in ('EM_386', 'EM_486'):
        bits = 32
    else:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True

    text = elf.get_section_by_name('.text')
    if not text:
        return []
    data = text.data()
    base = text['sh_addr']
    insns = list(md.disasm(data, base))
    return _analyze_overflow_from_insns(insns, bits, path)


# ══════════════════════════════════════════════════════════════════
# 语义查询层 (v2): 定义-使用链数据流, 替代脆弱的前 N 条窗口正则匹配
#
# 规则从"匹配指令"升级为"匹配语义关系":
#   _buf_stack_offset(调用点, 缓冲寄存器) → 栈偏移 int | None(非栈) | UNKNOWN
#   _size_value(调用点, 大小寄存器)       → 常量 int | None | UNKNOWN
# 回溯整个函数 (最多 BACKTRACK_LIMIT 条, 不锁死窗口), 追 mov/lea 链式传播,
# 编译器重排/长链都追得到; 分支/调用处截断该路径.
# ══════════════════════════════════════════════════════════════════

UNKNOWN = None  # 语义查询结果: None = 无法确定 (供 angr 兜底/保守处理)

_BACKTRACK_LIMIT = 200  # 单次查询最多回溯指令数 (防超大函数 O(N²))


def _reg_family(reg: str) -> str:
    """寄存器族: rax/r/eax/ax/al → rax (用于跨宽度传播)"""
    r = reg.lower()
    for base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
        if r == base or r.startswith(base):
            return base
        if base.startswith('r') and r in ('e' + base[1:],):
            return base
    return reg.lower()


def _parse_lea_stack_offset(op_str: str):
    """lea reg, [rbp - 0x40] → (reg, 0x40); [rbp+8]/[rbp-8] 符号化; 非 rbp 基址 → None"""
    m = re.match(r'^\s*(\S+),\s*\[(?:r|e)?bp\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', op_str)
    if not m:
        return None
    reg, sign, val = m.group(1), m.group(2), int(m.group(3), 16)
    off = val if sign == '-' else -val
    # 负位移 (栈内局部) 才是缓冲; [rbp+8] 是入参, 不是栈缓冲
    if off <= 0:
        return None
    return reg, off


def _parse_mov_const(op_str: str):
    """mov reg, imm → (reg, int); mov reg, reg → (reg, src_reg); 其他 → None"""
    parts = op_str.split(',')
    if len(parts) != 2:
        return None
    dst, src = parts[0].strip(), parts[1].strip()
    try:
        if src.startswith('0x') or src.isdigit():
            return dst, int(src, 16)
    except ValueError:
        pass
    if re.match(r'^[er]?[a-ds]?x?[0-9]*$', src) or re.match(r'^(r\d+|[er][abcd]x|[er]sp|[er]bp|[er]si|[er]di)$', src):
        return dst, src  # 寄存器传播
    return None


def _buf_stack_offset(func_insns, call_idx: int, buf_reg: str, limit: int = _BACKTRACK_LIMIT):
    """语义查询: 回溯 buf_reg 的定义链, 返回栈偏移 (lea [rbp-X]) 或 None (非栈/无法确定).

    追 mov 链式传播 (lea rax,[rbp-0x40] → mov rsi,rax → 调用), 编译器重排
    (lea 提前几百条) 也追得到 — 与旧窗口正则的核心差异。
    """
    target = _reg_family(buf_reg)
    for k in range(call_idx - 1, max(-1, call_idx - limit - 1), -1):
        insn = func_insns[k]
        m, ops = insn.mnemonic, insn.op_str
        if m in ('call', 'jmp', 'ret'):
            break  # 函数调用/跳转截断路径 (跨函数数据流不属于本函数)
        if m == 'lea':
            r = _parse_lea_stack_offset(ops)
            if r:
                dst, off = r
                if _reg_family(dst) == target:
                    return off
                continue  # lea 其他寄存器 → 不影响 target
        if m == 'mov':
            r = _parse_mov_const(ops)
            if r:
                dst, src = r
                if isinstance(src, int):
                    if _reg_family(dst) == target:
                        return 0 if src == 0 else None  # mov target, imm: 常数非栈
                    continue
                # mov dst, src (寄存器传播)
                if _reg_family(dst) == target:
                    target = _reg_family(src)  # 沿源寄存器继续回溯
        # 其他指令 (add/sub/算术) 写到 target → 值不再纯 → 无法确定
        if m in ('add', 'sub', 'xor', 'imul', 'and', 'or', 'shl', 'shr', 'inc', 'dec'):
            dst = ops.split(',')[0].strip() if ',' in ops else ops.strip()
            if _reg_family(dst) == target:
                return None
    return None


def _size_value(func_insns, call_idx: int, size_reg: str, limit: int = _BACKTRACK_LIMIT):
    """语义查询: 回溯 size_reg 定义链 → 常量大小 (int) 或 None (非常量/无法确定)."""
    target = _reg_family(size_reg)
    for k in range(call_idx - 1, max(-1, call_idx - limit - 1), -1):
        insn = func_insns[k]
        m, ops = insn.mnemonic, insn.op_str
        if m in ('call', 'jmp', 'ret'):
            break
        if m == 'mov':
            r = _parse_mov_const(ops)
            if r:
                dst, src = r
                if isinstance(src, int):
                    if _reg_family(dst) == target:
                        return src
                    continue
                if _reg_family(dst) == target:
                    target = _reg_family(src)  # mov target, reg → 沿源继续
        elif m == 'lea':
            r = _parse_lea_stack_offset(ops)
            if r and _reg_family(r[0]) == target:
                return None  # lea 栈地址当大小 → 非常量
        elif m in ('add', 'sub', 'xor', 'imul', 'and', 'or', 'shl', 'shr', 'inc', 'dec'):
            dst = ops.split(',')[0].strip() if ',' in ops else ops.strip()
            if _reg_family(dst) == target:
                # mov edx, 0x100; sub edx, 8 → 非常量但可沿源继续? 保守: 判未知
                # (简单 add/sub 立即数可精化, 首版保守)
                return None
    return None


def _buf_reg_on_stack(func_insns, call_idx: int, buf_reg: str, window: int = 30) -> bool:
    """近似数据流: 调用前 window 条指令内, buf_reg 是否被 lea [rbp-X] 赋值。

    通过 mov 传播跟踪 (lea rax,[rbp-X]; mov rsi,rax 也算指向栈),
    排除从堆/全局加载的目标 (mov rsi,[rip+chunks] / mov rsi,[rbp+8] 参数)。
    """
    stack_regs = set()
    for insn in func_insns[max(0, call_idx - window):call_idx]:
        m = insn.mnemonic
        ops = insn.op_str
        if m == 'lea' and ('rbp' in ops or 'ebp' in ops):
            dst = ops.split(',')[0].strip()
            stack_regs.add(dst)
        elif m == 'mov':
            parts = ops.split(',')
            if len(parts) == 2:
                dst, src = parts[0].strip(), parts[1].strip()
                if src in stack_regs:
                    stack_regs.add(dst)
    return buf_reg in stack_regs


def _stack_buf_passed(func_insns, call_idx: int, window: int = 30) -> bool:
    """x86 32 位 cdecl: 参数在栈上, 无寄存器传参约定.

    检测调用前是否有 lea [ebp-X] 装载栈缓冲 → 经 push reg / mov [esp..], reg
    写入参数区 (lea eax,[ebp-0x28]; push eax; call gets)。
    """
    stack_regs = set()
    for insn in func_insns[max(0, call_idx - window):call_idx]:
        m, ops = insn.mnemonic, insn.op_str
        # 只认 lea [ebp-0x..] 负位移 (栈缓冲); [ebp+8] 是参数装载, 不是缓冲
        if m == 'lea' and re.search(r'\[ebp\s*-', ops):
            dst = ops.split(',')[0].strip()
            if dst.startswith('e') or dst.startswith('r'):
                stack_regs.add(dst)
        elif m == 'mov':
            parts = ops.split(',')
            if len(parts) == 2:
                dst, src = parts[0].strip(), parts[1].strip()
                if src in stack_regs and (dst.startswith('e') or dst.startswith('r')):
                    stack_regs.add(dst)
    if not stack_regs:
        return False
    # 栈缓冲地址被压栈或写入栈参数区 → 传给目标函数
    for insn in func_insns[max(0, call_idx - window):call_idx]:
        m, ops = insn.mnemonic, insn.op_str
        if m == 'push' and ops.strip() in stack_regs:
            return True
        if m == 'mov':
            parts = ops.split(',')
            # capstone 输出带尺寸前缀: mov dword ptr [esp], eax — 用正则匹配 [esp
            if len(parts) == 2 and re.search(r'\[e?s?p', parts[0].strip()) \
                    and parts[1].strip() in stack_regs:
                return True
    return False


def _analyze_overflow_from_insns(insns, bits, path, func_bounds=None, plt_map=None,
                                 semantic_mode: str = "throttled") -> list:
    """反汇编结果分析 — 与反汇编解耦 (func_bounds/plt_map 可传黑板缓存复用)"""
    results = []

    # 按函数边界分割 (基于符号表) — 黑板缓存优先, 无则自扫
    if func_bounds is None:
        func_bounds = []
        try:
            with open_elf(path) as elf:
                symtab = elf.get_section_by_name('.symtab')
                if symtab:
                    for sym in symtab.iter_symbols():
                        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                            func_bounds.append((sym['st_value'], sym['st_value'] + sym['st_size'], sym.name))
        except Exception:
            pass

    if not func_bounds and insns:
        func_bounds = [(insns[0].address, insns[-1].address + 1, "sub_%x" % insns[0].address)]

    # 建立 PLT 地址→名称映射 (黑板缓存优先; 静态链接无 PLT: fallback 到符号表)
    # 注意: 黑板可能传空 {} (静态链接无 PLT) — 必须继续走 fallback, 不能只判 None
    if not plt_map:
        plt_map = {}
        try:
            pwn_elf = ELF(path, checksec=False)
            plt_map = {v: k for k, v in pwn_elf.plt.items()}
        except Exception:
            pass
        if not plt_map:
            # 静态链接/无 PLT: 用符号表 (STT_FUNC) 建 addr→name, 覆盖 gets/read/strcpy 等
            try:
                with open_elf(path) as elf:
                    for sec_name in ('.symtab', '.dynsym'):
                        sec = elf.get_section_by_name(sec_name)
                        if not sec:
                            continue
                        for sym in sec.iter_symbols():
                            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                                plt_map.setdefault(sym['st_value'], sym.name)
            except Exception:
                pass

    # 危险输入函数分两类:
    #  - BOUNDED_INPUTS: 有显式大小参数, 需比较 大小 vs 栈帧
    #  - UNBOUNDED_WRITES: 无大小参数, 目标地址落在栈上即危险
    #  - scanf 特殊: 取决于格式串 (仅 %s 无宽度时危险)
    bounded_inputs = {
        'read': ('rdx', 'edx'),      # (fd, buf, size)
        'recv': ('rdx', 'edx'),      # (fd, buf, size, flags)
        'memcpy': ('rdx', 'edx'),    # (dst, src, size)
        'strncpy': ('rdx', 'edx'),   # (dst, src, size)
        'fgets': ('rsi', 'esi'),     # (buf, size, stream)
        'snprintf': ('rsi', 'esi'),  # (buf, size, fmt, ...)
    }
    unbounded_writes = {'gets', 'strcpy', 'sprintf', 'strcat'}
    input_funcs = set(bounded_inputs) | unbounded_writes | {'scanf'}

    # 预建地址表供二分查找 (O(N) 一次, 替代 O(N×F) 逐函数过滤)
    addrs = [insn.address for insn in insns]

    for f_start, f_end, f_name in func_bounds:
        lo = bisect.bisect_left(addrs, f_start)
        hi = bisect.bisect_right(addrs, f_end - 1)
        func_insns = insns[lo:hi]
        if not func_insns:
            continue

        has_lea = False
        stack_size = 0
        lea_insn = ""
        has_danger = False
        danger_addr = ""
        danger_site = None
        danger_conf = "高"

        for idx, insn in enumerate(func_insns):
            if insn.mnemonic == 'lea' and ('rbp' in insn.op_str or 'ebp' in insn.op_str):
                m = re.search(r'\[rbp\s*-\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
                if not m:
                    m = re.search(r'\[ebp\s*-\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
                if m:
                    sz = int(m.group(1), 16)
                    if sz > stack_size:
                        stack_size = sz
                        has_lea = True
                        lea_insn = f"{insn.mnemonic} {insn.op_str}"

            if insn.mnemonic == 'call':
                try:
                    target = int(insn.op_str, 16)
                    callee = plt_map.get(target, "")
                except (ValueError, TypeError):
                    continue

                if callee not in input_funcs:
                    continue

                window = func_insns[max(0, idx - 10):idx]

                truly_dangerous = False
                arg_size = -1
                conf = "高"

                if callee in bounded_inputs:
                    reg64, reg32 = bounded_inputs[callee]
                    # 缓冲寄存器: read/recv 在 rsi (rdi 是 fd), 其余在 rdi
                    buf_reg = 'rsi' if callee in ('read', 'recv') else 'rdi'
                    if bits == 32:
                        buf_reg = 'esi' if buf_reg == 'rsi' else 'edi'
                    # 语义查询 (v2): 回溯定义链求 缓冲栈偏移 + 常量大小, 破固定窗口
                    size_reg = reg64 if bits == 64 else reg32
                    # force 模式: 纯 angr 符号执行 (跳过轻量, 彻底但慢)
                    if semantic_mode == "force":
                        try:
                            from intelpwn.core.analysis.semantic_angr import (
                                angr_eval_size, angr_eval_buf_offset)
                            buf_off = angr_eval_buf_offset(path, f_start, insn.address,
                                                           buf_reg, bits, mode="force")
                            arg_size = angr_eval_size(path, f_start, insn.address,
                                                      size_reg, bits, mode="force")
                        except Exception:
                            buf_off = _buf_stack_offset(func_insns, idx, buf_reg)
                            arg_size = _size_value(func_insns, idx, size_reg)
                    else:
                        buf_off = _buf_stack_offset(func_insns, idx, buf_reg)
                        arg_size = _size_value(func_insns, idx, size_reg)
                        # angr 兜底: 轻量判未知 (且大小非常量) 时符号执行求值
                        if arg_size is None:
                            try:
                                from intelpwn.core.analysis.semantic_angr import angr_eval_size
                                arg_size = angr_eval_size(path, f_start, insn.address,
                                                          size_reg, bits, mode="throttled")
                            except Exception:
                                pass
                    if bits == 32:
                        # 32 位 cdecl: 参数在栈上, 缓冲经 push/mov[esp] 传递 — 用栈传递检测
                        stack_linked = _stack_buf_passed(func_insns, idx)
                    else:
                        stack_linked = buf_off is not None
                    if arg_size is not None and arg_size > 0:
                        # 大小常量: 需同时知道缓冲偏移才能比 (栈缓冲 or 未知)
                        truly_dangerous = stack_linked and arg_size > (buf_off or 0) + 16
                    else:
                        # 大小无法静态确定 → 仅当目标确认在栈上才保守报险
                        truly_dangerous = stack_linked
                        if truly_dangerous:
                            conf = "中"

                elif callee in unbounded_writes:
                    # 无界写: 第一个参数 (rdi/edi) 必须指向栈缓冲
                    if bits == 32:
                        truly_dangerous = _stack_buf_passed(func_insns, idx)
                    else:
                        truly_dangerous = _buf_stack_offset(func_insns, idx, 'rdi') is not None

                elif callee == 'scanf':
                    # 格式串含无宽度 %s → 危险; 否则 (如 %d/%x) 不是溢出源
                    fmt = _resolve_scanf_format(path, window, bits)
                    if fmt and re.search(r'%[0-9]*s', fmt) and not re.search(r'%[0-9]+s', fmt):
                        if bits == 32:
                            truly_dangerous = _stack_buf_passed(func_insns, idx)
                        else:
                            truly_dangerous = _buf_stack_offset(func_insns, idx, 'rdi') is not None

                if truly_dangerous:
                    has_danger = True
                    danger_addr = f"{callee} ({insn.op_str})"
                    danger_site = insn.address
                    if arg_size is not None and arg_size > 0:
                        danger_addr += f" size={arg_size}"
                    danger_conf = conf

        if has_lea and has_danger:
            padding = stack_size + (8 if bits == 64 else 4)
            results.append({
                "function": f_name,
                "address": hex(f_start),
                "stack_size": stack_size,
                "calculated_padding": padding,
                "dangerous_call": danger_addr,
                "call_site": hex(danger_site) if danger_site else None,
                "lea_insn": lea_insn,
                "confidence": danger_conf,
            })

    return results


def _resolve_scanf_format(path: str, window, bits) -> str:
    """解析 scanf 的格式串: 查找 lea reg, [rip+disp] / mov reg, imm / push imm (x86) 指向的 .rodata 字符串"""
    fmt_addr = None
    for prev in window:
        if prev.mnemonic == 'lea' and 'rip' in prev.op_str:
            m = re.search(r'\[rip\s*\+\s*(0x[0-9a-fA-F]+)\]', prev.op_str)
            if m:
                fmt_addr = prev.address + prev.size + int(m.group(1), 16)
                break
        elif prev.mnemonic == 'mov' and prev.op_str.startswith(('rdi,', 'edi,')):
            parts = prev.op_str.split(',')
            if len(parts) >= 2:
                try:
                    fmt_addr = int(parts[1].strip(), 16)
                    break
                except ValueError:
                    pass
        elif bits == 32 and prev.mnemonic == 'mov' and re.search(r'\[e?s?p', prev.op_str):
            # x86 32 位: mov [esp], imm / mov dword ptr [esp], imm (格式串入栈)
            # 取逗号后的立即数 (槽位移 0x4 不是格式串地址)
            m = re.search(r',\s*0x([0-9a-fA-F]+)', prev.op_str)
            if m:
                fmt_addr = int(m.group(1), 16)
                break
        elif bits == 32 and prev.mnemonic == 'push':
            # x86 32 位: push imm (格式串入栈)
            try:
                fmt_addr = int(prev.op_str.strip(), 16)
                break
            except ValueError:
                pass
    if fmt_addr is None:
        return ""
    try:
        with open_elf(path) as elf:
            # vaddr → 文件偏移 (非 PIE 下 vaddr ≠ offset, 直接 seek(vaddr) 会越界)
            off = None
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= fmt_addr \
                        < seg['p_vaddr'] + seg['p_memsz']:
                    off = seg['p_offset'] + (fmt_addr - seg['p_vaddr'])
                    break
            if off is None:
                return ""
            with open(path, 'rb') as f:
                f.seek(off)
                raw = f.read(64)
        return raw.split(b'\x00')[0].decode(errors='replace')
    except Exception:
        return ""


def verify_padding(path: str, static_padding: int) -> dict:
    """三重验证: 静态 + objdump 反汇编 + cyclic 动态 (x64/x86 自适应)"""
    bits = 64
    try:
        with open_elf(path) as elf:
            if elf.header.e_machine in ('EM_386', 'EM_486'):
                bits = 32
    except Exception:
        pass
    n = 8 if bits == 64 else 4
    bp_regs = ('rbp', 'rsp') if bits == 64 else ('ebp', 'esp')

    results = {
        "static": static_padding,
        "objdump": None,
        "dynamic": None,
        "final": static_padding,
        "confidence": "低",
    }

    # objdump 验证 (Intel 语法, 否则 GNU 默认 AT&T 与正则不匹配)
    rc, out, _ = run(["objdump", "-d", "-M", "intel", path])
    if rc == 0:
        lea_matches = re.findall(
            r'lea\s+rax,\s*\[rbp[^]]*-(0x[0-9a-fA-F]+)\]', out
        )
        if not lea_matches:
            lea_matches = re.findall(
                r'lea\s+eax,\s*\[ebp[^]]*-(0x[0-9a-fA-F]+)\]', out
            )
        if lea_matches:
            stack_sz = max(int(m, 16) for m in lea_matches)
            obj_pad = stack_sz + (8 if bits == 64 else 4)
            results["objdump"] = obj_pad

    # 静态 + objdump 一致 → 跳过 GDB (90%+ 情况)
    if results["static"] is not None and results["static"] == results.get("objdump"):
        results["final"] = results["static"]
        results["confidence"] = "高"
        return results

    # 动态 cyclic 验证 (仅在静态与 objdump 不一致时执行)
    pattern = cyclic(2000, n=n)
    cf = tempfile.NamedTemporaryFile(delete=False, suffix=".crash")
    cp = cf.name
    cf.write(pattern)
    cf.close()

    gdb_script = f"""set pagination off
file {path}
run < {cp}
info registers {'rip rsp rbp' if bits == 64 else 'eip esp ebp'}
quit"""
    sf = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gdb")
    sf.write(gdb_script)
    sp = sf.name
    sf.close()

    _, out, _ = run(["gdb", "-batch", "-x", sp])
    os.unlink(cp)
    os.unlink(sp)

    regs = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if parts and len(parts) >= 2:
            if parts[0] in ('rbp', 'rsp', 'rip', 'ebp', 'esp', 'eip'):
                try:
                    regs[parts[0]] = int(parts[1], 16)
                except ValueError:
                    pass

    for rname in bp_regs:
        if rname in regs:
            val = regs[rname]
            packed = p64(val) if bits == 64 else p32(val)
            offset = cyclic_find(packed[:n], n=n)
            if offset is not None and offset >= 0:
                pad = offset + n if rname in ('rbp', 'ebp') else offset
                if 8 <= pad <= 4096:
                    results["dynamic"] = pad
                    break

    # 综合可信度
    vals = [v for v in [results["static"], results["objdump"], results["dynamic"]] if v]
    if len(vals) >= 2 and max(vals) == min(vals):
        results["final"] = vals[0]
        results["confidence"] = "高"
    elif len(vals) >= 2:
        results["final"] = max(set(vals), key=vals.count) if len(set(vals)) < len(vals) else vals[0]
        results["confidence"] = "中"
    elif vals:
        results["final"] = vals[0]
        results["confidence"] = "低"

    return results
