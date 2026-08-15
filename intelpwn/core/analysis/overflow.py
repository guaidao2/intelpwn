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


def analyze_assembly_overflow(path: str, insns=None, bits=None) -> list:
    """反汇编 .text 段, 找 lea + read/gets/scanf 模式 → 算 padding

    Args:
        path: 二进制路径
        insns: 可选预反汇编指令列表（避免重复反汇编）
        bits: 可选预检测位数
    """
    if insns is None or bits is None:
        try:
            with open_elf(path) as elf:
                return _analyze_overflow_inner(elf, path)
        except Exception:
            return []
    return _analyze_overflow_from_insns(insns, bits, path)


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


def _analyze_overflow_from_insns(insns, bits, path) -> list:
    """反汇编结果分析 — 与反汇编解耦"""
    results = []

    # 按函数边界分割 (基于符号表) — 先物化列表再关文件
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

    # 建立 PLT 地址→名称映射
    try:
        pwn_elf = ELF(path, checksec=False)
        plt_map = {v: k for k, v in pwn_elf.plt.items()}
    except Exception:
        plt_map = {}

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
                    # 大小参数常通过 mov reg, imm 或 mov reg, [reg+disp] 传入
                    for prev in window:
                        if prev.mnemonic == 'mov':
                            parts = prev.op_str.split(',')
                            if len(parts) >= 2 and parts[0].strip() in (reg64, reg32):
                                try:
                                    arg_size = int(parts[1].strip(), 16)
                                    break
                                except ValueError:
                                    pass
                    # 目标必须确实指向栈 (lea rbp-X 经 mov 传播), 否则是堆/全局写, 不是栈溢出
                    stack_linked = _buf_reg_on_stack(func_insns, idx, buf_reg)
                    if arg_size > 0:
                        truly_dangerous = stack_linked and arg_size > stack_size + 16
                    else:
                        # 大小无法静态确定 → 仅当目标确认在栈上才保守报险
                        truly_dangerous = stack_linked
                        if truly_dangerous:
                            conf = "中"

                elif callee in unbounded_writes:
                    # 无界写: 第一个参数 (rdi/edi) 必须指向栈缓冲
                    first_reg = 'rdi' if bits == 64 else 'edi'
                    truly_dangerous = _buf_reg_on_stack(func_insns, idx, first_reg)

                elif callee == 'scanf':
                    # 格式串含无宽度 %s → 危险; 否则 (如 %d/%x) 不是溢出源
                    fmt = _resolve_scanf_format(path, window, bits)
                    if fmt and re.search(r'%[0-9]*s', fmt) and not re.search(r'%[0-9]+s', fmt):
                        first_reg = 'rdi' if bits == 64 else 'edi'
                        truly_dangerous = _buf_reg_on_stack(func_insns, idx, first_reg)

                if truly_dangerous:
                    has_danger = True
                    danger_addr = f"{callee} ({insn.op_str})"
                    danger_site = insn.address
                    if arg_size > 0:
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
    """解析 scanf 的格式串: 查找 lea reg, [rip+disp] / mov reg, imm 指向的 .rodata 字符串"""
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
    if fmt_addr is None:
        return ""
    try:
        with open(path, 'rb') as f:
            f.seek(fmt_addr)
            raw = f.read(64)
        return raw.split(b'\x00')[0].decode(errors='replace')
    except Exception:
        return ""


def verify_padding(path: str, static_padding: int) -> dict:
    """三重验证: 静态 + objdump 反汇编 + cyclic 动态"""
    arch = "x64"  # fallback, caller should pass arch
    bits = 64
    n = 8

    results = {
        "static": static_padding,
        "objdump": None,
        "dynamic": None,
        "final": static_padding,
        "confidence": "低",
    }

    # objdump 验证
    rc, out, _ = run(["objdump", "-d", path])
    if rc == 0:
        lea_matches = re.findall(
            r'lea\s+(?:rax|eax),\s*\[rbp[^]]*-(0x[0-9a-fA-F]+)\]', out
        ) or re.findall(
            r'lea\s+(?:eax),\s*\[ebp[^]]*-(0x[0-9a-fA-F]+)\]', out
        )
        if lea_matches:
            stack_sz = max(int(m, 16) for m in lea_matches)
            obj_pad = stack_sz + 8 if bits == 64 else stack_sz + 4
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
info registers rip rsp rbp
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
            if parts[0] in ('rbp', 'rsp', 'rip'):
                try:
                    regs[parts[0]] = int(parts[1], 16)
                except ValueError:
                    pass

    for rname in ('rbp', 'rsp'):
        if rname in regs:
            val = regs[rname]
            packed = p64(val) if bits == 64 else p32(val)
            offset = cyclic_find(packed[:n], n=n)
            if offset is not None and offset >= 0:
                pad = offset + n if rname == 'rbp' else offset
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
