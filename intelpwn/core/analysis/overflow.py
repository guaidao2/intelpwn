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

    if not func_bounds and insns:
        func_bounds = [(insns[0].address, insns[-1].address + 1, "sub_%x" % insns[0].address)]

    # 建立 PLT 地址→名称映射
    try:
        pwn_elf = ELF(path, checksec=False)
        plt_map = {v: k for k, v in pwn_elf.plt.items()}
    except Exception:
        plt_map = {}

    dangerous_names = {'read', 'gets', 'fgets', 'scanf', 'system', 'execve'}

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

                if callee not in dangerous_names:
                    continue

                truly_dangerous = False
                arg_size = -1
                for j in range(max(0, idx - 10), idx):
                    prev = func_insns[j]
                    if callee == 'read' and prev.mnemonic == 'mov' and 'edx' in prev.op_str.split(',')[0]:
                        try:
                            arg_size = int(prev.op_str.split(',')[1].strip(), 16)
                        except ValueError:
                            pass
                    if callee == 'read' and prev.mnemonic == 'mov' and ('rdx,' in prev.op_str or 'rdx ' in prev.op_str):
                        parts = prev.op_str.split(',')
                        src = parts[1].strip() if len(parts) > 1 else ""
                        try:
                            arg_size = int(src, 16)
                        except ValueError:
                            pass
                    if callee == 'fgets' and prev.mnemonic == 'mov' and ('esi,' in prev.op_str or 'esi ' in prev.op_str):
                        parts = prev.op_str.split(',')
                        src = parts[1].strip() if len(parts) > 1 else ""
                        try:
                            arg_size = int(src, 16)
                        except ValueError:
                            pass
                    if callee == 'fgets' and prev.mnemonic == 'mov' and ('rsi,' in prev.op_str or 'rsi ' in prev.op_str):
                        parts = prev.op_str.split(',')
                        src = parts[1].strip() if len(parts) > 1 else ""
                        try:
                            arg_size = int(src, 16)
                        except ValueError:
                            pass

                if callee == 'gets':
                    truly_dangerous = True
                elif callee in ('read', 'fgets') and arg_size > 0:
                    truly_dangerous = arg_size > stack_size + 16
                elif callee in ('read', 'fgets') and arg_size < 0:
                    truly_dangerous = True
                elif callee == 'scanf':
                    truly_dangerous = True
                else:
                    truly_dangerous = False

                if truly_dangerous:
                    has_danger = True
                    danger_addr = f"{callee} ({insn.op_str})"
                    if arg_size > 0:
                        danger_addr += f" size={arg_size}"

        if has_lea and has_danger:
            padding = stack_size + (8 if bits == 64 else 4)
            results.append({
                "function": f_name,
                "address": hex(f_start),
                "stack_size": stack_size,
                "calculated_padding": padding,
                "dangerous_call": danger_addr,
                "lea_insn": lea_insn,
                "confidence": "高",
            })

    return results


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
