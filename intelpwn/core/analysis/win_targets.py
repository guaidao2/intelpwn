"""win 目标扫描 — 利用层"看整个二进制" (ret2text 泛化)

扫描 .text 中所有 call system/execve@plt 站点, 回走参数链到自包含起点
(mov <reg>, imm / lea <reg>, [rip+X]), 解析目标字符串, 命令特征判定。
返回目标地址 = 链起点 (ret 到这里顺势设置参数并 call system)。

不依赖函数符号: system/execve 是动态符号 (PLT), stripped 靶子同样适用。
纯 pyelftools + capstone, 无 pwn 依赖。
"""

import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from intelpwn.utils.binary import open_elf
from .overflow import disassemble_text

# 命令特征 (保守判别): 覆盖 /bin/sh 与 cat flag 类, 排除 system("clear") 等良性调用
_CMD_PATTERNS = (
    '/bin/sh', '/bin/bash', '/bin/zsh', 'sh -c', 'bash ',
    'cat ', 'nc ', 'ncat', 'nc.e', 'id', 'whoami',
    'ls /', 'head /', 'tail /', 'more /', 'less /', 'cp /', 'mv /',
)

_REGS64 = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9',
           'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
_REGS32 = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi')


def _is_command_string(s: str) -> bool:
    for p in _CMD_PATTERNS:
        if s.startswith(p):
            return True
    return False


def _vaddr_to_offset(path: str, vaddr: int) -> int:
    """vaddr → 文件偏移 (按 PT_LOAD 段映射; 非 PIE 常见 vaddr==offset 兜底)"""
    try:
        with open_elf(path) as elf:
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD':
                    start = seg['p_vaddr']
                    if start <= vaddr < start + seg['p_memsz']:
                        return vaddr - start + seg['p_offset']
    except Exception:
        pass
    return vaddr


def _read_string(path: str, vaddr: int) -> str:
    off = _vaddr_to_offset(path, vaddr)
    try:
        with open(path, 'rb') as f:
            f.seek(off)
            return f.read(64).split(b'\x00')[0].decode(errors='replace')
    except Exception:
        return ""


def _resolve_rdi_chain(insns, call_idx: int, window: int = 20):
    """回走 rdi 赋值链, 找自包含起点 (mov imm / lea [rip+X]).

    研究实证: ret 目标必须是链起点 — ret 到中间 (mov rdi, rax) 会因
    寄存器未初始化而崩。参数来自内存加载/栈时无法确认 → None。
    rdi/edi 等价 (32 位写零扩展)。返回 (字符串地址, 链起点指令地址) 或 None。
    """
    lo = max(0, call_idx - window)
    # rdi <-> edi 视为同一 (x64: mov edi 零扩展; x86 同理)
    cur_set = {'rdi', 'edi'}
    for prev in reversed(insns[lo:call_idx]):
        if prev.mnemonic not in ('mov', 'lea'):
            continue
        parts = prev.op_str.split(',')
        if len(parts) < 2 or parts[0].strip() not in cur_set:
            continue
        src = parts[1].strip()
        if prev.mnemonic == 'mov':
            m = re.search(r'0x[0-9a-fA-F]+', src)
            if m and '[' not in src:
                # mov edi, <imm> → 自包含起点 (pwn1 形态)
                return int(m.group(0), 16), prev.address
            # mov reg, reg2 → 链传播
            if src in _REGS64 or src in _REGS32:
                cur_set = {src}
                continue
            return None  # 内存加载/其他 → 无法确认
        else:  # lea
            m = re.search(r'\[rip\s*\+\s*(0x[0-9a-fA-F]+)\]', src)
            if m:
                addr = prev.address + prev.size + int(m.group(1), 16)
                return addr, prev.address
            return None  # lea 非 rip 相对 → 无法确认
    return None


def _resolve_x86_push(insns, call_idx: int, window: int = 15):
    """x86: system 参数压栈, 回找最近的 push <imm>"""
    for prev in reversed(insns[max(0, call_idx - window):call_idx]):
        if prev.mnemonic == 'push':
            m = re.search(r'0x[0-9a-fA-F]+', prev.op_str)
            if m:
                return int(m.group(0), 16), prev.address
    return None


def _build_plt_map(path: str, bits: int) -> dict:
    """PLT 槽地址 → 符号名 (纯 pyelftools: .rela.plt + .dynsym + .plt stub 扫描)"""
    plt = {}
    try:
        with open_elf(path) as elf:
            got_to_name = {}
            for secname in ('.rela.plt', '.rel.plt'):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                dynsym = elf.get_section_by_name('.dynsym')
                if not dynsym:
                    continue
                for reloc in sec.iter_relocations():
                    try:
                        got_to_name[reloc['r_offset']] = dynsym.get_symbol(reloc['r_info_sym']).name
                    except Exception:
                        pass
            plt_sec = elf.get_section_by_name('.plt')
            if not plt_sec:
                return {}
            data = plt_sec.data()
            base = plt_sec['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
            md.detail = True
            for insn in md.disasm(data, base):
                if insn.mnemonic == 'jmp' and 'rip' in insn.op_str:
                    m = re.search(r'\[rip\s*\+\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
                    if m:
                        got = insn.address + insn.size + int(m.group(1), 16)
                        if got in got_to_name:
                            plt[insn.address] = got_to_name[got]
    except Exception:
        pass
    return plt


def scan_win_targets(path: str, insns=None, bits=None) -> list:
    """扫描命令执行目标 (ret2text).

    Returns:
        [{address(链起点), call, string, string_addr}]
    """
    if insns is None or bits is None:
        pre = disassemble_text(path)
        if not pre:
            return []
        insns, bits = pre[0], pre[1]

    plt_map = _build_plt_map(path, bits)

    targets = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != 'call':
            continue
        try:
            callee = plt_map.get(int(insn.op_str, 16), "")
        except (ValueError, TypeError):
            continue
        if callee not in ('system', 'execve'):
            continue
        resolved = _resolve_rdi_chain(insns, i, bits) if bits == 64 else _resolve_x86_push(insns, i)
        if not resolved:
            continue
        str_addr, target_addr = resolved
        s = _read_string(path, str_addr)
        if not _is_command_string(s):
            continue
        targets.append({
            "address": hex(target_addr),
            "call": f"{callee} @ {hex(insn.address)}",
            "string": s,
            "string_addr": hex(str_addr),
        })
    return targets
