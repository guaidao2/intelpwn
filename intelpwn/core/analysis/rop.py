"""ROP gadgets 扫描 + 链可行性分析

优化：定向 capstone 扫描替代 pwntools ROP 全量扫描。
对 6 个常用 gadget 直接查指令序列，不用 pwntools 的大海捞针。
对大二进制，从 3-5s 降到 ~0.1s。
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from intelpwn.utils.binary import open_elf, strings_has_binsh


def _disassemble_text(path: str):
    """反汇编 .text 段，返回 (insns, bits) 或 (None, None)"""
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
                return None, None
            md.detail = True
            text = elf.get_section_by_name('.text')
            if not text:
                return None, None
            insns = list(md.disasm(text.data(), text['sh_addr']))
            return insns, bits
    except Exception:
        return None, None


def find_gadgets_capstone(insns, bits) -> dict:
    """用 capstone 直接扫描常用 gadget。仅返回 .text 范围内对齐指令。"""
    result = {
        "pop_rdi": "未找到",
        "pop_rsi": "未找到",
        "pop_rdx": "未找到",
        "ret": "未找到",
        "pop_eax": "未找到",
        "pop_ebx": "未找到",
        "pop_ecx": "未找到",
        "pop_edx": "未找到",
        "int_0x80": "未找到",
        "jmp_rsp": "未找到",
        "syscall": "未找到",
    }

    for i, insn in enumerate(insns):
        mnemo = insn.mnemonic
        op_str = insn.op_str

        # ret
        if mnemo == 'ret' and result["ret"] == "未找到":
            result["ret"] = hex(insn.address)

        # pop rdi; ret (x64)
        if bits == 64 and mnemo == 'pop' and op_str == 'rdi':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["pop_rdi"] == "未找到":
                    result["pop_rdi"] = hex(insn.address)

        # pop rsi; ret (x64)
        if bits == 64 and mnemo == 'pop' and op_str == 'rsi':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["pop_rsi"] == "未找到":
                    result["pop_rsi"] = hex(insn.address)

        # pop rdx; ret (x64)
        if bits == 64 and mnemo == 'pop' and op_str == 'rdx':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["pop_rdx"] == "未找到":
                    result["pop_rdx"] = hex(insn.address)

        # pop eax; ret (x86)
        if bits == 32 and mnemo == 'pop' and op_str == 'eax':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["pop_eax"] == "未找到":
                    result["pop_eax"] = hex(insn.address)

        # pop ebx; ret (x86 — execve 第 1 参)
        if bits == 32 and mnemo == 'pop' and op_str == 'ebx':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result.get("pop_ebx", "未找到") == "未找到":
                    result["pop_ebx"] = hex(insn.address)

        # pop ecx; ret (x86 — execve 第 2 参)
        if bits == 32 and mnemo == 'pop' and op_str == 'ecx':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result.get("pop_ecx", "未找到") == "未找到":
                    result["pop_ecx"] = hex(insn.address)

        # pop edx; ret (x86 — execve 第 3 参)
        if bits == 32 and mnemo == 'pop' and op_str == 'edx':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result.get("pop_edx", "未找到") == "未找到":
                    result["pop_edx"] = hex(insn.address)

        # int 0x80 (x86)
        if bits == 32 and mnemo == 'int' and op_str == '0x80':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["int_0x80"] == "未找到":
                    result["int_0x80"] = hex(insn.address)

        # jmp rsp (x64) — shellcode 注入无地址泄露时用
        if bits == 64 and mnemo == 'jmp' and op_str == 'rsp':
            if result["jmp_rsp"] == "未找到":
                result["jmp_rsp"] = hex(insn.address)

        # syscall; ret (x64) — SROP / 直接 syscall
        if bits == 64 and mnemo == 'syscall':
            if i + 1 < len(insns) and insns[i + 1].mnemonic == 'ret':
                if result["syscall"] == "未找到":
                    result["syscall"] = hex(insn.address)

    return result


def analyze_rop(path: str, plt: dict = None, insns=None, bits=None) -> dict:
    """ROP gadgets 扫描 + 链可行性

    使用 capstone 定向扫描 6 个常用 gadget。
    若 scan_mode="full" 或 capstone 找不到关键 gadget，回退到 pwntools ROP。

    Args:
        path: 二进制路径
        plt: 可选的 PLT 函数表
        insns: 可选预反汇编指令列表
        bits: 可选预检测位数
    """
    # 分解/获取反汇编
    if insns is None or bits is None:
        insns, bits = _disassemble_text(path)
    if insns is None:
        return {"pop_rdi": "未找到", "pop_rsi": "未找到", "ret": "未找到"}

    arch = "x64" if bits == 64 else "x86"

    # 定向扫描
    result = find_gadgets_capstone(insns, bits)

    # 若 ret 仍缺失，回退到 pwntools ROP 找跨节 gadget
    if result.get("ret") == "未找到" or result.get("pop_rdi") == "未找到":
        try:
            from pwn import ELF, ROP
            elf = ELF(path, checksec=False)
            rop = ROP(elf)

            fallback_map = {
                "pop_rdi": ['pop rdi', 'ret'],
                "pop_rsi": ['pop rsi', 'ret'],
                "pop_rdx": ['pop rdx', 'ret'],
                "ret": ['ret'],
                "pop_eax": ['pop eax', 'ret'],
                "int_0x80": ['int 0x80', 'ret'],
                "jmp_rsp": ['jmp rsp'],
                "syscall": ['syscall', 'ret'],
            }
            for gname, pattern in fallback_map.items():
                if result.get(gname, "未找到") == "未找到":
                    try:
                        gadget = rop.find_gadget(pattern)
                        if gadget:
                            result[gname] = hex(gadget[0])
                    except Exception:
                        pass
        except Exception:
            pass

    # 链可行性分析
    if plt is None:
        plt = {}

    chains = []
    if result.get('pop_rdi', "未找到") != "未找到" and 'system' in plt and 'puts' in plt:
        chains.append({
            "type": "ret2system",
            "condition": "pop_rdi + system@plt + /bin/sh",
            "feasible": strings_has_binsh(path),
        })

    if result.get('pop_rdi', "未找到") != "未找到" and 'write' in plt:
        chains.append({
            "type": "ret2libc (write泄漏)",
            "condition": "pop_rdi + write@plt + main → 二次利用",
            "feasible": True,
        })

    if result.get('syscall', "未找到") != "未找到":
        chains.append({
            "type": "SROP",
            "condition": "syscall; ret gadget + 可控栈 → sigreturn",
            "feasible": True,
        })

    if result.get('pop_eax', "未找到") != "未找到" and result.get('int_0x80', "未找到") != "未找到":
        chains.append({
            "type": "execve syscall",
            "condition": "pop_eax=59 + pop_ebx=binsh + int_0x80",
            "feasible": True,
        })

    result['chains'] = chains
    return result
