"""静态链接 libc 符号识别 — 能力包示例 (P2.1 静态链接专项)

静态链接二进制没有 PLT/GOT: system/execve 地址直接在符号表里,
/bin/sh 字符串在 .rodata. 输出 {system_addr, execve_addr, binsh_addr, symbols}
供 exploit 模板直接生成固定地址利用 (No PIE 下地址固定).
"""

from intelpwn.core.analysis import register_analyzer
from intelpwn.utils.binary import open_elf

# 高危 libc 符号 (静态链接时这些地址直接可用)
_LIBC_SYMS = ("system", "execve", "execl", "execlp", "execvp",
              "mprotect", "mmap", "read", "write", "puts", "printf", "gets",
              "strcpy", "strcat", "sprintf", "scanf", "system@plt", "execve@plt")


@register_analyzer("static_libc")
def static_libc_analysis(path, results):
    """静态链接: 提取 libc 内置符号地址 (system/execve/binsh 等).

    非静态链接 → 返回空 (动态链接走 PLT/GOT 路径, 无需此能力包).
    """
    if not results.get("protections", {}).get("static"):
        return {}
    syms = {}
    binsh_addr = None
    try:
        with open_elf(path) as elf:
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym.name in _LIBC_SYMS:
                        syms.setdefault(sym.name, sym['st_value'])
            # /bin/sh 字符串 (仅匹配 NUL 结尾的完整字符串, 避免 b"sh" 误报代码字节)
            for sec_name in ('.rodata', '.data'):
                sec = elf.get_section_by_name(sec_name)
                if not sec:
                    continue
                idx = sec.data().find(b"/bin/sh\x00")
                if idx >= 0:
                    binsh_addr = sec['sh_addr'] + idx
                    break
    except Exception:
        return {}
    if not syms and binsh_addr is None:
        return {}
    return {
        "system_addr": hex(syms.get("system") or syms.get("execve") or 0),
        "execve_addr": hex(syms.get("execve") or 0),
        "binsh_addr": hex(binsh_addr) if binsh_addr else "0x0",
        "symbols": {k: hex(v) for k, v in sorted(syms.items())},
    }