"""PLT 危险函数扫描"""

from pwn import ELF


def analyze_plt(path: str) -> dict:
    """扫描 PLT 函数表，返回 {名称: 地址十六进制}"""
    try:
        elf = ELF(path, checksec=False)
    except Exception:
        return {}
    return {name: hex(addr) for name, addr in elf.plt.items() if name and addr}


def analyze_got(path: str) -> dict:
    """扫描 GOT 表，返回 {名称: 地址十六进制}"""
    try:
        elf = ELF(path, checksec=False)
        return {n: hex(a) for n, a in elf.got.items() if n and a}
    except Exception:
        return {}
