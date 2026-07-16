"""BSS 可写符号扫描"""

from intelpwn.utils.binary import open_elf


def analyze_bss(path: str, min_size: int = 16) -> list:
    """扫描 BSS 区大符号 (用于 shellcode 存储)"""
    try:
        with open_elf(path) as elf:
            symtab = elf.get_section_by_name('.symtab')
            if not symtab:
                return []
            symbols = []
            for sym in symtab.iter_symbols():
                if sym['st_shndx'] in ('SHN_COMMON', 'SHN_ABS'):
                    continue
                if sym['st_info']['type'] == 'STT_OBJECT' and sym['st_size'] >= min_size:
                    symbols.append({
                        "name": sym.name,
                        "addr": hex(sym['st_value']) if sym['st_value'] else "0",
                        "size": sym['st_size'],
                    })
            return symbols
    except Exception:
        return []
