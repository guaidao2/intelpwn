"""保护状态分析 — checksec + CET (SHSTK/IBT) 属性解析, x64/x86 通用"""

import os
import struct

from intelpwn.utils.binary import parse_checksec, readelf_arch, readelf_sections, has_rwx_segment, is_static_binary


# GNU_PROPERTY_X86_FEATURE_1: bit0=IBT, bit1=SHSTK
GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 1 << 0
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 1 << 1

# x86-64 与 x86 (32 位) 共用同一 property 类型编号
FEATURE_1_TYPES = (GNU_PROPERTY_X86_FEATURE_1_AND,)


def _parse_property_data(data: bytes) -> dict:
    """解析 .note.gnu.property 段数据 → {ibt, shstk}.

    遍历 notes: namesz(4) + descsz(4) + type(4) + name + pad + desc + pad.
    GNU_PROPERTY_X86_FEATURE_1_AND (0xc0000002) 条目按 bit0(IBT)/bit1(SHSTK) 判定.
    """
    result = {"ibt": False, "shstk": False}
    off = 0
    n = len(data)
    while off + 12 <= n:
        namesz, descsz, ntype = struct.unpack_from('<III', data, off)
        p = off + 12 + namesz
        p = (p + 3) & ~3  # name 4 字节对齐
        d_end = min(p + descsz, n)
        if ntype == 0x05:  # NT_GNU_PROPERTY_TYPE_0 (GNU note type = 5, 非 4)
            q = p
            while q + 8 <= d_end:
                pr_type, pr_datasz = struct.unpack_from('<II', data, q)
                if pr_type in FEATURE_1_TYPES and pr_datasz == 4 and q + 12 <= d_end:
                    feature = struct.unpack_from('<I', data, q + 8)[0]
                    result["ibt"] = bool(feature & GNU_PROPERTY_X86_FEATURE_1_IBT)
                    result["shstk"] = bool(feature & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
                    return result
                q += 8 + ((pr_datasz + 3) & ~3)  # 属性数据 4 字节对齐
        # 下一条 note (desc 4 字节对齐)
        off = (d_end + 3) & ~3
    return result


def cet_properties(path: str) -> dict:
    """解析 .note.gnu.property 段 → {ibt: bool, shstk: bool} (x64/x86 通用).

    读 ELF 的 .note.gnu.property 里 GNU_PROPERTY_X86_FEATURE_1_AND 条目,
    按 bit0 (IBT) / bit1 (SHSTK) 判定. 无该段或未启用 → False.
    """
    try:
        from intelpwn.utils.binary import open_elf
        with open_elf(path) as elf:
            sec = elf.get_section_by_name('.note.gnu.property')
            if sec is None:
                return {"ibt": False, "shstk": False}
            return _parse_property_data(sec.data())
    except Exception:
        return {"ibt": False, "shstk": False}


def analyze_protections(path: str) -> dict:
    """checksec 解析 + CET (SHSTK/IBT) + 安全评级。返回英文键名。"""
    sec = parse_checksec(path)
    arch = readelf_arch(path) or "unknown"
    bits = 64 if arch == "x64" else (32 if arch == "x86" else 0)
    rwx = has_rwx_segment(path)
    static = is_static_binary(path)
    sections = dict(readelf_sections(path))
    text_sz = sections.get(".text", 0)
    cet = cet_properties(path)

    risks = []
    if not sec["canary"]:
        risks.append("栈溢出高危(无Canary)")
    if sec["rwx"]:
        risks.append("RWX段存在")
    if sec["relro"] == "none":
        risks.append("无RELRO")
    # CET 是防御而非缺陷, 不进 risks (避免被 findings 标成"保护缺失 EXPLOITABLE");
    # 状态由 shstk/ibt 字段 + report 区块单独展示

    sev = "高危" if any("高危" in r for r in risks) else \
           "中危" if risks else "低危"

    return {
        "arch": arch,
        "bits": bits,
        "canary": sec.get("canary", False),  # True=有Canary
        "nx": sec.get("nx", False),
        "pie": sec.get("pie", False),
        "relro": sec.get("relro", "none"),
        "rwx_segment": rwx,
        "static": static,
        "text_size": text_sz,
        "shstk": cet["shstk"],   # CET 影子栈 (x86-64/x86)
        "ibt": cet["ibt"],       # CET 间接分支保护
        "cet": cet["shstk"] or cet["ibt"],
        "risks": risks,
        "risk_level": sev,
    }
