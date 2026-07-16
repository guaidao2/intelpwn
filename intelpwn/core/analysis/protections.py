"""保护状态分析"""

import os
from intelpwn.utils.binary import parse_checksec, readelf_arch, readelf_sections, has_rwx_segment, is_static_binary


def analyze_protections(path: str) -> dict:
    """checksec 解析 + 安全评级。返回英文键名。"""
    sec = parse_checksec(path)
    arch = readelf_arch(path) or "unknown"
    bits = 64 if arch == "x64" else (32 if arch == "x86" else 0)
    rwx = has_rwx_segment(path)
    static = is_static_binary(path)
    sections = dict(readelf_sections(path))
    text_sz = sections.get(".text", 0)

    risks = []
    if not sec["canary"]:
        risks.append("栈溢出高危(无Canary)")
    if sec["rwx"]:
        risks.append("RWX段存在")
    if sec["relro"] == "none":
        risks.append("无RELRO")

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
        "risks": risks,
        "risk_level": sev,
    }
