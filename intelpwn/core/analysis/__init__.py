"""分析模块包 — analyzer.py 的模块化拆分。"""

import os

from intelpwn.utils.output import print_info, print_success

from .protections import analyze_protections
from .plt import analyze_plt, analyze_got
from .overflow import analyze_assembly_overflow, verify_padding, disassemble_text
from .fmtstr import detect_format_string
from .rop import analyze_rop
from .bss import analyze_bss
from .cfg import analyze_cfg
from .heap import detect_heap
from .findings import (
    generate_findings,
    generate_strategy,
    scan_high_risk_strings,
    analyze_segments,
    detect_libc,
    check_binsh,
)

__all__ = [
    "analyze_all",
    "analyze_protections",
    "analyze_plt",
    "analyze_assembly_overflow",
    "verify_padding",
    "detect_format_string",
    "analyze_rop",
    "analyze_bss",
    "analyze_cfg",
    "detect_heap",
    "generate_findings",
    "generate_strategy",
]


def analyze_all(path: str, libc_path: str = None) -> dict:
    """全量分析入口

    Args:
        path: 二进制路径
        libc_path: 指定 libc 路径 (若不指定则自动检测)

    Returns:
        包含英文键名的分析结果 dict
    """
    print_info("开始全量分析...")

    result = {"file": os.path.basename(path), "path": os.path.abspath(path)}

    print_info("分析二进制保护...")
    result["protections"] = analyze_protections(path)

    print_info("扫描PLT危险函数...")
    result["plt"] = analyze_plt(path)

    # 预反汇编 .text — 供 overflow/fmtstr 共享，避免重复扫描
    pre_disasm = disassemble_text(path)
    if pre_disasm:
        shared_insns, shared_bits, _, _ = pre_disasm
    else:
        shared_insns, shared_bits = None, None

    print_info("反汇编分析栈溢出...")
    asm_results = analyze_assembly_overflow(path, insns=shared_insns, bits=shared_bits)
    result["overflow"] = asm_results

    print_info("检测格式化字符串...")
    result["format_string"] = detect_format_string(path, insns=shared_insns, bits=shared_bits)

    result["got"] = analyze_got(path)

    print_info("扫描ROP gadgets...")
    result["rop"] = analyze_rop(path, result["plt"], insns=shared_insns, bits=shared_bits)

    print_info("扫描BSS符号...")
    result["bss_writable"] = analyze_bss(path)

    print_info("计算CFG复杂度指标...")
    result["cfg"] = analyze_cfg(path)

    result["heap_analysis"] = detect_heap(path)

    result["high_risk_strings"] = scan_high_risk_strings(path)

    result["segment_permissions"] = analyze_segments(path)

    # 三重 padding 验证
    if asm_results:
        static_pad = asm_results[0].get("calculated_padding", 0)
        print_info(f"三重验证 padding (静态={static_pad})...")
        result["padding_verify"] = verify_padding(path, static_pad)
    else:
        result["padding_verify"] = {"final": None, "confidence": "无"}

    padding = result["padding_verify"]["final"] or 0
    print_info("生成利用策略...")
    result["strategy"] = generate_strategy(
        result["protections"],
        result["plt"],
        result["rop"],
        padding,
    )

    # libc
    if libc_path and os.path.exists(libc_path):
        result["libc"] = libc_path
    else:
        result["libc"] = detect_libc(path)

    result["has_binsh"] = check_binsh(path)

    print_info("生成综合漏洞评估...")
    result["summary"] = generate_findings(result)

    print_success("分析完成!")
    return result
