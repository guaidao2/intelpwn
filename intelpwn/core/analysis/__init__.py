"""分析模块包 — analyzer.py 的模块化拆分。

提供插件注册机制: 新分析器可通过 register_analyzer 自注册,
analyze_all 会在内置流程之后自动执行所有已注册的扩展分析器,
结果写入 result[<name>]。内置分析器仍走显式管线 (有依赖关系)。
"""

import logging
import os

from pwn import ELF
from intelpwn.utils.binary import open_elf
from intelpwn.utils.output import print_info, print_success

from .protections import analyze_protections
from .plt import analyze_plt, analyze_got
from .overflow import analyze_assembly_overflow, verify_padding, disassemble_text
from .fmtstr import detect_format_string
from .rop import analyze_rop
from .bss import analyze_bss
from .cfg import analyze_cfg
from .heap import detect_heap
from .win_targets import scan_win_targets
from .findings import (
    generate_findings,
    generate_strategy,
    scan_high_risk_strings,
    analyze_segments,
    detect_libc,
    check_binsh,
)

# ── 插件注册表 ─────────────────────────────────────────────────────
_EXTRA_ANALYZERS = {}  # name -> callable(path, results_so_far) -> dict


def register_analyzer(name: str):
    """注册扩展分析器 (装饰器)。

    用法:
        @register_analyzer("angr_check")
        def angr_check(path, results):
            ...
    """
    def deco(fn):
        _EXTRA_ANALYZERS[name] = fn
        return fn
    return deco


def list_analyzers() -> list:
    """返回所有扩展分析器名称 (调试/报告用)"""
    return sorted(_EXTRA_ANALYZERS)


def run_extra_analyzers(path: str, results: dict) -> dict:
    """执行所有已注册的扩展分析器, 结果写入 results[name]"""
    for name, fn in _EXTRA_ANALYZERS.items():
        try:
            results[name] = fn(path, results)
        except Exception as e:
            results[name] = {"error": f"{type(e).__name__}: {e}"}
    return results


# 可选插件模块: 必须在注册表定义之后导入 (插件依赖 register_analyzer),
# 导入失败 (依赖缺失) 时自动跳过, 不影响内置分析
try:
    from . import angr_analysis  # noqa: F401 — 自注册 angr_check 插件
    from . import static_libc   # noqa: F401 — 自注册 static_libc 插件 (静态链接专项)
    from . import menu          # noqa: F401 — 自注册 menu 分析器 (菜单交互识别)
except Exception:
    pass


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
    "register_analyzer",
    "list_analyzers",
]


def _build_shared_blackboard(path: str, insns, bits):
    """黑板基础设施缓存: 一次性物化 func_bounds/sym_by_addr/plt_map, 供各分析器消费.

    避免 menu/callgraph/overflow 各自重复 open_elf + 符号表 + PLT 扫描 (大二进制
    静态链接可省 4-5 次重复解析)。
    """
    shared = {"insns": insns, "bits": bits, "func_bounds": [], "sym_by_addr": {}, "plt_map": {}}
    try:
        with open_elf(path) as elf:
            for sec_name in ('.symtab', '.dynsym'):
                sec = elf.get_section_by_name(sec_name)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                        shared["func_bounds"].append((sym['st_value'],
                                                      sym['st_value'] + sym['st_size'], sym.name))
                        shared["sym_by_addr"].setdefault(sym['st_value'], sym.name)
    except Exception as e:
        logging.getLogger("intelpwn").warning("黑板符号表物化失败 %s: %s", path, e)
    # PLT 槽 → 符号名: pyelftools 跨平台主方案 (pwntools ELF.plt 在 Windows 缺
    # pkg_resources 会静默空) + pwntools 兜底; 失败记 warning 不静默
    try:
        from .win_targets import _build_plt_map
        shared["plt_map"] = _build_plt_map(path, shared["bits"] or 64)
    except Exception as e:
        logging.getLogger("intelpwn").warning("黑板 PLT 物化失败 %s: %s", path, e)
    if not shared["plt_map"]:
        try:
            pwn_elf = ELF(path, checksec=False)
            shared["plt_map"] = {v: k for k, v in pwn_elf.plt.items()}
        except Exception as e:
            logging.getLogger("intelpwn").warning("黑板 PLT pwntools 兜底失败 %s: %s", path, e)
    if not shared["plt_map"]:
        # pwntools 的 Windows 失败是静默空 .plt (不抛异常) — 显式告警堵住静默
        logging.getLogger("intelpwn").warning(
            "黑板 PLT 物化为空 (pyelftools + pwntools 均未解析出槽位): %s — 下游将回退符号表", path)
    return shared


def analyze_all(path: str, libc_path: str = None, semantic_mode: str = "throttled") -> dict:
    """全量分析入口

    Args:
        path: 二进制路径
        libc_path: 指定 libc 路径 (若不指定则自动检测)
        semantic_mode: angr 语义兜底 — throttled(默认) / force(纯 angr)

    Returns:
        包含英文键名的分析结果 dict
    """
    # 每次 analyze 重置 angr 节流预算 (默认模式每二进制最多 _ANG_MAX_CALLS 次)
    try:
        from intelpwn.core.analysis.semantic_angr import reset_throttle
        reset_throttle()
    except Exception:
        pass
    print_info("开始全量分析...")

    result = {"file": os.path.basename(path), "path": os.path.abspath(path)}

    print_info("分析二进制保护...")
    result["protections"] = analyze_protections(path)

    print_info("扫描PLT危险函数...")
    result["plt"] = analyze_plt(path)

    # 预反汇编 .text + 物化共享黑板 (基础设施缓存, 各分析器消费避免重复扫描)
    pre_disasm = disassemble_text(path)
    if pre_disasm:
        shared_insns, shared_bits, _, _ = pre_disasm
    else:
        shared_insns, shared_bits = None, None
    _shared = _build_shared_blackboard(path, shared_insns, shared_bits)
    result["_shared"] = _shared

    print_info("反汇编分析栈溢出...")
    asm_results = analyze_assembly_overflow(path, insns=shared_insns, bits=shared_bits,
                                            func_bounds=_shared.get("func_bounds"),
                                            plt_map=_shared.get("plt_map"),
                                            semantic_mode=semantic_mode)
    result["overflow"] = asm_results

    print_info("检测格式化字符串...")
    result["format_string"] = detect_format_string(path, insns=shared_insns, bits=shared_bits)

    print_info("扫描命令执行目标 (ret2text)...")
    result["win_targets"] = scan_win_targets(path, insns=shared_insns, bits=shared_bits)

    result["got"] = analyze_got(path)

    print_info("扫描ROP gadgets...")
    result["rop"] = analyze_rop(path, result["plt"], insns=shared_insns, bits=shared_bits)

    print_info("扫描BSS符号...")
    result["bss_writable"] = analyze_bss(path)

    print_info("计算CFG复杂度指标...")
    result["cfg"] = analyze_cfg(path)

    result["heap_analysis"] = detect_heap(path, libc_path)

    # 跨函数 UAF 启发 (菜单/选项粒度: 哪个选项 free, 哪个选项 use — 语义层数组基址关联)
    # 仅堆题启用 (非堆二进制无 free, 全 .text 扫描白费)
    if (result.get("heap_analysis") or {}).get("has_heap"):
        try:
            from intelpwn.core.analysis.heap_uaf import detect_cross_function_uaf
            uaf = detect_cross_function_uaf(path, insns=shared_insns, bits=shared_bits,
                                            func_bounds=_shared.get("func_bounds"),
                                            plt_map=_shared.get("plt_map"))
            if uaf:
                for ch in uaf:
                    ch["type"] = "use_after_free"
                result["heap_analysis"]["uaf_chains"] = uaf
                result["heap_analysis"]["clues"].append(
                    {"type": "use_after_free", "detail": f"{len(uaf)} 条跨函数 UAF 链"})
        except Exception:
            pass

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

    # 扩展分析器 (插件钩子)
    extra = list_analyzers()
    if extra:
        print_info(f"执行扩展分析器: {', '.join(extra)}")
        run_extra_analyzers(path, result)

    # 跨函数 UAF 选项号标注 — menu 扩展分析器此时已跑, 补 handler 地址→选项映射
    try:
        uaf = (result.get("heap_analysis") or {}).get("uaf_chains")
        if uaf:
            menu_opts = (result.get("menu") or {}).get("options") or {}
            opt_ranges = []
            for no, info in menu_opts.items():
                try:
                    if info.get("address"):
                        start = int(info["address"], 16)
                        opt_ranges.append((start, start + 0x100, no))
                except (ValueError, TypeError):
                    pass
            def _opt_for(addr):
                a = int(addr, 16)
                for s, e, no in opt_ranges:
                    if s <= a < e:
                        return no
                return "?"
            for ch in uaf:
                ch["free_option"] = _opt_for(ch["free_addr"])
                ch["use_option"] = _opt_for(ch["use_addr"])
    except Exception:
        pass

    print_info("生成综合漏洞评估...")
    result["summary"] = generate_findings(result)

    print_success("分析完成!")
    return result
