"""综合发现生成 + 利用策略推荐"""

import os
import re
from typing import Optional

from intelpwn.utils.binary import strings_has_binsh, run
from .protections import analyze_protections
from .plt import analyze_plt


def generate_findings(result: dict) -> dict:
    """综合所有检测结果生成漏洞总结。返回英文键。"""
    findings = []
    severity = "低危"

    # 栈溢出
    overflow_list = result.get("overflow", [])
    if overflow_list:
        for r in overflow_list:
            pad = r.get("calculated_padding", 0)
            findings.append({
                "type": "栈缓冲区溢出",
                "function": r["function"],
                "address": r["address"],
                "padding": f"{pad} 字节",
                "severity": "高危",
                "exploitable": pad <= 256,
            })
        severity = "高危"

    # 格式化字符串
    fs = result.get("format_string", {})
    if fs.get("vulnerable"):
        findings.append({
            "type": "格式化字符串漏洞",
            "evidence_count": len(fs.get("evidence", [])),
            "offset": str(fs.get("best_offset", "未确定")),
            "severity": "高危" if fs.get("best_offset") is not None else "中危",
            "exploitable": fs.get("best_offset") is not None,
        })
        if severity != "高危":
            severity = "高危"

    # 保护缺陷
    prot = result.get("protections", {})
    for risk in prot.get("risks", []):
        findings.append({
            "type": "保护缺失",
            "detail": risk,
            "severity": "高危" if "高危" in risk else "中危",
            "exploitable": True,
        })

    # 堆
    heap = result.get("heap_analysis", {})
    if heap.get("heap_function_list"):
        findings.append({
            "type": "堆函数使用",
            "detail": f"检测到堆函数: {', '.join(heap['heap_function_list'])}",
            "severity": "中危",
            "exploitable": False,
        })
    for clue in heap.get("clues", []):
        findings.append({
            "type": f"堆线索: {clue.get('type', '')}",
            "detail": clue.get("detail", ""),
            "severity": clue.get("severity", "中危"),
            "exploitable": clue.get("type") == "double_free",
        })

    # ROP
    rop = result.get("rop", {})
    for chain in rop.get("chains", []):
        if chain.get("feasible"):
            findings.append({
                "type": f"ROP策略: {chain['type']}",
                "detail": chain['condition'],
                "severity": "信息",
                "exploitable": True,
            })

    # 整数溢出线索 (angr 静态扫描)
    angr_res = result.get("angr_check", {})
    for io_f in angr_res.get("int_overflow", []):
        findings.append({
            "type": "整数溢出 (大小参数算术运算)",
            "detail": io_f.get("detail", ""),
            "severity": io_f.get("severity", "中危"),
            "exploitable": False,
        })

    return {
        "count": len(findings),
        "max_severity": severity,
        "items": findings,
    }


def generate_strategy(prot: dict, plt: dict, rop: dict, padding: int) -> list:
    """基于保护状态、PLT 和 ROP 生成利用策略"""
    strategies = []
    canary = prot.get("canary", False)
    nx = prot.get("nx", False)
    pie = prot.get("pie", False)
    bits = prot.get("bits", 64)

    has_system = 'system' in plt
    has_execve = 'execve' in plt
    # ret2win
    if not pie and has_system and not canary:
        strategies.append({
            "type": "ret2system",
            "chain": f"padding={padding} → pop_rdi → /bin/sh → ret → system",
            "condition": "Canary关闭 + PIE关闭 + system存在",
        })

    # ret2libc
    if 'puts' in plt and not canary:
        strategies.append({
            "type": "ret2libc (leak → ret2system)",
            "chain": f"padding={padding} → puts(puts@got) → main → leak libc → ret2system",
            "condition": "Canary关闭 + puts存在 + libc可用",
        })

    # shellcode
    if not canary and not nx:
        strategies.append({
            "type": "shellcode注入",
            "chain": f"padding={padding} → jmp_rsp → shellcode",
            "condition": "NX关闭 + Canary关闭",
        })

    # execve syscall (x86)
    if rop.get('pop_eax') and rop.get('int_0x80') and not canary:
        strategies.append({
            "type": "execve syscall (int 0x80)",
            "chain": f"padding={padding} → pop_eax=59 → pop_ebx=/bin/sh → int_0x80",
            "condition": "x86 + int 0x80 gadget可用",
        })

    return strategies


def scan_high_risk_strings(path: str) -> list:
    """扫描高危字符串"""
    targets = [b'/bin/sh', b'/sh', b'cat ', b'flag', b'system', b'bash', b'/tmp', b'ncirc']
    found = []
    try:
        rc, out, _ = run(['strings', path], timeout=10)
        if rc == 0:
            for t in targets:
                count = out.count(t.decode())
                if count > 0:
                    found.append({"string": t.decode(), "count": count})
    except Exception:
        pass
    return found


def analyze_segments(path: str) -> dict:
    """分析段权限"""
    result = {"executable_stack": False, "got_writable": False, "wx_violation": False}
    try:
        rc, out, _ = run(['readelf', '-l', path], timeout=10)
        if rc == 0:
            in_stack = False
            for line in out.splitlines():
                if 'GNU_STACK' in line:
                    in_stack = True
                elif in_stack and line.strip():
                    if 'RWE' in line:
                        result["executable_stack"] = True
                    in_stack = False

        prot = analyze_protections(path)
        relro = prot.get('relro', '')
        result["got_writable"] = 'full' not in str(relro).lower()
        result["wx_violation"] = result["executable_stack"]
    except Exception:
        pass
    return result


def detect_libc(path: str) -> str:
    """检测 libc 路径"""
    rc, out, _ = run(["ldd", path])
    if rc != 0:
        return "未检测到"
    m = re.search(r'libc\.so[^\s]*\s+=>\s+(\S+)', out)
    return m.group(1) if m else "未检测到"


def check_binsh(path: str) -> bool:
    """检查二进制中是否包含 /bin/sh"""
    return strings_has_binsh(path)
