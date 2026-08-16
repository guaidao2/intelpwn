"""格式化字符串检测 (静态上下文分析 + 黑盒验证)"""

import os
import re
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from elftools.elf.elffile import ELFFile

from intelpwn.utils.binary import open_elf


def _fmtstr_static_context(path: str, insns=None, bits=None) -> dict:
    """通过反汇编检查 printf 的调用方式。返回英文键。

    Args:
        path: 二进制路径
        insns: 可选预反汇编指令列表
        bits: 可选预检测位数
    """
    # 获取 printf/sprintf 的 PLT 地址
    try:
        from pwn import ELF
        elf = ELF(path, checksec=False)
        printf_addr = elf.plt.get('printf', 0) or elf.plt.get('sprintf', 0)
        if not printf_addr:
            return {"dangerous": False, "detail": "无printf/sprintf"}
    except Exception:
        return {"dangerous": False, "detail": "pwntools解析失败"}

    # 如果未提供预反汇编，自己反汇编
    if insns is None or bits is None:
        try:
            with open_elf(path) as elf2:
                text = elf2.get_section_by_name('.text')
                if not text:
                    return {"dangerous": False, "detail": "无.text段"}
                data = text.data()
                base = text['sh_addr']
                e_machine = elf2.header.e_machine
        except Exception:
            return {"dangerous": False, "detail": "ELF解析失败"}

        cs_mode = CS_MODE_64 if 'X86_64' in str(e_machine) else CS_MODE_32
        md = Cs(CS_ARCH_X86, cs_mode)
        md.detail = True
        insns = list(md.disasm(data, base))
        bits = 64 if cs_mode == CS_MODE_64 else 32

    for i, insn in enumerate(insns):
        if insn.mnemonic == 'call':
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue
            if target == printf_addr:
                fmt_source = "unknown"
                for j in range(max(0, i - 15), i):
                    prev = insns[j]
                    if bits == 64:
                        if prev.mnemonic == 'lea' and 'rdi' in prev.op_str and 'rip' in prev.op_str:
                            fmt_source = "字符串常量(安全)"
                            break
                        if prev.mnemonic == 'lea' and 'rdi' in prev.op_str and ('rbp' in prev.op_str or 'rsp' in prev.op_str):
                            fmt_source = "栈缓冲区(危险)"
                        if prev.mnemonic == 'mov' and ('rdi,' in prev.op_str or 'rdi ' in prev.op_str):
                            parts = prev.op_str.split(',')
                            src = parts[1].strip() if len(parts) > 1 else ""
                            for k in range(max(0, j - 8), j):
                                prev2 = insns[k]
                                if prev2.mnemonic == 'lea' and src in prev2.op_str and ('rbp' in prev2.op_str or 'rsp' in prev2.op_str):
                                    fmt_source = "栈缓冲区(危险)"
                                    break
                                if prev2.mnemonic == 'lea' and src in prev2.op_str and 'rip' in prev2.op_str:
                                    fmt_source = "字符串常量(安全)"
                                    break
                    else:
                        fmt_source = "待验证"
                if fmt_source == "栈缓冲区(危险)":
                    return {"dangerous": True, "detail": f"printf调用栈缓冲区 (call 0x{printf_addr:x})", "call_style": "buffer"}
                elif fmt_source == "unknown":
                    return {"dangerous": "maybe", "detail": f"printf调用地址(0x{printf_addr:x}), 无法静态确定参数来源", "call_style": "unknown"}

    return {"dangerous": False, "detail": "printf参数均为字符串常量", "call_style": "safe"}


def _run_payload(path: str, payload: str, tag: str, timeout: float = 3) -> dict:
    """执行单个 payload 并返回分析结果"""
    result = {"tag": tag, "leaks": [], "crashed": False, "timed_out": False, "stdout": ""}
    try:
        r = subprocess.run(
            [path],
            input=payload.encode(errors='replace') + b"\n",
            capture_output=True,
            timeout=timeout,
        )
        result["stdout"] = r.stdout.decode(errors='replace')
        hex_addrs = re.findall(r'0x[0-9a-fA-F]{6,14}', result["stdout"])
        if hex_addrs:
            result["leaks"] = hex_addrs[:3]
        if r.returncode < 0:
            result["crashed"] = True
            result["signal"] = -r.returncode
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
    except OSError:
        result["timed_out"] = True
    return result


def detect_format_string(path: str, insns=None, bits=None) -> dict:
    """黑盒检测格式化字符串 + 自动定位偏移。返回英文键。

    优化：将 8 次串行 subprocess 合并为 4 批，减少等待时间。
    黑盒超时按二进制大小自适应: 静态链接大二进制 (1MB+) 启动慢,
    固定 3s 会随机失败 (探测结果不稳定)。

    Args:
        path: 二进制路径
        insns: 可选预反汇编指令列表（避免重复反汇编）
        bits: 可选预检测位数
    """
    try:
        probe_timeout = 3.0 if os.path.getsize(path) < 300_000 else 8.0
    except OSError:
        probe_timeout = 3.0
    ctx = _fmtstr_static_context(path, insns=insns, bits=bits)

    # 无 printf 族 → 不可能存在格式化字符串漏洞 (黑盒回显会误判, 如堆题菜单回显)
    try:
        from .plt import analyze_plt
        _plt = analyze_plt(path)
        _PRINTF_FAMILY = ('printf', 'sprintf', 'snprintf', 'fprintf', 'vsprintf',
                          'vprintf', '__printf_chk', 'dprintf', 'asprintf')
        if _plt and not any(p in _plt for p in _PRINTF_FAMILY):
            return {
                "vulnerable": False,
                "evidence": ["无 printf 族调用, 排除格式化字符串漏洞"],
                "evidence_detail": "PLT 无 printf/sprintf/fprintf/vsprintf 等",
                "best_offset": None,
                "risk": "低危",
            }
    except Exception:
        pass

    # 静态分析确认安全 → 直接跳过黑盒
    if ctx.get("dangerous") is False and ctx.get("call_style") == "safe":
        return {
            "vulnerable": False,
            "evidence": ["printf参数均为字符串常量, 无格式化字符串漏洞"],
            "evidence_detail": ctx["detail"],
            "best_offset": None,
            "risk": "低危",
        }

    evidence = []
    vulnerable = False
    best_offset = None

    if ctx.get("dangerous") is True:
        evidence.append(f"[静态分析] 确认危险: {ctx['detail']}")
        vulnerable = True

    # ── 批次 1: 泄漏检测 + 偏移定位（合并 %x/%p/%s + AAAA 链）──
    leak_payload = "AAAA%p|%x|" + "%x" * 16  # 覆盖泄漏 + 偏移
    r1 = _run_payload(path, leak_payload, "泄漏+偏移探测", timeout=probe_timeout)
    if r1["timed_out"]:
        evidence.append("[泄漏探测] 超时")
        vulnerable = True
    else:
        if r1["leaks"]:
            evidence.append(f"[泄漏探测] 发现泄漏: {r1['leaks'][:2]}")
            vulnerable = True
        if r1["crashed"]:
            evidence.append(f"[泄漏探测] 进程崩毁 (signal={r1.get('signal','?')})")
            vulnerable = True
        # 从合并输出中解析 AAAA 偏移
        out = r1["stdout"]
        offsets = re.findall(r'(0x41414141)', out)
        if offsets:
            output_parts = out.split('0x')
            for idx, part in enumerate(output_parts):
                if '41414141' in part:
                    best_offset = idx
                    break

    # ── 批次 2: 直接参数访问 ──
    direct_payload = "%1$p|%2$p|%3$p|%4$p|%5$p|%10$p|%20$p|%30$p|%40$p"
    r2 = _run_payload(path, direct_payload, "直接参数访问", timeout=probe_timeout)
    if r2["timed_out"]:
        evidence.append("[直接参数] 超时")
    else:
        if r2["leaks"]:
            evidence.append(f"[直接参数] 发现泄漏: {r2['leaks'][:2]}")
            vulnerable = True
        if r2["crashed"]:
            evidence.append(f"[直接参数] 进程崩毁 (signal={r2.get('signal','?')})")

    # ── 批次 3: 危险模式 %s/%n（可能崩毁）──
    danger_payload = "%s%s%s|%n%n%n|%hhn%hhn"
    r3 = _run_payload(path, danger_payload, "危险模式(%s/%n)", timeout=probe_timeout)
    if r3["timed_out"]:
        evidence.append("[危险模式] 超时")
        vulnerable = True
    else:
        if r3["crashed"]:
            evidence.append(f"[危险模式] 进程崩毁 — 可写入/读取任意地址")
            vulnerable = True
        if r3["leaks"]:
            evidence.append(f"[危险模式] 发现泄漏: {r3['leaks'][:2]}")
            vulnerable = True

    # ── 批次 4: 宽度溢出（单独，可能 hang）──
    r4 = _run_payload(path, "%99999999s", "宽度溢出", timeout=2)
    if r4["timed_out"]:
        evidence.append("[宽度溢出] 进程卡死 — 可能触发宽字符处理")
        vulnerable = True
    elif r4["crashed"]:
        evidence.append(f"[宽度溢出] 进程崩毁 (signal={r4.get('signal','?')})")
        vulnerable = True
    elif r4["leaks"]:
        evidence.append(f"[宽度溢出] 发现泄漏: {r4['leaks'][:2]}")

    risk = "高危" if best_offset else ("中危" if vulnerable else "低危")
    if ctx.get("dangerous") == "maybe" and not vulnerable:
        vulnerable = False
        risk = "低危"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "evidence_detail": '\n'.join(evidence) if evidence else "",
        "best_offset": best_offset,
        "risk": risk,
        "call_style": ctx.get("call_style", "unknown"),
    }
