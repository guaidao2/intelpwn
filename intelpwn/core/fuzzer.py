"""分析引导的定点 Fuzzer — 基于 analyze 结果做针对性测试。"""

import subprocess
import tempfile
import os
from typing import Optional

from pwn import cyclic, cyclic_find, p64, p32
from intelpwn.utils.output import print_info, print_success, print_warning, Colors, print_error
from intelpwn.core.analysis import analyze_all


def fmtstr_offset_find(binary: str, max_probe: int = 40) -> Optional[int]:
    """定位格式化字符串偏移: 发送 AAAA + 逐位 %x 找 0x41414141"""
    for n in range(1, max_probe + 1):
        payload = f"AAAA%{n}$x".encode()
        try:
            r = subprocess.run([binary], input=payload, capture_output=True, timeout=3)
            out = r.stdout.decode(errors='replace')
            if '41414141' in out:
                print_success(f"格式化字符串偏移: {n} (payload: AAAA%{n}$x → {out.strip()[:40]})")
                return n
        except (subprocess.TimeoutExpired, OSError):
            pass
    return None


def fuzz_by_analysis(binary: str, libc_path: str = None) -> tuple:
    """基于分析结果进行定点 Fuzz
    
    Returns:
        (findings, results) — findings 为人类可读列表, results 为分析 dict
    """
    print_info("运行全量分析以获取目标信息...")
    results = analyze_all(binary, libc_path)

    findings = []
    arch = results.get("protections", {}).get("arch", "x64")
    bits = results.get("protections", {}).get("bits", 64)

    # ── 1. 栈溢出验证 ──
    so_list = results.get("overflow", [])
    if so_list:
        so = so_list[0]
        padding = so.get("calculated_padding", 0)
        func = so.get("function", "?")
        print_info(f"验证栈溢出 (padding={padding}, 函数={func})...")

        test_payload = b"A" * padding + b"BBBBBBBB"
        try:
            r = subprocess.run([binary], input=test_payload + b"\n",
                               capture_output=True, timeout=3)
            if r.returncode < 0:
                sig = -r.returncode

                crash_file = tempfile.NamedTemporaryFile(delete=False)
                crash_path = crash_file.name
                crash_file.write(test_payload)
                crash_file.close()

                gdb_script = f"""set pagination off
file {binary}
run < {crash_path}
info registers rip rsp
quit"""
                sf = tempfile.NamedTemporaryFile(mode="w", delete=False)
                sf.write(gdb_script)
                spath = sf.name
                sf.close()

                rc, out, _ = subprocess.run(["gdb", "-batch", "-x", spath],
                                            capture_output=True, text=True, timeout=10)
                os.unlink(crash_path)
                os.unlink(spath)

                rip_val = 0
                for line in out.splitlines():
                    p = line.strip().split()
                    if p and p[0] in ('rip', 'eip') and len(p) >= 2:
                        try:
                            rip_val = int(p[1], 16)
                        except ValueError:
                            pass

                findings.append({
                    "类型": "栈溢出验证",
                    "严重度": "严重",
                    "详情": f"padding={padding}, 函数={func}, RIP={'0x%x' % rip_val if rip_val else '已控制'} (signal={sig})"
                })
                print_success(f"  RIP 被控制: 0x{rip_val:x}" if rip_val else f"  signal={sig}, 崩毁确认")
            else:
                print_warning(f"  padding={padding} 未造成崩毁")
        except OSError:
            print_error(f"  无法执行 {binary}")

    # ── 2. 格式化字符串偏移定位 ──
    fs = results.get("format_string", {})
    if fs.get("vulnerable"):
        print_info("定位格式化字符串偏移...")
        off = fmtstr_offset_find(binary)
        if off:
            findings.append({
                "类型": "格式化字符串偏移",
                "严重度": "高危",
                "详情": f"偏移={off}, 可用 %{off}$p 泄露, %{off}$n 写入"
            })
        else:
            findings.append({
                "类型": "格式化字符串确认",
                "严重度": "中危",
                "详情": "存在漏洞但未自动定位偏移, 可手动尝试更多偏移值"
            })

    # ── 3. 边界值测试 (针对 read/gets) ──
    plt = results.get("plt", {})
    danger_inputs = [n for n, a in plt.items() if n in ('read', 'gets', 'scanf', 'fgets')]
    if danger_inputs:
        print_info(f"边界值测试 (针对: {', '.join(danger_inputs)})...")
        for sz in [64, 128, 256, 512, 1024]:
            payload = b"A" * sz
            try:
                r = subprocess.run([binary], input=payload + b"\n",
                                   capture_output=True, timeout=2)
                if r.returncode < 0:
                    findings.append({
                        "类型": "边界崩毁",
                        "严重度": "高危",
                        "详情": f"size={sz} 触发 signal={-r.returncode}"
                    })
                    print_warning(f"  size={sz} → SIG{-r.returncode}")
                    break
            except Exception:
                pass

    return findings, results
