"""分析引导的定点验证器 — 基于 analyze 结果做针对性验证 (原 fuzzer)。

名称说明: 本模块不是覆盖率引导的 fuzz 器, 而是对已分析出的漏洞做
确定性验证: cyclic 精确偏移提取 + 边界值测试 + 格式化字符串偏移定位。
"""

import re
import subprocess
import tempfile
import os
from typing import Optional

from pwn import cyclic, cyclic_find, p64, p32
from intelpwn.utils.binary import run
from intelpwn.utils.output import print_info, print_success, print_warning, Colors, print_error


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


def cyclic_crash_offset(binary: str, bits: int = 64, pattern_len: int = 0x400) -> dict:
    """cyclic 崩溃实验: 自动提取精确溢出偏移。

    研究结论 (实证):
      - 主流崩溃模式是 saved rbp 被覆盖后 epilogue 走坏 rbp,
        gdb 的 rip 显示 ret 指令本身 → cyclic_find(rip) 恒失败;
        但崩溃时 $rsp 正指向返回地址槽, 里面的 cyclic 字节能被精确命中。
      - canary 靶子: SIGABRT + "stack smashing detected" + rip 在 libc → canary_hit。
    提取顺序: $rsp 指向值 → $rip → canary 指纹 → 未命中。

    Returns:
        {crash, signal, canary_hit, cyclic_offset, rip}
    """
    n = 8 if bits == 64 else 4
    pat = cyclic(pattern_len, n=n)
    cf = tempfile.NamedTemporaryFile(delete=False)
    cf.write(pat)
    cf.close()

    gs = f"""set pagination off
file {binary}
run < {cf.name}
set $rspval = *(unsigned long long*)$rsp
printf "CRASH-MARK RIP=%#llx RSPVAL=%#llx RBP=%#llx\\n", $rip, $rspval, $rbp
quit"""
    sf = tempfile.NamedTemporaryFile(mode="w", delete=False)
    sf.write(gs)
    sp = sf.name
    sf.close()

    try:
        rc, out, _ = run(["gdb", "-batch", "-x", sp], timeout=15)
    finally:
        os.unlink(cf.name)
        os.unlink(sp)

    crash = rc is not None and rc < 0 or "CRASH-MARK" in out
    sig = None
    m = re.search(r'Program received signal (\S+)', out)
    if m:
        sig = m.group(1)
    smashing = "stack smashing detected" in out

    rip = rspval = 0
    m = re.search(r'CRASH-MARK RIP=(0x[0-9a-f]+) RSPVAL=(0x[0-9a-f]+) RBP=(0x[0-9a-f]+)', out)
    if m:
        rip, rspval, _ = (int(x, 16) for x in m.groups())

    canary_hit = smashing or sig == "SIGABRT" or (0x7f0000000000 <= rip < 0x800000000000)

    offset = None
    pack = p64 if bits == 64 else p32
    if rspval:
        off = cyclic_find(pack(rspval), n=n)
        if off is not None and off >= 0:
            offset = off
    if offset is None and rip:
        off = cyclic_find(pack(rip), n=n)
        if off is not None and off >= 0:
            offset = off

    return {"crash": crash, "signal": sig, "canary_hit": bool(canary_hit),
            "cyclic_offset": offset, "rip": rip}


def verify_dynamic(binary: str, results: dict) -> dict:
    """动态验证 (不重复 analyze_all, 直接消费已计算的 results)

    Returns:
        {overflow_crash, fmtstr_offset, boundary_crash}
    """
    bits = results.get("protections", {}).get("bits", 64)
    out = {"overflow_crash": None, "fmtstr_offset": None, "boundary_crash": None}

    # 1. 栈溢出: cyclic 精确偏移提取
    so_list = results.get("overflow", [])
    if so_list:
        func = so_list[0].get("function", "?")
        print_info(f"cyclic 验证栈溢出 (函数={func})...")
        out["overflow_crash"] = cyclic_crash_offset(binary, bits)
        c = out["overflow_crash"]
        if c.get("cyclic_offset") is not None:
            print_success(f"  动态偏移: {c['cyclic_offset']}")
        elif c.get("canary_hit"):
            print_warning("  canary 拦截 (stack smashing), 需先泄露 canary")
        elif c.get("crash"):
            print_warning(f"  崩溃 ({c.get('signal')}) 但未提取到偏移")
        else:
            print_warning("  未崩溃")

    # 2. 格式化字符串偏移定位
    fs = results.get("format_string", {})
    if fs.get("vulnerable"):
        print_info("定位格式化字符串偏移...")
        out["fmtstr_offset"] = fmtstr_offset_find(binary)

    # 3. 边界值测试 (针对 read/gets)
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
                    out["boundary_crash"] = {"size": sz, "signal": -r.returncode}
                    print_warning(f"  size={sz} → SIG{-r.returncode}")
                    break
            except Exception:
                pass

    return out
