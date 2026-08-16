"""专业 CTF 报告输出 — 中文 + 全量信息 (适配英文键名)"""
import os

from intelpwn.utils.output import Colors, print_info, print_success, print_warning


SEV = {
    '严重': f"{Colors.RED}[严重]{Colors.END}",
    '高危': f"{Colors.RED}[高危]{Colors.END}",
    '中危': f"{Colors.YELLOW}[中危]{Colors.END}",
    '低危': f"{Colors.GREEN}[低危]{Colors.END}",
    '信息': f"{Colors.CYAN}[信息]{Colors.END}",
}


def _sev_tag(level: str) -> str:
    return SEV.get(level, SEV['信息'])


# report.py 已硬编码渲染的 results key — 兜底区块跳过这些
_RENDERED_KEYS = {
    "angr_check", "bss_writable", "cross_validation", "file", "format_string",
    "got", "has_binsh", "heap_analysis", "high_risk_strings", "libc", "overflow",
    "path", "plt", "protections", "rop", "segment_permissions", "summary",
    "win_targets", "_shared",
}


def _fmt_value(v, indent="  │     "):
    """插件输出通用格式化: dict → 键值对, list → 项, 标量 → 直显"""
    if isinstance(v, dict):
        lines = []
        for k, val in v.items():
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{indent}{k}:")
                lines.append(_fmt_value(val, indent + "    "))
            else:
                lines.append(f"{indent}{k}: {val}")
        return "\n".join(lines) or f"{indent}(空)"
    if isinstance(v, list):
        if not v:
            return f"{indent}(空)"
        return "\n".join(f"{indent}- {_fmt_value(i, indent + '  ')}" for i in v)
    return f"{indent}{v}"


def _print_extra_analyzers(results: dict):
    """通配 CLI: 显示所有未硬编码渲染的 results key (内置扩展 + 未来插件)"""
    extra = {k: v for k, v in results.items()
             if k not in _RENDERED_KEYS and v not in (None, {}, [], "", False)}
    if not extra:
        return
    print(f"  │")
    print(f"  ├─ 扩展分析输出 ─────────────────────────────")
    for k in sorted(extra):
        v = extra[k]
        if k == "menu" and isinstance(v, dict):
            if v.get("present"):
                print(f"  │  {SEV['信息']} 菜单交互: 选项 {v.get('trigger')} → {v.get('target_func')}"
                      f" (锚点: {v.get('anchor') or '无'})")
                for opt, info in (v.get("options") or {}).items():
                    params = ",".join(info.get("params") or [])
                    print(f"  │     [{opt}] {info.get('handler')}"
                          + (f" 输入: {params}" if params else ""))
            else:
                print(f"  │  {SEV['信息']} 菜单交互: 未检测到 (无 scanf 数字菜单)")
        elif k == "static_libc" and isinstance(v, dict) and v.get("system_addr"):
            print(f"  │  {SEV['高危']} 静态链接 libc: system={v.get('system_addr')} "
                  f"execve={v.get('execve_addr')} binsh={v.get('binsh_addr')}")
        elif isinstance(v, dict) and "error" in v:
            print(f"  │  {SEV['中危']} {k}: 分析异常 ({v['error']})")
        else:
            print(f"  │  {SEV['信息']} {k}:")
            print(_fmt_value(v))


def print_results(results: dict, binary: str):
    """输出完整分析结果 (兼容英文键名)"""
    basename = os.path.basename(binary)
    prot = results.get("protections", {})
    plt = results.get("plt", {})
    so_list = results.get("overflow", [])
    fs = results.get("format_string", {})
    rop = results.get("rop", {})
    bss = results.get("bss_writable", [])
    has_binsh = results.get("has_binsh", False)
    libc = results.get("libc", "")
    summary = results.get("summary", {})
    findings = summary.get("items", [])

    arch = prot.get("arch", "?")
    bits = prot.get("bits", "?")
    canary = prot.get("canary", False)   # True = 有保护
    nx = prot.get("nx", False)
    pie = prot.get("pie", False)
    relro = prot.get("relro", "?")
    rwx = prot.get("rwx_segment", False)
    text_size = prot.get("text_size", 0)

    # ═══════════════════════════════════════════════
    # 1. 目标基本信息
    # ═══════════════════════════════════════════════
    arch_name = "x86" if "86" in str(arch) else str(arch)
    print(f"")
    print(f"  {SEV['信息']} 目标: {basename}  ({arch_name} {bits}bit)")
    print(f"  {SEV['信息']} 路径: {os.path.abspath(binary)}")
    print(f"  {SEV['信息']} .text 段大小: {text_size} bytes")

    # ═══════════════════════════════════════════════
    # 2. 高优先级风险汇总
    # ═══════════════════════════════════════════════
    print(f"")
    print(f"  ┌─ 高优先级风险 ────────────────────────────")
    if so_list:
        so = so_list[0]
        print(f"  │  {SEV['严重']} 栈溢出: {so.get('function','?')}, padding={so.get('calculated_padding','?')} 字节")
    if fs.get('vulnerable'):
        print(f"  │  {SEV['高危']} 格式化字符串: 可泄露内存 + 覆写 GOT")
    if not canary:
        print(f"  │  {SEV['高危']} 无栈 Canary: 可直接覆盖返回地址")
    seg = results.get("segment_permissions", {})
    if seg.get("executable_stack"):
        print(f"  │  {SEV['高危']} 栈可执行(RWX): 可直接注入 shellcode (W^X 违规)")
    if seg.get("got_writable") and so_list:
        print(f"  │  {SEV['中危']} GOT 可写: 可通过 ROP 覆写 GOT 表")
    if has_binsh:
        print(f"  │  {SEV['信息']} /bin/sh 存在于二进制中 → 可直接用于 ret2system")
    for wt in results.get("win_targets", []):
        print(f"  │  {SEV['高危']} 命令执行目标 @ {wt.get('address')}: "
              f"{wt.get('call')} 参数={wt.get('string')!r}")
    hr_strings = results.get("high_risk_strings", [])
    for s in hr_strings:
        if s.get('string') in ('/bin/sh', '/sh'):
            continue
        print(f"  │  {SEV['信息']} 发现高危字符串 \"{s['string']}\" ({s['count']}处)")
    print(f"  └────────────────────────────────────────────")

    # ═══════════════════════════════════════════════
    # 3. 保护状态 (详细)
    # ═══════════════════════════════════════════════
    print(f"")
    print(f"  ┌─ 安全保护 ───────────────────────────────")
    if not canary:
        print(f"  │  {SEV['高危']} 栈保护 (Canary)   关闭 → 可直接覆盖返回地址")
    else:
        print(f"  │  {SEV['低危']} 栈保护 (Canary)   开启 → 需要先泄露 canary")
    if nx:
        print(f"  │  {SEV['低危']} NX (栈不可执行)   开启 → 需要构造 ROP 链")
    else:
        print(f"  │  {SEV['高危']} NX (栈不可执行)   关闭 → 可直接执行 shellcode")
    if not pie:
        print(f"  │  {SEV['低危']} PIE (地址随机化)   关闭 → 地址固定, 可直接使用")
    else:
        print(f"  │  {SEV['中危']} PIE (地址随机化)   开启 → 需要泄露代码基址")
    if 'none' in str(relro).lower():
        print(f"  │  {SEV['中危']} RELRO              无 → GOT 表可写, 可覆写")
    elif 'partial' in str(relro).lower():
        print(f"  │  {SEV['低危']} RELRO              部分 → .got.plt 可写")
    else:
        print(f"  │  {SEV['低危']} RELRO              完全 → GOT 不可写")
    if rwx:
        print(f"  │  {SEV['高危']} RWX 段             存在 → 可直接注入 shellcode")
    # 静态链接
    if prot.get("static", False):
        print(f"  │  {SEV['中危']} 静态链接            是 → ROP gadgets 丰富")
    # CET (影子栈 / 间接分支保护) — x64/x86 通用
    if prot.get("shstk", False):
        print(f"  │  {SEV['高危']} CET 影子栈 (SHSTK)  开启 → 传统 ROP/SROP 被硬件阻断, 自动利用不可行")
    if prot.get("ibt", False):
        print(f"  │  {SEV['中危']} CET 间接分支 (IBT)  开启 → 间接 call/jmp 目标受限")

    # ═══════════════════════════════════════════════
    # 3. PLT 函数 (详细)
    # ═══════════════════════════════════════════════
    if plt:
        print(f"  │")
        print(f"  │  ┌─ PLT 函数 ───────────────────────")
        for name, addr in plt.items():
            if '.c' in name or name.startswith('_'):
                continue
            if name == "system":
                print(f"  │  │  {SEV['高危']} {name} @ {addr}  →  命令执行, 可直接 ret2system")
            elif name == "execve":
                print(f"  │  │  {SEV['高危']} {name} @ {addr}  →  命令执行")
            elif name in ("gets", "read", "scanf", "fgets"):
                print(f"  │  │  {SEV['高危']} {name} @ {addr}  →  输入函数, 可能造成栈溢出")
            elif name in ("printf", "sprintf", "fprintf", "snprintf"):
                print(f"  │  │  {SEV['中危']} {name} @ {addr}  →  格式化输出, 可能存在格式化字符串漏洞")
            elif name in ("write", "puts", "send"):
                print(f"  │  │  {SEV['信息']} {name} @ {addr}  →  输出函数, 可用于信息泄露")
            else:
                print(f"  │  │  {SEV['信息']} {name} @ {addr}")
        print(f"  │  └──────────────────────────────────")

    # ═══════════════════════════════════════════════
    # 4. 栈溢出分析 (最详细)
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  ├─ 栈缓冲区溢出 ─────────────────────────────")
    if not so_list:
        print(f"  │  {SEV['低危']} 未检测到明显的栈溢出漏洞")
    else:
        so = so_list[0]
        func = so.get('function', '?')
        addr = so.get('address', '?')
        stack_sz = so.get('stack_size', 0)
        padding = so.get('calculated_padding', '?')
        lea_insn = so.get('lea_insn', '?')
        danger_call = so.get('dangerous_call', '?')

        print(f"  │  {SEV['严重']} 发现栈溢出漏洞!")
        print(f"  │    漏洞函数:   {func} ({addr})")
        print(f"  │    危险调用:   {danger_call}")
        print(f"  │    栈帧大小:   {stack_sz} bytes")
        print(f"  │    LEA 指令:   {lea_insn}")
        print(f"  │    ┌─ Padding 计算 ───────────────────")
        print(f"  │    │  静态分析 (capstone):  {Colors.GREEN}{padding} bytes{Colors.END}")
        print(f"  │    │  反汇编证据:  lea rax, [rbp - 0x{stack_sz:x}] → 栈帧 {stack_sz}")
        print(f"  │    │              saved rbp ({'8' if bits==64 else '4'}) = {padding}")
        print(f"  │    └──────────────────────────────────")
        print(f"  │")
        print(f"  │    ┌─ 利用可行性 ─────────────────────")
        if not canary:
            print(f"  │    │  {Colors.GREEN}[+] Canary 关闭: 可直接覆盖返回地址{Colors.END}")
        else:
            print(f"  │    │  {Colors.YELLOW}[-] Canary 开启: 需先通过信息泄露获取 canary 值{Colors.END}")
        if not nx:
            print(f"  │    │  {Colors.GREEN}[+] NX 关闭: 可直接在栈上执行 shellcode{Colors.END}")
        else:
            print(f"  │    │  {Colors.YELLOW}[-] NX 开启: 需构造 ROP 链绕过{Colors.END}")
        if not pie:
            print(f"  │    │  {Colors.GREEN}[+] PIE 关闭: 代码地址固定, 可直接使用 ROP gadgets{Colors.END}")
        else:
            print(f"  │    │  {Colors.YELLOW}[-] PIE 开启: 需先泄露代码段基址{Colors.END}")

        # 利用策略推荐
        print(f"  │    │")
        has_system = 'system' in plt
        has_rop_rdi = rop.get('pop_rdi') and rop.get('pop_rdi') != "未找到"
        has_rop_ret = rop.get('ret') and rop.get('ret') != "未找到"

        strat = []
        if not canary and not pie and has_system and has_binsh:
            strat.append(f"  │    │     → ret2system: pad={padding} + pop_rdi + binsh_addr + ret + system")
        elif not canary and not pie and has_rop_rdi:
            strat.append(f"  │    │     → ret2libc: pad={padding} + puts@plt + main → leak libc → ret2system")
        if not nx:
            strat.append(f"  │    │     → shellcode: pad={padding} + jmp_rsp + shellcode")
        if rop.get('pop_eax') and rop.get('int_0x80'):
            strat.append(f"  │    │     → execve syscall: pad={padding} + pop_eax + 59 + pop_rdi + binsh + int_0x80")
        if not strat:
            strat.append(f"  │    │     → 基础 ret2win: pad={padding} + win_addr")
        for s in strat:
            print(s)
        print(f"  │    └──────────────────────────────────")

    # ═══════════════════════════════════════════════
    # 5. 格式化字符串
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  ├─ 格式化字符串 ─────────────────────────────")
    if not fs.get('vulnerable'):
        print(f"  │  {SEV['低危']} 未检测到格式化字符串漏洞")
    else:
        ev = fs.get('evidence', [])
        leak_count = sum(1 for e in ev if '泄漏' in e)
        crash_count = sum(1 for e in ev if '崩毁' in e or 'crash' in e.lower())
        offset = fs.get('best_offset')
        print(f"  │  {SEV['高危']} 发现格式化字符串漏洞!")
        print(f"  │    {SEV['信息']} 检测到 {leak_count} 个泄露点" + (f", {crash_count} 个崩毁点" if crash_count else ""))
        if offset:
            print(f"  │    {SEV['信息']} 最佳偏移: {offset} (可直接用 %{offset}$p 泄露)")
        print(f"  │")
        print(f"  │    ┌─ 利用步骤 ───────────────────────")
        print(f"  │    │  1. 发送 %p 或 %x 确定偏移")
        print(f"  │    │  2. 用 %{offset or 'N'}$p 泄露栈上感兴趣的值")
        print(f"  │    │     - libc 地址 → 计算 libc 基址")
        print(f"  │    │     - canary 值 → 绕过栈保护")
        print(f"  │    │     - 返回地址 → 确定代码基址 (PIE)")
        print(f"  │    │  3. 用 %{offset or 'N'}$n + 目标地址 覆写 GOT 表")
        print(f"  │    └──────────────────────────────────")

    # ═══════════════════════════════════════════════
    # 6. GOT 表 + 栈布局
    # ═══════════════════════════════════════════════
    got = results.get("got", {})
    if got:
        print(f"  │")
        print(f"  ├─ GOT 表 ────────────────────────────────")
        for name, addr in got.items():
            leak_type = {'puts': 'LEAK', 'write': 'LEAK', 'printf': 'FMT', 'read': 'BOF', 'gets': 'BOF'}.get(name, '')
            print(f"  │  {SEV['信息']} {name} @ {addr}" + (f" [{leak_type}]" if leak_type else ""))

    # 栈布局 (仅当有栈溢出时)
    if so_list:
        so = so_list[0]
        stack_sz = so.get('stack_size', 0)
        pad = so.get('calculated_padding', 0)
        bits_val = 8 if '64' in str(bits) else 4
        align = pad - stack_sz - bits_val
        print(f"  │")
        print(f"  ├─ 栈布局 ────────────────────────────────")
        print(f"  │  {SEV['信息']} [{Colors.BOLD}bof( {stack_sz} ){Colors.END}]" +
              (f" + [对齐({align})]" if align > 0 else "") +
              f" + [saved_rbp({bits_val})] + [ret_addr]")
        print(f"  │  {SEV['信息']} {'^--填充起始'}{' ' * (stack_sz + max(align, 0) + 8)}^--填充结束 = pad={pad}")

    # ═══════════════════════════════════════════════
    # 7. ROP Gadgets (全量)
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  ├─ ROP Gadgets ──────────────────────────────")
    has_rop = any(v and v != "未找到" and not isinstance(v, (int, list))
                  for v in rop.values())
    if not has_rop:
        print(f"  │  {SEV['中危']} 未找到关键 ROP gadgets")
    else:
        KNOWN_GADGETS = {'pop_rdi', 'pop_rsi', 'pop_rdx', 'ret', 'pop_eax', 'int_0x80'}
        gadgets_found = []
        for gname, gaddr in rop.items():
            if gname in KNOWN_GADGETS and gaddr and gaddr != "未找到" and not isinstance(gaddr, (int, list)):
                gadgets_found.append((gname, gaddr))
                if gname == 'pop_rdi':
                    print(f"  │  {SEV['信息']} pop rdi; ret  @ {gaddr}  ← ret2libc 必备")
                elif gname == 'pop_rsi':
                    print(f"  │  {SEV['信息']} pop rsi; ret  @ {gaddr}  ← 设置第二个参数")
                elif gname == 'ret':
                    print(f"  │  {SEV['信息']} ret           @ {gaddr}  ← 栈对齐, 绕过 movaps")
                elif gname == 'pop_rdx':
                    print(f"  │  {SEV['信息']} pop rdx; ret  @ {gaddr}  ← 设置第三个参数")
                elif gname == 'pop_eax':
                    print(f"  │  {SEV['信息']} pop eax; ret  @ {gaddr}  ← syscall 编号")
                elif gname == 'int_0x80':
                    print(f"  │  {SEV['信息']} int 0x80      @ {gaddr}  ← 系统调用")
                else:
                    print(f"  │  {SEV['信息']} {gname}         @ {gaddr}")
        print(f"  │  {SEV['信息']} 共 {len(gadgets_found)} 个可用 gadgets")

    # ═══════════════════════════════════════════════
    # 7. BSS 可写区
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  ├─ BSS / 可写内存 ──────────────────────────")
    if bss:
        for s in bss:
            print(f"  │  {SEV['信息']} {s.get('name', '?')} @ {s.get('addr', 0)}, size={s.get('size', 0)}")
    else:
        print(f"  │  {SEV['信息']} 未发现明显的大块 BSS 符号")

    # ═══════════════════════════════════════════════
    # 8. 关键资源
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  ├─ 关键资源 ────────────────────────────────")
    if has_binsh:
        print(f"  │  {SEV['信息']} /bin/sh 字符串存在于二进制中 → 可直接用于 ret2system")
    else:
        print(f"  │  {SEV['信息']} /bin/sh 不存在于二进制中 → 需要从 libc 中寻找")
    if libc and libc != "未检测到":
        print(f"  │  {SEV['信息']} libc 路径: {libc}")
        try:
            from pwn import ELF
            l = ELF(libc, checksec=False)
            print(f"  │  {SEV['信息']} libc system: {hex(l.symbols.get('system', 0))}")
            print(f"  │  {SEV['信息']} libc  /bin/sh: {hex(next(l.search(b'/bin/sh'), 0))}")
            print(f"  │  {SEV['信息']} libc  execve:  {hex(l.symbols.get('execve', 0))}")
            print(f"  │  {SEV['信息']} libc  puts:    {hex(l.symbols.get('puts', 0))}")
            print(f"  │  {SEV['信息']} libc  read:    {hex(l.symbols.get('read', 0))}")
            print(f"  │  {SEV['信息']} libc  write:   {hex(l.symbols.get('write', 0))}")
        except Exception:
            pass

    # ═══════════════════════════════════════════════
    # 9. 堆分析
    # ═══════════════════════════════════════════════
    heap = results.get("heap_analysis", {})
    if heap and isinstance(heap, dict) and heap.get('has_heap'):
        print(f"  │")
        print(f"  ├─ 堆分析 ─────────────────────────────────")
        for f in heap.get('functions', []):
            print(f"  │  {SEV['中危']} 堆函数: {f}")
        print(f"  │  {SEV['信息']} 函数数量: {heap.get('function_count', 0)}, 圈复杂度: {heap.get('complexity', 0)}")
        if heap.get('complexity', 0) > 30:
            print(f"  │  {SEV['中危']} 代码复杂度较高, 可能存在堆漏洞")
        for clue in heap.get('clues', []):
            print(f"  │  {_sev_tag(clue.get('severity', '中危'))} {clue.get('detail', '')}")

    # ═══════════════════════════════════════════════
    # 9.5 angr 符号执行
    # ═══════════════════════════════════════════════
    angr_res = results.get("angr_check", {})
    if angr_res:
        print(f"  │")
        print(f"  ├─ 符号执行 (angr) ────────────────────────")
        if not angr_res.get("available"):
            print(f"  │  {SEV['信息']} angr 未安装, 已跳过 (可选: pip install angr)")
        else:
            for ch in angr_res.get("checks", []):
                fn = ch.get("function", "?")
                reach = ch.get("reachability", {})
                if reach.get("reachable"):
                    print(f"  │  {SEV['信息']} {fn}: 溢出调用点可达")
                    sc = ch.get("size_check", {})
                    if sc.get("status") == "concrete":
                        tag = SEV['高危'] if sc.get("dangerous") else SEV['低危']
                        print(f"  │  {tag} {fn}: 大小参数确定 = {sc.get('size')}, "
                              + ("超过栈缓冲" if sc.get("dangerous") else "未超过栈缓冲"))
                    elif sc.get("status") == "symbolic":
                        tag = SEV['高危'] if sc.get("dangerous") else SEV['中危']
                        print(f"  │  {tag} {fn}: 大小参数为符号值, 最大可能 = {sc.get('max_possible')}, "
                              + ("可能超过栈缓冲" if sc.get("dangerous") else "受限"))
                elif reach.get("reachable") is False:
                    print(f"  │  {SEV['中危']} {fn}: 调用点不可达 (疑似死代码), 静态报告可能误报")
                else:
                    print(f"  │  {SEV['信息']} {fn}: 可达性未知 ({reach.get('reason', '')})")
            for io_f in angr_res.get("int_overflow", []):
                print(f"  │  {SEV['中危']} 整数溢出线索: {io_f.get('detail', '')}")
            for d in angr_res.get("discovered", []):
                if d.get("status") == "truncated":
                    print(f"  │  {SEV['信息']} [angr 探索截断] {d.get('callee')} @ {d.get('call_addr')}: "
                          f"{d.get('reason', '符号执行截断, 无法确认')}")
                    continue
                tag = SEV['高危']
                miss = "" if d.get("static_detected") else " (静态漏检)"
                pad = f", padding~{d['padding']}" if 'padding' in d else ""
                kind = "无界写" if d.get("vuln") == "unbounded_write" else "可控大小读"
                print(f"  │  {tag} [angr 主动发现] {d['callee']} @ {d['call_addr']}: "
                      f"{kind} 目标在栈上{pad}{miss}")
            for pc in angr_res.get("padding_crosscheck", []):
                print(f"  │  {SEV['中危']} padding 不一致: {pc.get('function')} "
                      f"静态={pc.get('static_padding')} vs angr={pc.get('angr_padding')}")

    # ═══════════════════════════════════════════════
    # 9.6 交叉验证 (静态 vs 动态)
    # ═══════════════════════════════════════════════
    cross = results.get("cross_validation")
    if cross:
        print(f"  │")
        print(f"  ├─ 交叉验证 (静态 vs 动态) ─────────────────")
        STATE_TAG = {
            "确认": f"{Colors.GREEN}[确认]{Colors.END}",
            "冲突": f"{Colors.RED}[冲突]{Colors.END}",
            "未复现": f"{Colors.YELLOW}[未复现]{Colors.END}",
            "动态发现": f"{Colors.RED}[动态发现]{Colors.END}",
            "崩溃未关联": f"{Colors.RED}[崩溃未关联]{Colors.END}",
            "canary": f"{Colors.YELLOW}[canary拦截]{Colors.END}",
            "跳过": f"{Colors.CYAN}[跳过]{Colors.END}",
        }
        for e in cross.get("entries", []):
            tag = STATE_TAG.get(e.get("state"), f"{SEV['信息']}")
            note = e.get("note") or ""
            print(f"  │  {tag} {e.get('item')}: 静态={e.get('static')} 动态={e.get('dynamic')}"
                  + (f" ({note})" if note else ""))
        print(f"  │  结论: {cross.get('verdict')}")

    # ═══════════════════════════════════════════════
    # 9.7 扩展分析输出 (通配 CLI — 插件/未硬编码 key 全显示)
    # ═══════════════════════════════════════════════
    _print_extra_analyzers(results)

    # ═══════════════════════════════════════════════
    # 10. 综合发现
    # ═══════════════════════════════════════════════
    print(f"  │")
    print(f"  └─ 漏洞总结 ────────────────────────────────")
    if not findings:
        print(f"     {SEV['低危']} 未发现可利用漏洞")
    else:
        for f in findings:
            sev = f.get("severity", "信息")
            vtype = f.get("type", "")
            detail = f.get("detail", "") or f.get("padding", "")
            usable = f.get("exploitable", False)
            print(f"     {_sev_tag(sev)} {vtype} | {detail}" +
                  (f" {Colors.GREEN}[EXPLOITABLE]{Colors.END}" if usable else ""))

    # ═══════════════════════════════════════════════
    # 11. 修复建议
    # ═══════════════════════════════════════════════
    print(f"")
    print(f"  ┌─ 修复建议 ────────────────────────────────")
    fixes = []
    if so_list:
        fixes.append("使用 fgets/read 时严格校验输入长度, 避免缓冲区溢出")
        fixes.append("编译时启用栈保护: -fstack-protector-strong (Canary)")
    if fs.get('vulnerable'):
        fixes.append("使用 printf(\"%s\", str) 替代 printf(str) 防止格式化字符串攻击")
        fixes.append("编译时启用 -Wformat-security 检查格式化字符串误用")
    if not canary:
        fixes.append("添加 Canary 保护: gcc -fstack-protector-strong")
    if nx:
        fixes.append("如需使用 ROP: 收集足够的 gadgets (pop rdi, pop rsi, ret)")
    if not fixes:
        fixes.append("当前配置无明显漏洞, 保持良好编码习惯即可")
    for f in fixes:
        print(f"  │  {SEV['信息']} {f}")
    print(f"  └────────────────────────────────────────────")
    print(f"")


def print_json_summary(results: dict) -> str:
    """输出 JSON 格式摘要"""
    import json

    def _safe(v):
        if isinstance(v, (bytes, bytearray)):
            return v.decode(errors='replace')
        return v

    summary = {
        "schema_version": "2.0",
        "file": results.get("file"),
        "path": results.get("path"),
        "protections": {
            "canary": results.get("protections", {}).get("canary"),
            "nx": results.get("protections", {}).get("nx"),
            "pie": results.get("protections", {}).get("pie"),
            "relro": results.get("protections", {}).get("relro"),
        },
        "overflow": [
            {
                "function": o.get("function"),
                "padding": o.get("calculated_padding"),
                "address": o.get("address"),
            }
            for o in results.get("overflow", [])
        ],
        "format_string": {
            "vulnerable": results.get("format_string", {}).get("vulnerable"),
            "offset": results.get("format_string", {}).get("best_offset"),
        },
        "summary": {
            "count": results.get("summary", {}).get("count", 0),
            "max_severity": results.get("summary", {}).get("max_severity"),
            "findings": [
                {
                    "type": f.get("type"),
                    "detail": f.get("detail"),
                    "severity": f.get("severity"),
                    "exploitable": f.get("exploitable"),
                }
                for f in results.get("summary", {}).get("items", [])
            ],
        },
        "cross_validation": {
            "verdict": results.get("cross_validation", {}).get("verdict"),
            "entries": [
                {
                    "item": e.get("item"),
                    "static": e.get("static"),
                    "dynamic": e.get("dynamic"),
                    "state": e.get("state"),
                    "note": e.get("note"),
                }
                for e in results.get("cross_validation", {}).get("entries", [])
            ],
        },
    }
    return json.dumps(summary, ensure_ascii=False, indent=2)
