"""汇编自动注释引擎 — 三级注释 (对新人友好, 漏洞上下文优先)

red    (漏洞链): 来自分析结论直接映射, 可信度高
yellow(风险):   规则猜测, 条件性风险提示 (明说"若…则危险")
gray  (语义):   通用汇编模式, 提升可读性

用法:
    from intelpwn.core.analysis.comments import annotate_disasm
    lines = annotate_disasm(lines, overflow_entry, sym_map)
"""

import re

# x86_64 常用 syscall 号 → 名称
SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 5: "fstat",
    9: "mmap", 10: "mprotect", 14: "rt_sigprocmask", 39: "getpid",
    59: "execve", 60: "exit", 62: "kill", 231: "exit_group", 322: "execveat",
}

# 装入 eax/rax 即黄的"危险 syscall"号 (exec 类 / 内存权限类)
DANGER_SYSCALLS = {9: "mmap", 10: "mprotect", 59: "execve", 322: "execveat"}

# call 命中即黄的敏感函数子串
SENSITIVE_CALL_SUBSTR = ("system", "exec", "strcpy", "strcat", "gets",
                         "sprintf", "scanf", "mprotect", "shell")

# 危险调用的缓冲寄存器 (按函数): read/recv → rsi, 其余 → rdi
BUF_REG = {"read": "rsi", "recv": "rsi", "fgets": "rdi", "gets": "rdi",
           "strcpy": "rdi", "strcat": "rdi", "sprintf": "rdi", "scanf": "rdi",
           "memcpy": "rdi", "strncpy": "rdi", "snprintf": "rdi"}
# 危险调用的大小参数寄存器
SIZE_REG = {"read": "rdx", "recv": "rdx", "fgets": "rsi", "snprintf": "rsi",
            "memcpy": "rdx", "strncpy": "rdx"}


def _imm_value(op_str):
    """提取第一个立即数 (0x.. 或十进制), 无则 None"""
    if not op_str:
        return None
    for tok in op_str.replace(",", " ").split():
        t = tok.strip().lower()
        if t.startswith("0x"):
            try:
                return int(t, 16)
            except ValueError:
                continue
        if t.isdigit():
            try:
                return int(t, 10)
            except ValueError:
                continue
    return None


def _buf_ref(op_str):
    """从 lea 操作数提取栈缓冲引用: Capstone x86 Intel 输出带空格如 [rbp - 0x20] → ('rbp', 0x20); 无则 None"""
    op_str = op_str or ""
    m = re.search(r'\[(r?bp|r?sp)\s*([+-])\s*0x([0-9a-f]+)\]', op_str, re.I)
    if not m:
        return None
    try:
        val = int(m.group(3), 16)
        return m.group(1).lower(), (-val if m.group(2) == '-' else val)
    except ValueError:
        return None


def _call_target_addr(op_str):
    """call/jmp 操作数 → 直接目标地址 (int) 或 None. 间接调用 (含 []) 返回 None"""
    op_str = op_str or ""
    if "[" in op_str:
        return None  # 间接调用 (call qword ptr [rip+...]), 目标地址不可静态解析
    m = re.search(r'0x([0-9a-f]+)', op_str, re.I)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def _reg_prefixed(ops, reg):
    """ops 是否以 reg 或同族 32 位寄存器开头 (rdx/edx, rsi/esi...)"""
    ops = (ops or "").lower()
    if ops.startswith(reg):
        return True
    w32 = {"rdx": "edx", "rsi": "esi", "rdi": "edi", "rax": "eax", "rcx": "ecx"}
    return w32.get(reg) is not None and ops.startswith(w32[reg])


def _is_last_ret(idx, ins):
    """该 ret 是否为函数内最后一个 ret (尾声返回)"""
    for i in range(idx + 1, len(ins)):
        if ins[i]["mnemonic"] == "ret":
            return False
    return True


def _find_call_idx(ins, call_site):
    """定位危险调用所在行索引"""
    for idx, i in enumerate(ins):
        if i["addr"] == call_site and i["mnemonic"] == "call":
            return idx
    return None


def annotate_disasm(lines, entry=None, sym_map=None):
    """为反汇编行添加注释 (原地追加 note/note_level 字段).

    lines:   [{addr, mnemonic, op_str, ...}]
    entry:   overflow 条目 (或 None) — 提供 call_site/calculated_padding/stack_size/function
    sym_map: {addr: 符号名} (用于 call 解析)
    返回:    新列表, 每行含 note(str|None) / note_level(red|yellow|gray|None)
    """
    sym_map = sym_map or {}
    ins = list(lines)

    # ── 上下文: 漏洞条目 ──
    call_site = padding = stack_size = func_name = None
    if entry:
        raw = entry.get("call_site")
        if raw:
            try:
                call_site = int(raw, 16)
            except (ValueError, TypeError):
                call_site = None
        try:
            padding = int(entry.get("calculated_padding") or 0) or None
        except (ValueError, TypeError):
            padding = None
        try:
            stack_size = int(entry.get("stack_size") or 0) or None
        except (ValueError, TypeError):
            stack_size = None
        func_name = entry.get("function") or None

    # 危险调用行 → 缓冲装载 / 大小装载指令索引 (向前 8 条内)
    buf_load_idx = size_load_idx = None
    call_idx = _find_call_idx(ins, call_site) if call_site else None
    if call_idx is not None:
        # call 操作数是目标地址, 需经 sym_map 解析为函数名再匹配寄存器约定
        tgt = _call_target_addr(ins[call_idx]["op_str"])
        name = (sym_map.get(tgt) if tgt is not None else None) or ""
        buf_reg = size_reg = None
        for fname, breg in BUF_REG.items():
            if fname in name.lower():
                buf_reg = breg
                size_reg = SIZE_REG.get(fname)
                break
        for j in range(call_idx - 1, max(-1, call_idx - 9), -1):
            m, ops = ins[j]["mnemonic"], ins[j]["op_str"]
            if buf_reg and buf_load_idx is None and m == "lea":
                ref = _buf_ref(ops)
                # 目标寄存器必须是危险调用的缓冲寄存器 (如 read → rsi)
                if ref and (ref[0] in ("rbp", "ebp", "rsp", "esp")) and _reg_prefixed(ops, buf_reg):
                    buf_load_idx = j
            if size_reg and size_load_idx is None and m in ("mov", "movl"):
                if _reg_prefixed(ops, size_reg):
                    if _imm_value(ops) is not None:
                        size_load_idx = j

    out = []
    for idx, i in enumerate(ins):
        note, level = None, None
        mnem, ops, addr = i["mnemonic"], i["op_str"], i["addr"]

        # ── 🔴 漏洞链 (分析结论) ──
        if call_site and addr == call_site and mnem == "call":
            buf = f"栈缓冲 {stack_size:#x}" if stack_size else "栈缓冲"
            pad = f" padding={padding}" if padding else ""
            note = f"★ 危险输入点 {func_name or '?'} — {buf}{pad}"
            level = "red"
        elif buf_load_idx == idx:
            ref = _buf_ref(ops)
            if ref:
                size = abs(ref[1])
                sign = '-' if ref[1] < 0 else '+'
                note = f"缓冲 {size:#x} @ {ref[0]}{sign}{abs(ref[1]):#x} (危险调用目标)"
                level = "red"
        elif size_load_idx == idx:
            v = _imm_value(ops)
            if v is not None:
                if stack_size and v > stack_size:
                    note = f"大小 {v:#x}={v} > 缓冲 {stack_size:#x} → 可溢出 {v - stack_size}B"
                    level = "red"
                else:
                    note = f"读取大小 {v:#x}={v}"
                    level = "gray"
        elif mnem == "ret" and call_site and _is_last_ret(idx, ins):
            note = f"← 返回地址可被溢出改写 (padding={padding})"
            level = "red"

        # ── 🟡 风险提示 (规则猜测) ──
        elif mnem == "mov" and level is None:
            v = _imm_value(ops)
            op_low = ops.lower()
            dest = op_low.split(",")[0].strip() if "," in op_low else op_low
            if "fs:[0x28]" in op_low or "fs:0x28" in op_low:
                note = "⚠ 加载 canary (栈保护开启)"
                level = "yellow"
            elif v in DANGER_SYSCALLS and dest in ("eax", "rax"):
                note = f"⚠ 常量 0x{v:x} = syscall {DANGER_SYSCALLS[v]} 号? (规则猜测)"
                level = "yellow"
            elif v in SYSCALLS and v != 0 and dest in ("eax", "rax"):
                note = f"syscall 号 {v:#x} = {SYSCALLS[v]}"
                level = "gray"
        elif mnem == "syscall" and level is None:
            note = "⚠ 发起系统调用 (若 rax=execve 则可得 shell)"
            level = "yellow"
        elif mnem == "call" and level is None:
            tgt = _call_target_addr(ops)
            name = sym_map.get(tgt) if tgt is not None else None
            if name and any(s in name.lower() for s in SENSITIVE_CALL_SUBSTR):
                note = f"⚠ {name}() 调用 — 若参数可控则危险"
                level = "yellow"

        # ── ⚪ 语义标注 ──
        if level is None:
            if idx == 0 and mnem == "push" and "rbp" in ops:
                note, level = "保存帧指针 (函数序言)", "gray"
            elif mnem == "mov" and ops.lower() == "rbp, rsp":
                note, level = "建立栈帧", "gray"
            elif mnem in ("sub", "add") and ops.lower().startswith("rsp"):
                v = _imm_value(ops)
                if v is not None:
                    act = "分配" if mnem == "sub" else "回收"
                    note, level = f"{act}栈空间 {v} ({v:#x})", "gray"
            elif mnem == "xor" and "," in ops:
                a, b = [x.strip() for x in ops.split(",")[:2]]
                if a == b:
                    note, level = "清零 (常用作返回 0)", "gray"
            elif mnem == "endbr64":
                note, level = "CET 边界指令 (无实际作用)", "gray"
            elif mnem == "leave":
                note, level = "恢复栈帧", "gray"
            elif mnem in ("movzx", "movsxd"):
                note, level = ("零扩展" if mnem == "movzx" else "符号扩展"), "gray"
            elif mnem == "call":
                tgt = _call_target_addr(ops)
                name = sym_map.get(tgt) if tgt is not None else None
                if name:
                    disp = name[:-4] if name.endswith("@plt") else name  # 避免 @plt@plt
                    note, level = f"call {disp}", "gray"
            elif mnem == "jmp":
                tgt = _call_target_addr(ops)
                name = sym_map.get(tgt) if tgt is not None else None
                if name:
                    disp = name[:-4] if name.endswith("@plt") else name
                    note, level = f"→ 跳转 {disp}", "gray"

        out.append({**i, "note": note, "note_level": level})
    return out
