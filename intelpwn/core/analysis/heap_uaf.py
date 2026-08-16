"""跨函数堆 UAF 启发式检测 — 数组基址关联 (语义层复用).

核心思路: 不依赖符号/菜单精度, 全 .text 扫 free 调用 + use 调用 (puts/read/
write/memcpy/strlen 等), 各自回溯参数定义链求"全局数组基址" ([rip+X]);
同一数组基址既有 free 又有 use (不同函数) → UAF 链.

与语义层 v2 一致: 定义-使用链回溯, 破固定窗口, 编译器重排/长链不漏.
"""

import re
import logging

log = logging.getLogger("intelpwn")

# 使用类调用 (free 之外的操作对象函数) — 若参数来自已 free 数组 → UAF
_USE_CALLS = ('puts', 'printf', 'read', 'write', 'memcpy', 'strlen', 'strcmp',
              'strcpy', 'memset', 'fwrite', 'fread', 'send', 'recv')

_BACKTRACK = 60


def _reg_family(reg: str) -> str:
    """寄存器族归一: rax/eax/ax/al → rax"""
    r = reg.lower()
    for base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
        if r == base or r.startswith(base):
            return base
    return reg.lower()


def _rip_target(insn) -> int:
    """lea/mov 的 [rip±disp] 目标地址; 非 rip 相对 → None"""
    m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
    if not m:
        return None
    disp = int(m.group(2), 16)
    return insn.address + insn.size + (disp if m.group(1) == '+' else -disp)


def _array_base_of(insns, call_idx: int, arg_reg: str):
    """回溯 arg_reg 定义链 → 全局数组基址 (第一个 [rip+X] 组件) or None.

    队列式多候选: [a+b] 取元素时同时追 a 和 b (基址/索引位置因编译器而异);
    lea r,[r*8] 追源; mov r,r 传播. 遇 [rip+X] 即返回.
    """
    targets = {_reg_family(arg_reg)}
    for k in range(call_idx - 1, max(-1, call_idx - _BACKTRACK - 1), -1):
        insn = insns[k]
        m, ops = insn.mnemonic, insn.op_str
        if m in ('call', 'jmp', 'ret'):
            break
        if m in ('lea', 'mov'):
            t = _rip_target(insn)
            if t is not None:
                dst = ops.split(',')[0].strip()
                if _reg_family(dst) in targets:
                    return t  # 直接 rip 相对 → 全局对象基址
                continue
            parts = ops.split(',')
            if len(parts) != 2:
                continue
            dst, src = parts[0].strip(), parts[1].strip()
            if _reg_family(dst) not in targets:
                continue
            targets.discard(_reg_family(dst))
            if re.match(r'^[er]?[a-ds]?x?[0-9]*$', src):
                targets.add(_reg_family(src))  # mov 寄存器传播
            else:
                # 内存/索引形式: 提取其中所有寄存器加入候选
                for rm in re.finditer(r'(r\d+|[er][abcd]x|[er]si|[er]di)', src):
                    targets.add(_reg_family(rm.group(1)))
            if not targets:
                return None  # 无候选可追 → 非全局数组
        else:
            # 其他指令 (xor/pop/add 等) 写候选寄存器 → 值被覆写, 丢弃该候选
            for rm in re.finditer(r'(r\d+|[er][abcd]x|[er]si|[er]di)', ops):
                reg = _reg_family(rm.group(1))
                if reg in targets:
                    targets.discard(reg)
            if not targets:
                return None  # 候选全部被覆写 → 数组基址不确定
    return None


def _split_functions(insns):
    """stripped (无符号表) 时按函数启发切分: endbr64 / ret 后 padding 边界"""
    funcs = []
    cur = insns[0].address if insns else None
    for k, insn in enumerate(insns):
        is_boundary = False
        if insn.mnemonic == 'endbr64':
            is_boundary = True
        elif insn.mnemonic == 'ret' and k + 1 < len(insns):
            nxt = insns[k + 1]
            if nxt.address - (insn.address + insn.size) > 4:
                is_boundary = True
        if is_boundary and cur is not None and insn.address > cur:
            funcs.append((cur, insn.address, "func_%x" % cur))
            cur = insn.address
    if cur is not None and insns:
        funcs.append((cur, insns[-1].address + 1, "func_%x" % cur))
    return funcs


def detect_cross_function_uaf(path: str, insns=None, bits=None, func_bounds=None,
                              plt_map=None) -> list:
    """跨函数 UAF 启发: [{free: {addr, array}, use: {addr, array}, array_base}]"""
    if insns is None or bits is None:
        from intelpwn.core.analysis.overflow import disassemble_text
        pre = disassemble_text(path)
        if not pre:
            return []
        insns, bits = pre[0], pre[1]
    if not plt_map:
        try:
            from intelpwn.core.analysis.win_targets import _build_plt_map
            plt_map = _build_plt_map(path, bits)
        except Exception:
            plt_map = {}
    if not plt_map:
        # pyelftools 版失败 (stripped 动态链接 reloc 解析差异) → pwntools 兜底 (与黑板一致)
        try:
            from pwn import ELF
            pwn_elf = ELF(path, checksec=False)
            plt_map = {v: k for k, v in pwn_elf.plt.items()}
        except Exception:
            pass
    if not plt_map:
        return []  # 无 PLT 解析 → 无法识别 free/use 调用
    if not func_bounds:
        # stripped/无符号: 匿名函数切分 (endbr64/ret), 否则全 .text 单函数无法判"跨函数"
        func_bounds = _split_functions(insns)

    # 1) 扫所有 free / use 调用 + 数组基址
    frees = []   # {addr, array, func}
    uses = []    # {addr, array, func, callee}
    for f_start, f_end, f_name in func_bounds:
        f_insns = [i for i in insns if f_start <= i.address < f_end]
        for idx, insn in enumerate(f_insns):
            if insn.mnemonic != 'call':
                continue
            try:
                tgt = int(insn.op_str.strip(), 16)
            except ValueError:
                continue
            callee = plt_map.get(tgt) or plt_map.get(tgt - 4) or plt_map.get(tgt + 4)
            if not callee:
                continue
            if callee == 'free':
                base = _array_base_of(f_insns, idx, 'rdi')
                if base:
                    frees.append({"addr": insn.address, "array": base, "func": f_name})
            elif callee in _USE_CALLS:
                # use 的参数: puts/printf/read 第一参 rdi; write/send/recv 第二参 rsi
                arg_reg = 'rsi' if callee in ('write', 'send', 'recv') else 'rdi'
                base = _array_base_of(f_insns, idx, arg_reg)
                if base:
                    uses.append({"addr": insn.address, "array": base,
                                 "func": f_name, "callee": callee})

    # 2) 关联: 同一数组基址 free + use 在不同函数 → UAF
    chains = []
    for fr in frees:
        for us in uses:
            if fr["array"] == us["array"] and fr["func"] != us["func"]:
                chains.append({
                    "free_addr": hex(fr["addr"]), "free_func": fr["func"],
                    "use_addr": hex(us["addr"]), "use_func": us["func"],
                    "use_callee": us["callee"],
                    "array_base": hex(fr["array"]),
                    "detail": f"free@0x{fr['addr']:x} 后 {us['callee']}@0x{us['addr']:x} 使用同一对象数组"
                })
    return chains
