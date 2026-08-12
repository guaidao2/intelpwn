"""angr 符号执行扩展分析器 (可选依赖, 插件自注册)

功能:
  1. 漏洞可达性: 对检测到的溢出调用点做符号执行, 确认其从入口可达
     (死代码/不可达路径 → 降置信度)。
  2. 大小参数符号化检查: 当静态无法确定 read/fgets 等的大小参数时,
     用 angr 求解器判断其最大可能值是否超过栈缓冲 (升/降置信度)。
  3. 整数溢出线索: 扫描 malloc/memcpy/read 大小参数是否来自乘法/移位
     等算术运算 (静态, 不依赖 angr)。

angr 未安装时: 模块导入不报错, 分析器注册为 available=False,
analyze_all 仍会执行但直接返回状态, 不影响其他分析。
"""

import re

from . import register_analyzer

try:
    import angr
    _HAVE_ANGR = True
except Exception:
    _HAVE_ANGR = False

# 有界输入: 函数 → (大小参数寄存器 x64, x86)
_SIZE_REGS = {
    'read': ('rdx', 'edx'),
    'recv': ('rdx', 'edx'),
    'memcpy': ('rdx', 'edx'),
    'strncpy': ('rdx', 'edx'),
    'fgets': ('rsi', 'esi'),
    'snprintf': ('rsi', 'esi'),
}


def _extract_call_addr(dangerous_call: str):
    """从 'read (0x401234) size=0x200' 提取调用点地址"""
    m = re.search(r'0x[0-9a-fA-F]+', dangerous_call or "")
    return int(m.group(0), 16) if m else None


def _angr_reachability(path: str, call_addr: int, timeout: int = 60) -> dict:
    """符号执行: 从入口能否到达 call_addr"""
    try:
        proj = angr.Project(path, auto_load_libs=False)
        state = proj.factory.full_init_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=call_addr, num_find=1, timeout=timeout)
        if simgr.found:
            return {"reachable": True, "steps": simgr.found[0].history.depth}
        if simgr.errored:
            return {"reachable": None, "reason": "探索出错"}
        return {"reachable": False, "reason": "未找到到调用点的路径 (可能为死代码)"}
    except Exception as e:
        return {"reachable": None, "reason": f"angr 错误: {type(e).__name__}"}


def _angr_size_check(path: str, call_addr: int, callee: str, stack_size: int,
                     bits: int, timeout: int = 60) -> dict:
    """符号执行: 调用点处大小参数的最大可能值 vs 栈缓冲"""
    regs = _SIZE_REGS.get(callee)
    if not regs:
        return {"status": "skip", "reason": f"无大小参数寄存器映射: {callee}"}
    reg = regs[0] if bits == 64 else regs[1]
    try:
        proj = angr.Project(path, auto_load_libs=False)
        state = proj.factory.full_init_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=call_addr, num_find=1, timeout=timeout)
        if not simgr.found:
            return {"status": "unknown", "reason": "调用点不可达"}
        st = simgr.found[0]
        try:
            concrete = st.solver.eval(st.regs.__getattr__(reg))
        except Exception:
            concrete = None
        try:
            maxv = st.solver.max(st.regs.__getattr__(reg))
        except Exception:
            maxv = None
        if concrete is not None and maxv is not None and concrete == maxv:
            # 大小是确定常量
            return {
                "status": "concrete",
                "size": concrete,
                "dangerous": concrete > stack_size,
            }
        if maxv is not None:
            return {
                "status": "symbolic",
                "max_possible": maxv,
                "dangerous": maxv > stack_size,
                "note": "大小参数来自变量, 无法静态确定",
            }
        return {"status": "unknown", "reason": "求解器无法解析大小参数"}
    except Exception as e:
        return {"status": "error", "reason": f"angr 错误: {type(e).__name__}: {e}"}


def _scan_int_overflow(path: str, results: dict, insns=None, bits=None) -> list:
    """静态扫描: malloc/memcpy/read 的大小参数是否来自算术运算 (mul/shl/add)"""
    if insns is None:
        from .overflow import disassemble_text
        pre = disassemble_text(path)
        if not pre:
            return []
        insns, bits = pre[0], pre[1]

    plt = results.get("plt", {})
    addr_to_name = {}
    try:
        from pwn import ELF
        elf = ELF(path, checksec=False)
        addr_to_name = {v: k for k, v in elf.plt.items()}
    except Exception:
        pass

    size_regs = {'rdx', 'edx', 'rsi', 'esi'}
    findings = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != 'call':
            continue
        try:
            callee = addr_to_name.get(int(insn.op_str, 16), "")
        except (ValueError, TypeError):
            continue
        if callee not in ('malloc', 'calloc', 'memcpy', 'read', 'recv', 'fgets'):
            continue
        # 调用前窗口内: 大小寄存器被算术指令 (imul/shl/lea 复合) 修改过
        window = insns[max(0, i - 12):i]
        for prev in window:
            if prev.mnemonic in ('imul', 'mul', 'shl', 'sal', 'lea') and \
               any(r in prev.op_str for r in size_regs):
                findings.append({
                    "function_call": f"{callee} @ 0x{insn.address:x}",
                    "arithmetic": f"{prev.mnemonic} {prev.op_str}",
                    "severity": "高危",
                    "detail": f"{callee} 的大小参数来自算术运算 ({prev.mnemonic}), "
                              "可能存在整数溢出导致堆/栈分配过小",
                })
                break
    return findings


# 主动发现: 需要 angr 验证的危险输入函数
#   函数 → (类型, 大小参数寄存器 x64, 缓冲/目标寄存器 x64)
#   注意: read/recv 的缓冲在 rsi (rdi 是 fd); 其余函数的第一个参数在 rdi
_DISCOVER_FUNCS = {
    'read':    ('bounded', 'rdx', 'rsi'),   # (fd, buf, size)
    'recv':    ('bounded', 'rdx', 'rsi'),   # (fd, buf, size, flags)
    'fgets':   ('bounded', 'rsi', 'rdi'),   # (buf, size, stream)
    'memcpy':  ('bounded', 'rdx', 'rdi'),   # (dst, src, size)
    'strncpy': ('bounded', 'rdx', 'rdi'),   # (dst, src, size)
    'snprintf': ('bounded', 'rsi', 'rdi'),  # (buf, size, fmt, ...)
    'gets':    ('unbounded', None, 'rdi'),
    'strcpy':  ('unbounded', None, 'rdi'),
    'sprintf': ('unbounded', None, 'rdi'),
    'strcat':  ('unbounded', None, 'rdi'),
    'scanf':   ('unbounded', None, 'rdi'),
}


def _compute_padding(st, buf: int, max_off: int = 0x400):
    """从 buf 向上扫描栈内存: 找到 saved rbp (栈指针) + 返回地址 (代码地址) 特征。

    跨帧场景 (子函数内 strcpy 覆盖调用者的缓冲) 也正确:
    返回地址槽 = buf + off + 8, padding = off + 8。
    """
    for off in range(0, max_off, 8):
        try:
            # 必须显式 Iend_LE: 默认 load 端序会返回字节反转的值
            q = st.solver.eval(st.memory.load(buf + off, 8, endness='Iend_LE'))
            r = st.solver.eval(st.memory.load(buf + off + 8, 8, endness='Iend_LE'))
        except Exception:
            break
        # q = 栈指针 (saved rbp), r = 非栈的代码地址 (返回地址; 排除 libc/ld 0x7f...)
        if 0x7f0000000000 <= q < 0x800000000000 and 0x400000 <= r < 0x7f0000000000:
            return off + 8
    return None


def _angr_discover(path: str, results: dict, max_sites: int = 20) -> dict:
    """主动发现: 枚举二进制中所有危险输入函数调用点, 符号执行验证

    对每个可达调用点检查:
      - 目标地址是否落在栈上 (第一个参数 rdi)
      - 无界写 (strcpy/gets/...) 目标为栈 → 溢出, 用 angr 状态算 padding
      - 有界读 (read/fgets/...) 大小参数是否符号化 (可控) / 超过栈缓冲
    返回 {discovered: [...], static_verified: [...], padding_crosscheck: [...]}
    """
    from .overflow import disassemble_text

    pre = disassemble_text(path)
    if not pre:
        return {"discovered": [], "static_verified": [], "padding_crosscheck": []}
    insns, bits = pre[0], pre[1]

    try:
        from pwn import ELF
        plt_map = {v: k for k, v in ELF(path, checksec=False).plt.items()}
    except Exception:
        plt_map = {}

    static_calls = set()
    for so in results.get("overflow", []):
        a = _extract_call_addr(so.get("dangerous_call", ""))
        if a:
            static_calls.add(a)

    discovered, verified = [], []
    sites = 0
    for i, insn in enumerate(insns):
        if insn.mnemonic != 'call':
            continue
        try:
            callee = plt_map.get(int(insn.op_str, 16), "")
        except (ValueError, TypeError):
            continue
        if callee not in _DISCOVER_FUNCS:
            continue
        sites += 1
        if sites > max_sites:
            break

        call_addr = insn.address
        kind, size_reg, buf_reg = _DISCOVER_FUNCS[callee]

        # 可达性
        try:
            proj = angr.Project(path, auto_load_libs=False)
            state = proj.factory.full_init_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=call_addr, num_find=1, timeout=30)
        except Exception:
            continue
        if not simgr.found:
            continue  # 不可达, 跳过
        st = simgr.found[0]

        entry = {"callee": callee, "call_addr": hex(call_addr),
                 "static_detected": call_addr in static_calls}

        # 缓冲/目标地址: read/recv 在 rsi, 其余在 rdi
        try:
            buf = st.solver.eval(st.regs.__getattr__(buf_reg))
            on_stack = 0x7f0000000000 <= buf < 0x800000000000
        except Exception:
            continue
        entry["buf_addr"] = hex(buf)

        if kind == 'unbounded':
            # 无界写: 目标在栈上 → 溢出点
            if not on_stack:
                continue
            padding = _compute_padding(st, buf)
            entry.update({"vuln": "unbounded_write", "stack_buf": True})
            if padding is not None:
                entry["padding"] = padding
            if call_addr in static_calls:
                verified.append(entry)
            else:
                entry["discovered_by"] = "angr"
                discovered.append(entry)
        else:
            # 有界读: 大小符号化检查
            try:
                sz_expr = st.regs.__getattr__(size_reg)
                symbolic = st.solver.is_symbolic(sz_expr)
                maxv = st.solver.max(sz_expr) if symbolic else st.solver.eval(sz_expr)
            except Exception:
                continue
            dangerous = on_stack and (symbolic or maxv > 0x100)
            entry.update({"vuln": "bounded_read", "size_symbolic": symbolic,
                          "size_max": maxv, "stack_buf": on_stack})
            if dangerous:
                if on_stack:
                    pad = _compute_padding(st, buf)
                    if pad is not None:
                        entry["padding"] = pad
                if call_addr in static_calls:
                    verified.append(entry)
                else:
                    entry["discovered_by"] = "angr"
                    discovered.append(entry)

    # 符号化 padding 交叉确认 (静态已检出 + angr 可达的调用点)
    padding_crosscheck = []
    for so in results.get("overflow", []):
        call_addr = _extract_call_addr(so.get("dangerous_call", ""))
        if call_addr is None:
            continue
        # 从 dangerous_call 文本取 callee 名, 查缓冲寄存器 (read/recv 在 rsi)
        callee = (so.get("dangerous_call", "").split("(")[0].strip() or "read")
        _, _, buf_reg = _DISCOVER_FUNCS.get(callee, ('bounded', 'rdx', 'rdi'))
        try:
            proj = angr.Project(path, auto_load_libs=False)
            state = proj.factory.full_init_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=call_addr, num_find=1, timeout=30)
            if not simgr.found:
                continue
            st = simgr.found[0]
            buf = st.solver.eval(st.regs.__getattr__(buf_reg))
            angr_pad = _compute_padding(st, buf)
            if angr_pad is None:
                continue
        except Exception:
            continue
        static_pad = so.get("calculated_padding", 0)
        if abs(angr_pad - static_pad) > 0 and angr_pad > 0:
            padding_crosscheck.append({
                "function": so.get("function"),
                "static_padding": static_pad,
                "angr_padding": angr_pad,
                "mismatch": True,
            })

    return {"discovered": discovered, "static_verified": verified,
            "padding_crosscheck": padding_crosscheck}


def _analyze_angr(path: str, results: dict) -> dict:
    """angr 扩展分析主入口 (插件签名: fn(path, results) -> dict)"""
    if not _HAVE_ANGR:
        return {"available": False, "reason": "angr 未安装 (pip install angr)"}

    out = {"available": True}
    bits = results.get("protections", {}).get("bits", 64)
    overflow = results.get("overflow", [])

    # 1. 溢出调用点可达性 + 大小符号化检查 (静态已检出的)
    checks = []
    for so in overflow:
        call_addr = _extract_call_addr(so.get("dangerous_call", ""))
        callee = (so.get("dangerous_call", "").split("(")[0].strip() or "read")
        entry = {"function": so.get("function"), "address": so.get("address")}
        if call_addr is None:
            checks.append({**entry, "status": "skip", "reason": "无法解析调用点地址"})
            continue
        reach = _angr_reachability(path, call_addr)
        entry["reachability"] = reach
        if reach.get("reachable"):
            size = _angr_size_check(path, call_addr, callee, so.get("stack_size", 0), bits)
            entry["size_check"] = size
        checks.append(entry)
    out["checks"] = checks

    # 2. 主动发现: 全量枚举危险调用点 (含静态漏检的)
    out.update(_angr_discover(path, results))

    # 3. 整数溢出线索 (静态)
    out["int_overflow"] = _scan_int_overflow(path, results)

    return out


if _HAVE_ANGR:
    register_analyzer("angr_check")(_analyze_angr)
