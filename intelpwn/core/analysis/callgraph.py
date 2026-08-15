"""全二进制函数调用图 — 全局关系分析 (函数级)

节点 = 函数 / PLT stub; 边 = call 指令 (直接目标).
标注: vuln (栈溢出函数 / angr 发现) · danger (敏感 PLT) · entry (main/_start) ·
      on_path (从漏洞/危险节点沿调用链反向可达 = 攻击路径)

数据流: 复用 disassemble_text (capstone) + 符号表 + PLT 解析, 无新依赖.
"""

from collections import defaultdict

# 敏感 PLT 函数 (危险调用目标, 命中即标橙)
DANGER_PLT = {"read", "recv", "gets", "fgets", "strcpy", "strncpy", "strcat",
              "sprintf", "snprintf", "scanf", "system", "execve", "mprotect",
              "memcpy", "printf", "puts"}

# 入口函数候选
ENTRY_NAMES = ("main", "_start", "entry")


def _direct_target(op_str):
    """call 操作数 → 直接目标地址 (int); 间接调用 (含 []) 返回 None"""
    from intelpwn.core.analysis.comments import _call_target_addr
    return _call_target_addr(op_str)


def _find_caller(addr, bounds):
    """addr 所在函数边界 (start, end, name) 或 None"""
    for start, end, _name in bounds:
        if start <= addr < end:
            return start
    return None


def _func_bounds_local(path):
    """符号表函数边界 [(start, end, name)] (standalone 用, 未传时)"""
    from intelpwn.utils.binary import open_elf
    funcs = []
    try:
        with open_elf(path) as elf:
            for sec_name in ('.symtab', '.dynsym'):
                sec = elf.get_section_by_name(sec_name)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                        funcs.append((sym['st_value'], sym['st_value'] + sym['st_size'], sym.name))
    except Exception:
        pass
    return funcs


def _sym_map_local(path, bits):
    """符号表 {addr: name} + PLT stub {addr: name@plt} (standalone 用, 未传时)"""
    from intelpwn.utils.binary import open_elf
    from intelpwn.core.analysis.win_targets import _build_plt_map
    smap = {}
    try:
        with open_elf(path) as elf:
            for sec_name in ('.symtab', '.dynsym'):
                sec = elf.get_section_by_name(sec_name)
                if sec:
                    for sym in sec.iter_symbols():
                        if sym.name and sym['st_info']['type'] == 'STT_FUNC':
                            smap[sym['st_value']] = sym.name
    except Exception:
        pass
    try:
        for stub, name in _build_plt_map(path, bits).items():
            smap[stub] = name + "@plt"
    except Exception:
        pass
    return smap


def build_call_graph(path, results=None, func_bounds=None, sym_map=None, insns=None):
    """构建函数调用图.

    path: 二进制路径; results: 分析结果 (标注漏洞); func_bounds/sym_map/insns 可传入复用.
    返回 {"nodes": [...], "edges": [...], "error": str|None}
    """
    from intelpwn.core.analysis.overflow import disassemble_text

    if insns is None:
        r = disassemble_text(path)
        if r is None:
            return {"nodes": [], "edges": [], "error": "反汇编失败"}
        insns, bits, _e_machine, _base = r
    else:
        bits = 64

    if func_bounds is None:
        func_bounds = _func_bounds_local(path)
    if sym_map is None:
        sym_map = _sym_map_local(path, bits)

    # ── 1. 节点: 真实函数 + PLT stub ──
    nodes = {}
    for start, _end, name in func_bounds:
        nodes[start] = {"id": start, "name": name, "addr": start, "kind": "func",
                        "vuln": False, "danger": False, "entry": False, "on_path": False}
    for addr, name in sym_map.items():
        if addr not in nodes:
            nodes[addr] = {"id": addr, "name": name, "addr": addr,
                           "kind": "plt" if name.endswith("@plt") else "func",
                           "vuln": False, "danger": False, "entry": False, "on_path": False}

    # ── 2. 调用边 ──
    edges = set()
    for insn in insns:
        if insn.mnemonic != "call":
            continue
        tgt = _direct_target(insn.op_str)
        if tgt is None or tgt not in nodes:
            continue
        caller = _find_caller(insn.address, func_bounds)
        if caller is not None and caller in nodes:
            edges.add((caller, tgt))

    # ── 3. 标注 ──
    vuln_addrs = set()
    for v in (results or {}).get("overflow", []):
        try:
            vuln_addrs.add(int(v.get("address", "0x0"), 16))
        except (ValueError, TypeError):
            pass
    # angr 主动发现/验证的调用点所在函数
    angr = (results or {}).get("angr_check", {}) or {}
    for lst_key in ("discovered", "verified"):
        for d in angr.get(lst_key, []):
            try:
                ca = int(d.get("call_addr", "0x0"), 16)
            except (ValueError, TypeError):
                continue
            caller = _find_caller(ca, func_bounds)
            if caller is not None:
                vuln_addrs.add(caller)

    for nid, node in nodes.items():
        # danger 按 @plt 名字后缀判定 (不管节点 kind — symtab 里 read@plt 可能是 STT_FUNC)
        base = node["name"][:-4] if node["name"].endswith("@plt") else node["name"]
        if base in DANGER_PLT:
            node["danger"] = True
        if nid in vuln_addrs:
            node["vuln"] = True

    entry_id = None
    for nid, node in nodes.items():
        if node["name"] in ENTRY_NAMES:
            node["entry"] = True
            if entry_id is None:
                entry_id = nid

    # ── 4. 攻击路径: 漏洞/危险节点沿入边反向 BFS → on_path ──
    pred = defaultdict(set)
    for s, t in edges:
        pred[t].add(s)
    seeds = [nid for nid, node in nodes.items() if node["vuln"] or node["danger"]]
    seen = set(seeds)
    stack = list(seeds)
    while stack:
        cur = stack.pop()
        for p in pred.get(cur, ()):
            if p not in seen:
                seen.add(p)
                stack.append(p)
    for nid in seen:
        nodes[nid]["on_path"] = True

    return {
        "nodes": sorted(nodes.values(), key=lambda n: n["addr"]),
        "edges": [{"source": s, "target": t} for s, t in sorted(edges)],
        "error": None,
    }
