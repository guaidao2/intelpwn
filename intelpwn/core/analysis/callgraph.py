"""全二进制函数调用图 — 全局关系分析 (函数级)

节点 = 函数 / PLT stub; 边 = call 指令 (直接目标).
标注: vuln (栈溢出函数 / angr 发现) · danger (敏感 PLT) · entry (main/_start) ·
      on_path (从漏洞/危险节点沿调用链反向可达 = 攻击路径)

数据流: 复用 disassemble_text (capstone) + 符号表 + PLT 解析, 无新依赖.
"""

from collections import defaultdict
import logging
import re

log = logging.getLogger("intelpwn.callgraph")

# 敏感 PLT 函数 (危险调用目标, 命中即标橙)
DANGER_PLT = {"read", "recv", "gets", "fgets", "strcpy", "strncpy", "strcat",
              "sprintf", "snprintf", "scanf", "system", "execve", "mprotect",
              "memcpy", "printf", "puts"}

# 入口函数候选
ENTRY_NAMES = ("main", "_start", "entry")

# CRT 样板函数 (glibc 启动/收尾样板, 前端默认隐藏 — 对 CTF 分析是噪音)
CRT_FUNCS = {"_init", "_fini", "_dl_relocate_static_pie", "deregister_tm_clones",
             "register_tm_clones", "__do_global_dtors_aux", "frame_dummy",
             "__libc_csu_init", "__libc_csu_fini", "__do_global_ctors_aux"}


def _got_map(path):
    """GOT 地址 → 符号名 (.rela.plt/.rel.plt/.rela.dyn) — 解析间接调用用"""
    got = {}
    try:
        from intelpwn.utils.binary import open_elf
        with open_elf(path) as elf:
            dynsym = elf.get_section_by_name('.dynsym')
            if not dynsym:
                return got
            for secname in ('.rela.plt', '.rel.plt', '.rela.dyn'):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for reloc in sec.iter_relocations():
                    try:
                        name = dynsym.get_symbol(reloc['r_info_sym']).name
                        if name:
                            got[reloc['r_offset']] = name
                    except Exception:
                        pass  # 单条重定位解析失败, 跳过不影响整体
    except Exception as e:
        log.warning("GOT 重定位解析失败 %s: %s", path, e)
    return got


def _indirect_got_target(op_str, insn_addr, insn_size, got_map):
    """call qword ptr [rip + disp] → (got_addr, 符号名); 非 rip 相对或无解析返回 None"""
    m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', op_str or "")
    if not m:
        return None
    disp = int(m.group(2), 16) * (1 if m.group(1) == '+' else -1)
    got_addr = insn_addr + insn_size + disp
    name = got_map.get(got_addr)
    if not name:
        return None
    return got_addr, name


# 寄存器间接调用: call rax / call r12 等纯寄存器操作数
_REG_CALL = re.compile(r'^(r(ax|bx|cx|dx|si|di|sp|bp|8|9|10|11|12|13|14|15)|e(ax|bx|cx|dx|si|di))$')


def _call_reg_target(op_str, insns, insn_index):
    """call <reg>: 回看 6 条内 mov/lea reg, <常量地址> → 目标地址; 无则 None.

    保守策略: 只解析 1) mov reg, <裸 0x 常量> 2) lea reg, [<绝对地址>];
    命中任何其他对 reg 的写入 (寄存器来源/rip 相对/栈偏移/xor/pop) 立即停止 —
    常量已死, 不继续回看更旧的值 (防死值误报).
    """
    op = (op_str or "").strip()
    if not _REG_CALL.match(op):
        return None
    reg = op.lower()
    # 32 位同族 (eax/rax) 写入也要终止扫描 — 复用 comments._reg_prefixed
    from intelpwn.core.analysis.comments import _reg_prefixed
    WRITERS = ("mov", "lea", "xor", "add", "sub", "movzx", "movsxd", "pop")
    for j in range(insn_index - 1, max(-1, insn_index - 7), -1):
        prev = insns[j]
        if prev.mnemonic not in WRITERS:
            continue
        p_op = (prev.op_str or "").lower()
        # pop: 只 pop 本族 reg 才终止, pop 其他 reg 继续回看
        if prev.mnemonic == "pop":
            if _reg_prefixed(p_op, reg):
                return None
            continue
        if not _reg_prefixed(p_op, reg):
            continue  # 写的是其他寄存器, 不影响本 reg 的常量
        src = p_op.split(",", 1)[1].strip()
        # 只有 mov/lea 的常量才可能是地址; xor/add/sub/movzx/movsxd 的常量不是
        if prev.mnemonic not in ("mov", "lea"):
            return None  # 写即终止 (非常量装载)
        # 裸常量: mov reg, 0x...
        if re.fullmatch(r'0x[0-9a-f]+', src):
            try:
                return int(src, 16)
            except ValueError:
                return None
        # 绝对地址: lea reg, [0x...]
        if re.fullmatch(r'\[0x[0-9a-f]+\]', src):
            try:
                return int(src[1:-1], 16)
            except ValueError:
                return None
        # 其他写入 (寄存器/rip相对/栈偏移) → 常量已死, 停止
        return None
    return None


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
    except Exception as e:
        log.warning("函数边界解析失败 %s: %s", path, e)
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
    except Exception as e:
        log.warning("PLT stub 解析失败 %s: %s", path, e)
    return smap


def build_call_graph(path, results=None, func_bounds=None, sym_map=None, insns=None, bits=None):
    """构建函数调用图.

    path: 二进制路径; results: 分析结果 (标注漏洞); func_bounds/sym_map/insns/bits 可传入复用.
    返回 {"nodes": [...], "edges": [...], "error": str|None}
    """
    from intelpwn.core.analysis.overflow import disassemble_text

    if insns is None:
        r = disassemble_text(path)
        if r is None:
            return {"nodes": [], "edges": [], "error": "反汇编失败"}
        insns, bits, _e_machine, _base = r

    if func_bounds is None:
        func_bounds = _func_bounds_local(path)
    if sym_map is None:
        sym_map = _sym_map_local(path, bits or 64)

    # ── 1. 节点: 真实函数 + PLT stub ──
    nodes = {}
    for start, _end, name in func_bounds:
        nodes[start] = {"id": start, "name": name, "addr": start, "kind": "func",
                        "vuln": False, "danger": False, "entry": False, "on_path": False,
                        "crt": name in CRT_FUNCS}
    for addr, name in sym_map.items():
        if addr in nodes or addr == 0:  # 0x0 = dynsym 版本化占位符 (无实义), 跳过
            continue
        nodes[addr] = {"id": addr, "name": name, "addr": addr,
                       "kind": "plt" if name.endswith("@plt") else "func",
                       "vuln": False, "danger": False, "entry": False, "on_path": False,
                       "crt": name in CRT_FUNCS}

    # ── 2. 调用边 (直接 + 经 GOT 的间接 call [rip+disp] + 寄存器间接 call reg) ──
    got_map = _got_map(path)
    edges = set()
    for idx, insn in enumerate(insns):
        if insn.mnemonic != "call":
            continue
        tgt = _direct_target(insn.op_str)
        if tgt is None:
            # 间接调用: 先经 GOT 解析 (call qword ptr [rip+disp] → 符号)
            got_info = _indirect_got_target(insn.op_str, insn.address, getattr(insn, "size", 0), got_map)
            if got_info:
                got_addr, name = got_info
                # 目标节点: 优先同名非 0x0 符号; 否则 GOT 槽伪节点
                tgt = next((a for a, n in sym_map.items() if n == name and a != 0), None)
                if tgt is None and got_addr not in nodes:
                    nodes[got_addr] = {"id": got_addr, "name": name, "addr": got_addr,
                                       "kind": "got", "vuln": False, "danger": False,
                                       "entry": False, "on_path": False, "crt": False}
                    tgt = got_addr
            else:
                # 寄存器间接: call reg, 回看 mov/lea reg, 常量 (函数指针/vtable 场景)
                reg_tgt = _call_reg_target(insn.op_str, insns, idx)
                if reg_tgt is not None and reg_tgt in nodes:
                    tgt = reg_tgt
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
        # 取舍: 用户自定义的同名函数 (如 wrapper read) 也会标橙, 属误报扩大但可接受
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
