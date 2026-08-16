"""菜单交互识别 — 通用基础设施

识别 scanf 数字菜单 (如 pwn2 的 "1.Encrypt 2.Decrypt 3.Exit")：
  - 双通道锚点: rodata "N. 名称" 菜单项 / scanf %d 后 cmp+je 比较链
  - case→handler 映射: 选项号 → 跳转目标 → 函数名 → 参数结构
  - 输出 options 映射表 {选项: {handler, address, params}}, 供 exploit 模板
    插入预交互 (recvuntil(提示) + sendline(选项)), 否则脚本直接发 payload
    会错位到菜单 scanf。

防伪菜单: 只对"明确触发溢出函数"的选项置 confident — 选项多但 handler
无输入序列的伪菜单题不触发自动交互, 退回普通模板。
"""
import logging
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

from intelpwn.utils.binary import open_elf
from . import register_analyzer

log = logging.getLogger("intelpwn")

_PROMPT_KEYWORDS = ("choice", "option", "select", "menu", "input", "enter", "welcome", ">>>", ">")
_STRONG_PROMPT = ("choice", "option", "select", "input", "enter", ">>>", ">")
_ANCHOR_SPLIT = ("!", ":", "?", " ", "\n")
_INPUT_FUNCS = ("scanf", "gets", "fgets", "read", "fread")


def _read_cstr(path: str, vaddr: int) -> str:
    """从 ELF 读 vaddr 处的 NUL 结尾字符串 (跨 section 查找)"""
    try:
        with open_elf(path) as elf:
            for sec in elf.iter_sections():
                sh_addr, sh_size = sec['sh_addr'], sec['sh_size']
                if sh_addr <= vaddr < sh_addr + sh_size:
                    data = sec.data()
                    off = vaddr - sh_addr
                    end = data.find(b'\x00', off)
                    if end == -1:
                        end = len(data)
                    return data[off:end].decode('utf-8', errors='replace')
    except Exception:
        pass
    return ""


def _rodata_menu_items(path: str):
    """扫 .rodata 找 'N. 名称' 模式菜单项 (数字. 名词), 按顺序返回"""
    items = []
    try:
        with open_elf(path) as elf:
            rodata = elf.get_section_by_name('.rodata')
            if rodata:
                for raw in rodata.data().split(b'\x00'):
                    s = raw.decode('utf-8', errors='replace').strip()
                    if re.match(r'^\d+\.\s*\S+', s):
                        items.append(s)
    except Exception:
        pass
    return items


def _lea_rip_target(insn):
    """解析 'lea reg, [rip + 0x1234]' → 目标地址 (x64)"""
    m = re.match(r'^\S+,\s*\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]$', insn.op_str)
    if not m:
        return None
    disp = int(m.group(2), 16)
    if m.group(1) == '-':
        disp = -disp
    return insn.address + insn.size + disp


def _imm_of(insn):
    """从 mov/lea 指令 op_str 提取立即数地址 (0x... 或裸数字)"""
    m = re.search(r'0x[0-9a-fA-F]+|\b\d+\b', insn.op_str)
    if not m:
        return None
    s = m.group(0)
    return int(s, 16) if s.startswith('0x') else int(s)


def _call_target(insn, plt_map, sym_by_addr):
    """解析 call 指令的目标函数名 (直接地址/PLT 间接/寄存器)"""
    op = insn.op_str.strip()
    if op.startswith('qword ptr [rip') or op.startswith('dword ptr [rip'):
        m = re.search(r'0x[0-9a-fA-F]+', op)
        if m:
            return plt_map.get(int(m.group(0), 16)) or ('plt_%x' % int(m.group(0), 16))
    m = re.match(r'^0x([0-9a-fA-F]+)$', op)
    if m:
        addr = int(m.group(1), 16)
        name = sym_by_addr.get(addr)
        if name:
            return name
        return plt_map.get(addr)
    return None


def _callee_addr(insn):
    """call 指令的直接目标地址 (0x...)"""
    m = re.match(r'^0x([0-9a-fA-F]+)$', insn.op_str.strip())
    return int(m.group(1), 16) if m else None


def _anchor_from_prompt(prompt: str) -> str:
    """从提示串截取 recvuntil 锚点: 关键词后第一分隔符前 / 菜单项第一段"""
    low = prompt.lower()
    for kw in _PROMPT_KEYWORDS:
        idx = low.find(kw)
        if idx >= 0:
            tail = prompt[idx:]
            for sep in _ANCHOR_SPLIT:
                if sep in tail:
                    return tail[:tail.index(sep) + 1]
            return tail
    # 菜单项列表: 取第一段 "1.Encrypt" (puts 逐行输出, 整串匹配不到)
    m = re.match(r'(\d+\.\s*\S+)', prompt)
    if m:
        return m.group(1)
    return prompt


def _handler_params(path: str, insns, func_bounds, handler_addr: int,
                    plt_map, sym_by_addr) -> list:
    """handler 函数体内输入调用序列: 按顺序扫 scanf/gets/read + 格式串

    返回 e.g. ["%zu", "%s"] (Add 需先输 size 再输 content) 或 ["gets"]
    """
    hb = next(((s, e) for s, e, n in func_bounds if s == handler_addr), None)
    if not hb:
        return []
    params = []
    for i in insns:
        if not (hb[0] <= i.address < hb[1] and i.mnemonic == 'call'):
            continue
        name = _call_target(i, plt_map, sym_by_addr) or ''
        if 'scanf' in name:
            # 格式串: 调用前 ≤10 条的 mov/lea 到 rdi/edi
            fmt = ""
            idx = next((k for k, ins in enumerate(insns) if ins.address == i.address), None)
            for ins in insns[max(0, (idx or 0) - 10):(idx or 0)]:
                if ins.mnemonic in ('lea', 'mov') and ('rdi' in ins.op_str or 'edi' in ins.op_str):
                    tgt = _lea_rip_target(ins) or _imm_of(ins)
                    if tgt:
                        fmt = _read_cstr(path, tgt)
                        if fmt:
                            break
            params.append(fmt or "scanf")
        elif any(f in name for f in ('gets', 'fgets', 'read', 'fread')):
            params.append(name)
    return params


@register_analyzer("menu")
def analyze_menu(path: str, results: dict = None) -> dict:
    """识别数字菜单 → options 映射表 + 触发溢出函数的选项"""
    results = results or {}
    out = {"present": False, "confident": False, "prompt": "", "anchor": "",
           "trigger": "", "target_func": "", "numeric": False, "options": {}}

    overflow = results.get("overflow") or []
    if not overflow:
        return out
    target_func = overflow[0].get("function") or ""
    target_addr = None
    try:
        target_addr = int(str(overflow[0].get("address") or ""), 16)
    except ValueError:
        pass
    if not target_func and not target_addr:
        return out

    # 黑板基础设施缓存 (analyze_all 物化, 避免重复 open_elf/capstone) — 独立调用时回退自扫
    shared = results.get("_shared") or {}
    insns = shared.get("insns")
    bits = shared.get("bits")
    func_bounds = list(shared.get("func_bounds") or [])
    sym_by_addr = dict(shared.get("sym_by_addr") or {})
    if insns is None or not func_bounds:
        try:
            with open_elf(path) as elf:
                e_machine = elf.header.e_machine
                bits = 64 if e_machine == 'EM_X86_64' else (32 if e_machine in ('EM_386', 'EM_486') else 0)
                if not bits:
                    return out
                md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
                md.detail = True
                text = elf.get_section_by_name('.text')
                if not text:
                    return out
                insns = list(md.disasm(text.data(), text['sh_addr']))
                for sec_name in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sec_name)
                    if not sec:
                        continue
                    for sym in sec.iter_symbols():
                        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                            func_bounds.append((sym['st_value'], sym['st_value'] + sym['st_size'], sym.name))
                            sym_by_addr.setdefault(sym['st_value'], sym.name)
        except Exception as e:
            log.warning("菜单分析反汇编失败 %s: %s", path, e)
            return out

    # PLT 地址→名称: 黑板优先, 否则 results["plt"] (name→addr) 反转
    plt_map = dict(shared.get("plt_map") or {})
    if not plt_map:
        for name, addr in (results.get("plt") or {}).items():
            try:
                plt_map[int(str(addr), 16)] = name
            except (ValueError, TypeError):
                pass

    # main 范围
    main_bounds = next(((s, e) for s, e, n in func_bounds if n == 'main'), None)
    if not main_bounds:
        return out
    main_insns = [i for i in insns if main_bounds[0] <= i.address < main_bounds[1]]
    if not main_insns:
        return out

    # 1) 找 scanf 调用点
    scanf_idx = None
    for idx, insn in enumerate(main_insns):
        if insn.mnemonic == 'call':
            name = _call_target(insn, plt_map, sym_by_addr) or ''
            if 'scanf' in name:
                scanf_idx = idx
                break
    if scanf_idx is None:
        return out

    # 2) 格式串 → 数字菜单判定
    fmt = ""
    for insn in main_insns[max(0, scanf_idx - 12):scanf_idx]:
        if insn.mnemonic in ('lea', 'mov') and ('rdi' in insn.op_str or 'edi' in insn.op_str
                                                or 'eax' in insn.op_str or 'ebx' in insn.op_str):
            tgt = _lea_rip_target(insn) or _imm_of(insn)
            if tgt:
                fmt = _read_cstr(path, tgt)
                if fmt:
                    break
    is_numeric = '%d' in fmt or '%i' in fmt or fmt == ''

    # 3) scanf 后分支链: cmp $imm,reg + je/jne <target>
    jccs = []  # (imm, jcc_idx, kind, target)
    for idx in range(scanf_idx + 1, len(main_insns)):
        insn = main_insns[idx]
        if insn.mnemonic == 'cmp':
            m = re.match(r'^(0x[0-9a-fA-F]+|\d+)\s*,\s*(\S+)$', insn.op_str)
            if not m:
                m = re.match(r'^(\S+)\s*,\s*(0x[0-9a-fA-F]+|\d+)$', insn.op_str)
            if m:
                imm = m.group(1) if m.group(1).startswith(('0x', '0X', '1', '2', '3', '4', '5', '6', '7', '8', '9')) else m.group(2)
                nxt = main_insns[idx + 1] if idx + 1 < len(main_insns) else None
                if nxt and nxt.mnemonic in ('je', 'jne') and nxt.op_str.strip().startswith('0x'):
                    jccs.append((imm, idx + 1, nxt.mnemonic, int(nxt.op_str.strip(), 16)))
        if len(jccs) >= 16:
            break

    # 4) 分支 → handler 映射: je 查目标区, jne 查 fallthrough (jne 目标是 default)
    #    跳过 puts/printf 等打印调用 (非业务 handler)
    print_funcs = ('puts', 'printf', 'puts@plt', 'printf@plt', 'write', 'putchar')
    options = {}
    for bi, (imm, jcc_idx, kind, tgt) in enumerate(jccs):
        regions = []
        if kind == 'je':
            regions.append([tgt, tgt + 0x40])
        nxt_jcc = jccs[bi + 1][1] if bi + 1 < len(jccs) else len(main_insns)
        if jcc_idx + 1 < len(main_insns):
            fall_start = main_insns[jcc_idx + 1].address
            fall_end = main_insns[nxt_jcc].address if nxt_jcc < len(main_insns) else fall_start + 0x40
            regions.append([fall_start, fall_end])
        for r0, r1 in regions:
            for i in main_insns:
                if not (r0 <= i.address < r1 and i.mnemonic == 'call'):
                    continue
                name = _call_target(i, plt_map, sym_by_addr) or ''
                callee = _callee_addr(i)
                if not name and not callee:
                    continue
                if name in print_funcs:
                    continue  # 打印调用不是 handler
                if imm not in options:
                    options[imm] = {"handler": name or ('func_%x' % callee),
                                    "address": hex(callee) if callee else "",
                                    "params": []}
                # 匹配溢出函数 → 记 trigger/confident
                hit = (name == target_func) or (target_addr is not None and callee == target_addr)
                if hit and not out["confident"]:
                    out["trigger"] = imm
                    out["target_func"] = name or target_func
                    out["confident"] = True

    if not out["confident"]:
        return out

    # 5) handler 参数结构 (输入序列: scanf/gets/read + 格式串)
    for imm, opt in options.items():
        try:
            addr = int(opt["address"], 16) if opt["address"] else 0
        except ValueError:
            addr = 0
        if addr:
            opt["params"] = _handler_params(path, insns, func_bounds, addr, plt_map, sym_by_addr)

    # 6) 菜单提示串: 优先选择提示 (choice/input), 其次 rodata 菜单项, 再 welcome
    prompt = ""
    fallback_prompt = ""
    for insn in main_insns[max(0, scanf_idx - 40):scanf_idx]:
        if insn.mnemonic in ('lea', 'mov') and ('rdi' in insn.op_str or 'edi' in insn.op_str):
            tgt = _lea_rip_target(insn) or _imm_of(insn)
            if tgt:
                s = _read_cstr(path, tgt)
                low = s.lower()
                if any(kw in low for kw in _STRONG_PROMPT):
                    prompt = s
                    break
                if not fallback_prompt and any(kw in low for kw in _PROMPT_KEYWORDS):
                    fallback_prompt = s
    if not prompt:
        # rodata 菜单项 (如 "1.Encrypt 2.Decrypt 3.Exit") — 比欢迎词更接近选择点
        items = _rodata_menu_items(path)
        if items:
            prompt = " ".join(items)
    if not prompt:
        prompt = fallback_prompt
    if not prompt:
        prompt = fmt
    out["prompt"] = prompt
    out["anchor"] = _anchor_from_prompt(prompt) if prompt else ""
    out["numeric"] = is_numeric
    out["options"] = options
    out["present"] = True
    return out
