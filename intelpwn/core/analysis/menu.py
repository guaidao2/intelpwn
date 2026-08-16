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


def _has_chain(insns_window):
    """判断指令窗口内是否有 cmp imm,reg + je/jne 分发链特征"""
    return any(tk.mnemonic == 'cmp' and nxt.mnemonic in ('je', 'jne')
               and nxt.op_str.strip().startswith('0x')
               for tk, nxt in zip(insns_window, insns_window[1:]))


def _backfill_rodata_handlers(path, options):
    """stripped 场景: options 的 handler 是 func_ 匿名名时, 用 rodata 菜单项
    ("1.Add\n2.Del" 标签) 回填语义名 (add/del/show/edit), 供堆模板按名匹配"""
    if not options:
        return
    if any(v.get("handler") and not v["handler"].startswith("func_") for v in options.values()):
        return  # 已有符号名, 无需回填
    try:
        items = _rodata_menu_items(path)
    except Exception:
        return
    for item in items:
        m = re.match(r'^(\d+)\.\s*(\S+)', item)
        if m and m.group(1) in options:
            options[m.group(1)]["handler"] = m.group(2).lower()


def _func_start(insns, idx):
    """从指令索引向上找函数起点 (最近的 endbr64 / ret 后边界)"""
    for k in range(idx, -1, -1):
        if insns[k].mnemonic == 'endbr64':
            return insns[k].address
        if insns[k].mnemonic == 'ret':
            return insns[k + 1].address if k + 1 < len(insns) else None
    return None


def _func_end(insns, idx):
    """从指令索引向下找函数终点 (下一 endbr64 或文件尾)"""
    for k in range(idx + 1, len(insns)):
        if insns[k].mnemonic == 'endbr64':
            return insns[k].address
    return None


def _find_jump_table(insns, plt_map, sym_by_addr):
    """识别手写跳转表菜单: lea rX,[reg*8] + lea rax,[rip+table] + mov rax,[rdx+rax] + call/jmp rax

    Returns:
        {"table": 表基址, "prompt": ""} 或 None
    """
    for k, insn in enumerate(insns):
        if insn.mnemonic != 'lea' or '*8' not in insn.op_str:
            continue
        window = insns[k + 1:k + 16]
        for n in window:
            if n.mnemonic != 'lea' or '[rip' not in n.op_str:
                continue
            table = _lea_rip_target(n)
            if not table:
                continue
            # 后续 mov rax,[rdx+rax] (或 [reg+rax]) + call/jmp rax
            for m in insns[k:k + 24]:
                if m.mnemonic not in ('call', 'jmp'):
                    continue
                op = m.op_str.strip()
                if op.startswith('rax') or op.startswith('qword ptr [r'):
                    return {"table": table, "prompt": ""}
    return None


def _call_target(insn, plt_map, sym_by_addr):
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
        got = plt_map.get(addr)
        if got:
            return got
        # CET endbr64 错位: stub 起点 (endbr64) 与 jmp 槽 (key) 相差 4 字节
        for delta in (4, -4):
            got = plt_map.get(addr + delta)
            if got:
                return got
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
    scanf_idx = None  # 菜单读选项调用点 (主流程在 main_insns 局部索引)
    scanf_addr = None  # fallback 定位的读选项调用地址 (地址跨切片安全)

    overflow = results.get("overflow") or []
    # 菜单识别独立于漏洞类型: 溢出题匹配溢出函数, 堆题 (无 overflow) 也识别 options
    target_func = (overflow[0].get("function") if overflow else "") or ""
    target_addr = None
    if overflow:
        try:
            target_addr = int(str(overflow[0].get("address") or ""), 16)
        except ValueError:
            pass

    # 黑板基础设施缓存 (analyze_all 物化) — 独立调用时复用共享物化, 不重复手写解析
    shared = results.get("_shared") or {}
    insns = shared.get("insns")
    bits = shared.get("bits")
    func_bounds = list(shared.get("func_bounds") or [])
    sym_by_addr = dict(shared.get("sym_by_addr") or {})
    if insns is None or not func_bounds:
        try:
            from . import _build_shared_blackboard
            from .overflow import disassemble_text
            pre = disassemble_text(path)
            if not pre:
                return out
            bb = _build_shared_blackboard(path, pre[0], pre[1])
            insns, bits = bb["insns"], bb["bits"]
            func_bounds = list(bb["func_bounds"])
            sym_by_addr = dict(bb["sym_by_addr"])
            shared = bb  # 写回: 后续 plt_map 等从 shared 取 (瘦身时漏过 plt_map)
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

    # 菜单分发输入函数: scanf (格式串) / atoll·atoi·strtol (read 读入字符串后转数字)
    _MENU_INPUTS = ('scanf', 'atoll', 'atoi', 'strtol', 'strtoul')

    # main 范围
    main_bounds = next(((s, e) for s, e, n in func_bounds if n == 'main'), None)
    if not main_bounds:
        # 跳转表菜单 (手写函数指针表): [reg*8 + table] + call/jmp reg
        # 常见于 stripped 堆题 (read 读入 + atoll 转数字 + 间接调用), .bss 表静态不可读
        jt = _find_jump_table(insns, plt_map, sym_by_addr)
        if jt:
            items = _rodata_menu_items(path)
            for item in items:
                m = re.match(r'^(\d+)\.\s*(\S+)', item)
                if m:
                    out["options"][m.group(1)] = {"handler": m.group(2).lower(),
                                                  "address": "", "params": []}
            if out["options"]:
                out["present"] = True
            out["prompt"] = " ".join(items) if items else jt["prompt"]
            out["anchor"] = _anchor_from_prompt(out["prompt"]) if out["prompt"] else ""
            out["numeric"] = True
            out["jump_table"] = hex(jt["table"])
            return out
        # stripped 赛题 (无符号表 → func_bounds 可能完全为空):
        # 两通道定位菜单分发:
        #   A) 输入调用 (atoll/scanf) 自身后 40 条有 cmp/je 链 (main 内 scanf 菜单)
        #   B) 输入在子函数 (读选项函数) → 其调用点后 40 条有链 (duck 类, call 读数字函数)
        for j, i in enumerate(insns):
            if i.mnemonic != 'call':
                continue
            name = _call_target(i, plt_map, sym_by_addr) or ''
            if not any(k in name for k in _MENU_INPUTS):
                continue
            if _has_chain(insns[j + 1:j + 40]):
                main_bounds = (_func_start(insns, j) or insns[0].address,
                               _func_end(insns, j) or insns[-1].address)
                scanf_addr = insns[j].address
                break
            read_fn = _func_start(insns, j)
            if not read_fn:
                continue
            # 读选项函数特征: 只 read+转数字返回, 无业务调用
            # (handler 如 delete 也含 scanf 读参数 + free — 排除, 否则误当读选项)
            fn_end = _func_end(insns, j) or insns[-1].address
            fn_insns = [i for i in insns if read_fn <= i.address < fn_end]
            biz_calls = ('free', 'malloc', 'puts', 'printf', 'write', 'memcpy', 'strlen', 'system', 'realloc', 'calloc')
            has_biz = any(i.mnemonic == 'call'
                          and (_call_target(i, plt_map, sym_by_addr) or '') in biz_calls
                          for i in fn_insns)
            if has_biz:
                continue
            for j2, i2 in enumerate(insns):
                if i2.mnemonic != 'call' or i2.op_str.strip() != hex(read_fn):
                    continue
                if _has_chain(insns[j2 + 1:j2 + 40]):
                    main_bounds = (_func_start(insns, j2) or insns[0].address,
                                   _func_end(insns, j2) or insns[-1].address)
                    scanf_addr = insns[j2].address
                    break
            if main_bounds:
                break
    if not main_bounds:
        return out
    main_insns = [i for i in insns if main_bounds[0] <= i.address < main_bounds[1]]
    if not main_insns:
        return out

    # 1) 找菜单输入调用点 (跳过无分发链的调用 — 业务函数读参数, 非菜单)
    if scanf_addr:
        # fallback 定位的读选项调用 (地址 → main_insns 局部索引)
        for li, insn in enumerate(main_insns):
            if insn.address == scanf_addr:
                scanf_idx = li
                break
    if scanf_idx is None:
        for idx, insn in enumerate(main_insns):
            if insn.mnemonic == 'call':
                name = _call_target(insn, plt_map, sym_by_addr) or ''
                if any(k in name for k in _MENU_INPUTS):
                    tail = main_insns[idx + 1:idx + 40]
                    has_chain = any(tk.mnemonic == 'cmp' and nxt.mnemonic in ('je', 'jne')
                                    and nxt.op_str.strip().startswith('0x')
                                    for tk, nxt in zip(tail, tail[1:]))
                    if has_chain or len(main_insns) < 60:
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
            # 兼容寄存器 (cmp eax, 1) 与内存操作数 (cmp dword ptr [rbp - 4], 4)
            m = re.search(r',\s*(0x[0-9a-fA-F]+|\d+)\s*$', insn.op_str)
            if m:
                imm = m.group(1)
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
        # 无溢出函数匹配 (堆题等): 菜单结构仍识别 — options 供堆 exploit 模板 (gen_tcache_dup) 使用
        if options:
            _backfill_rodata_handlers(path, options)
            out["options"] = options
            out["present"] = True
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
    _backfill_rodata_handlers(path, options)
    out["options"] = options
    out["present"] = True
    return out
