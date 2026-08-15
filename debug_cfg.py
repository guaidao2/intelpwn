#!/usr/bin/env python3
"""调试: CFG 标记块为何不含 call"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from intelpwn.core.analysis.cfg import build_function_cfg
from intelpwn.core.analysis.overflow import disassemble_text
from intelpwn.utils.binary import open_elf

BIN = "challenges/challenge_ret2win"
start = end = None
with open_elf(BIN) as elf:
    symtab = elf.get_section_by_name('.symtab')
    for sym in symtab.iter_symbols():
        if sym.name == 'vulnerable' and sym['st_info']['type'] == 'STT_FUNC':
            start, end = sym['st_value'], sym['st_value'] + sym['st_size']
print("func range:", hex(start), hex(end))
pre = disassemble_text(BIN)
print("disassemble_text 返回类型:", type(pre), "长度:", len(pre) if pre else None)
insns, bits = pre[0], pre[1]
calls = [i.address for i in insns if start <= i.address < end and i.mnemonic == 'call']
print("calls:", [hex(c) for c in calls])
cfg = build_function_cfg(BIN, start, end, mark_addrs=[calls[0]])
print("marked:", cfg["marked"])
for n in cfg["nodes"]:
    addrs = [i["addr"] for i in n["insns"]]
    print("block", n["id"], hex(n["start"]), "->", hex(n["end"]), "insns:", [hex(a) for a in addrs][:4])
