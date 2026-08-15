"""单元测试 — CFG 基本块构建 (--web 可视化数据源, 纯 pyelftools+capstone)"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.cfg import build_function_cfg
from intelpwn.core.analysis.overflow import disassemble_text
from intelpwn.utils.binary import open_elf

BIN = "challenges/challenge_ret2win"


def _func_range():
    with open_elf(BIN) as elf:
        symtab = elf.get_section_by_name('.symtab')
        for sym in symtab.iter_symbols():
            if sym.name == 'vulnerable' and sym['st_info']['type'] == 'STT_FUNC':
                return sym['st_value'], sym['st_value'] + sym['st_size']
    raise AssertionError("未找到 vulnerable 符号")


def _first_call_in_func(start, end):
    pre = disassemble_text(BIN)
    insns = pre[0] if pre else []
    for i in insns:
        if start <= i.address < end and i.mnemonic == 'call':
            return i.address
    raise AssertionError("函数内无 call 指令")


class TestBuildFunctionCfg:
    def test_builds_blocks_and_edges(self):
        """ret2win 的 vulnerable 函数应产出基本块 + 边"""
        start, end = _func_range()
        cfg = build_function_cfg(BIN, start, end)
        assert cfg["nodes"], "应有基本块"
        assert cfg["edges"], "应有边"

    def test_marked_block_contains_call(self):
        """标记地址所在块应包含该地址的指令"""
        start, end = _func_range()
        call_addr = _first_call_in_func(start, end)
        cfg = build_function_cfg(BIN, start, end, mark_addrs=[call_addr])
        assert cfg["marked"], "call 所在块应被标记"
        marked_id = cfg["marked"][0]
        node = cfg["nodes"][marked_id]
        addrs = {i["addr"] for i in node["insns"]}
        assert call_addr in addrs

    def test_edges_target_existing_nodes(self):
        """边两端都应指向存在的块"""
        start, end = _func_range()
        cfg = build_function_cfg(BIN, start, end)
        ids = {n["id"] for n in cfg["nodes"]}
        for a, b in cfg["edges"]:
            assert a in ids and b in ids
