"""单元测试 — 栈溢出检测"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.overflow import analyze_assembly_overflow

BIN = "challenges/challenge_ret2win"


class TestAnalyzeOverflow:
    def test_detects_overflow(self):
        """challenge_ret2win 应有明显的栈溢出"""
        results = analyze_assembly_overflow(BIN)
        assert len(results) > 0, "应该检测到栈溢出"

    def test_padding_is_72(self):
        """ret2win 的标准 padding 是 72 (0x40 栈 + 8 rbp)"""
        results = analyze_assembly_overflow(BIN)
        assert results[0]["calculated_padding"] == 72

    def test_function_name(self):
        results = analyze_assembly_overflow(BIN)
        assert results[0]["function"] in ("vulnerable", "main")

    def test_stack_size(self):
        results = analyze_assembly_overflow(BIN)
        assert results[0]["stack_size"] == 64  # 0x40


class _I:
    def __init__(self, addr, mnemonic, op_str):
        self.address, self.mnemonic, self.op_str = addr, mnemonic, op_str


class TestStackBufPassed:
    """x86 32 位 cdecl 栈参数传递检测"""

    def _f(self, insns, call_idx):
        from intelpwn.core.analysis.overflow import _stack_buf_passed
        return _stack_buf_passed(insns, call_idx)

    def test_lea_push_detected(self):
        """lea eax,[ebp-0x28]; push eax; call gets → 栈链接"""
        insns = [_I(0, "lea", "eax, [ebp-0x28]"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is True

    def test_lea_mov_esp_detected(self):
        """lea eax,[ebp-0x28]; mov [esp],eax; call gets → 栈链接"""
        insns = [_I(0, "lea", "eax, [ebp-0x28]"),
                 _I(1, "mov", "[esp], eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is True

    def test_ebp_plus8_param_not_buffer(self):
        """lea eax,[ebp+8] 是参数装载, 不是栈缓冲 → 不判链接"""
        insns = [_I(0, "lea", "eax, [ebp+8]"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is False

    def test_no_stack_lea(self):
        """没有 lea [ebp-X] → 不判链接"""
        insns = [_I(0, "mov", "eax, 0x804a000"),
                 _I(1, "push", "eax"),
                 _I(2, "call", "gets")]
        assert self._f(insns, 2) is False


class TestResolveScanf32:
    """32 位 scanf 格式串解析 (push imm / mov [esp],imm)"""

    def test_push_imm(self):
        from intelpwn.core.analysis.overflow import _resolve_scanf_format
        win = [_I(0, "push", "0xdead0000"), _I(1, "call", "scanf")]
        # 0xdead0000 不落在任何 PT_LOAD → 返回空 (toolchain 无关)
        r = _resolve_scanf_format("challenges/challenge_x86_vuln", win, 32)
        assert r == ""

    def test_mov_esp_imm_takes_comma_value(self):
        """mov dword ptr [esp + 0x4], <rodata vaddr> → 应取逗号后的值 (映射出 Input)

        旧解析取第一个 0x (槽位移 0x4, 不映射 → 空); 新解析取逗号后的 vaddr → "Input"。
        此断言真正区分新旧解析。
        """
        from intelpwn.utils.binary import open_elf
        from intelpwn.core.analysis.overflow import _resolve_scanf_format
        vaddr = None
        with open_elf("challenges/challenge_x86_vuln") as elf:
            sec = elf.get_section_by_name('.rodata')
            if sec:
                idx = sec.data().find(b'Input:')
                if idx >= 0:
                    vaddr = sec['sh_addr'] + idx
        if vaddr is None:
            return
        win = [_I(0, "mov", f"dword ptr [esp + 0x4], 0x{vaddr:x}"), _I(1, "call", "scanf")]
        r = _resolve_scanf_format("challenges/challenge_x86_vuln", win, 32)
        assert "Input" in r


class TestMovEspPrefixed:
    """capstone 尺寸前缀形式: mov dword ptr [esp], eax 也能判栈链接"""

    def test_prefixed_mov_esp(self):
        from intelpwn.core.analysis.overflow import _stack_buf_passed
        insns = [_I(0, "lea", "eax, [ebp-0x28]"),
                 _I(1, "mov", "dword ptr [esp], eax"),
                 _I(2, "call", "gets")]
        assert _stack_buf_passed(insns, 2) is True


class TestScanfVaddrToOffset:
    """vaddr → 文件偏移映射: 真实 .rodata vaddr 应解析出字符串 (钉住修复)"""

    def test_rodata_vaddr_resolves(self):
        from intelpwn.utils.binary import open_elf
        from intelpwn.core.analysis.overflow import _resolve_scanf_format
        vaddr = None
        with open_elf("challenges/challenge_x86_vuln") as elf:
            sec = elf.get_section_by_name('.rodata')
            if sec:
                data = sec.data()
                idx = data.find(b'Input:')
                if idx >= 0:
                    vaddr = sec['sh_addr'] + idx
        if vaddr is None:
            return  # 无 .rodata/字符串则跳过
        win = [_I(0, "mov", f"dword ptr [esp], 0x{vaddr:x}"), _I(1, "call", "scanf")]
        r = _resolve_scanf_format("challenges/challenge_x86_vuln", win, 32)
        assert "Input" in r, f"应解析出 .rodata 字符串, 实际 {r!r}"
