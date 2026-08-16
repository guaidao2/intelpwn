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


class TestSemanticQueries:
    """语义查询层 (v2): 定义-使用链数据流 — 破固定窗口, 追重排/长链"""

    def _mk(self, insns):
        return [_I(a, m, o) for a, (m, o) in enumerate(insns)]

    def test_buf_chain_via_mov(self):
        """lea rax,[rbp-0x40] → (隔 150 条指令) → mov rsi,rax → call: 长链仍追到"""
        from intelpwn.core.analysis.overflow import _buf_stack_offset
        seq = [("lea", "rax, [rbp - 0x40]")] + [("nop", "")] * 150 + [("mov", "rsi, rax"), ("call", "0x10")]
        insns = self._mk(seq)
        assert _buf_stack_offset(insns, len(insns) - 1, "rsi") == 0x40

    def test_size_chain_reordered(self):
        """编译器重排: mov edx,0x100 在函数头, 中间插 50 条, 调用前才用"""
        from intelpwn.core.analysis.overflow import _size_value
        seq = [("mov", "edx, 0x100")] + [("nop", "")] * 50 + [("mov", "rdi, rax"), ("call", "0x10")]
        insns = self._mk(seq)
        assert _size_value(insns, len(insns) - 1, "rdx") == 0x100

    def test_multi_hop_mov_chain(self):
        """mov eax,ebx → mov edx,eax → call: 两级传播"""
        from intelpwn.core.analysis.overflow import _size_value
        seq = [("mov", "ebx, 0x40"), ("mov", "eax, ebx"), ("mov", "edx, eax"),
               ("mov", "rsi, rax"), ("call", "0x10")]
        insns = self._mk(seq)
        assert _size_value(insns, len(insns) - 1, "rdx") == 0x40

    def test_non_stack_buf_returns_none(self):
        """缓冲来自 [rip+chunks] (堆/全局) → 非栈 → None"""
        from intelpwn.core.analysis.overflow import _buf_stack_offset
        seq = [("mov", "rsi, qword ptr [rip + 0x2000]"), ("call", "0x10")]
        insns = self._mk(seq)
        assert _buf_stack_offset(insns, len(insns) - 1, "rsi") is None

    def test_call_breaks_backtrack(self):
        """跨调用回溯截断: lea 在 call 之前 → 不误连"""
        from intelpwn.core.analysis.overflow import _buf_stack_offset
        seq = [("lea", "rax, [rbp - 0x40]"), ("call", "0x20"), ("mov", "rsi, rax"), ("call", "0x10")]
        insns = self._mk(seq)
        assert _buf_stack_offset(insns, len(insns) - 1, "rsi") is None


class TestPaddingPrecision:
    """padding 用危险调用缓冲偏移 (非函数最大 lea) — vuln 类多 lea 场景"""

    def _mk(self, insns):
        return [_I(a, m, o) for a, (m, o) in enumerate(insns)]

    def test_padding_uses_danger_buf_off(self):
        """函数有 0x28 和 0x20 两个 lea, 危险 read 用 0x20 buf → padding 应 0x20+8"""
        from intelpwn.core.analysis.overflow import _buf_stack_offset, _size_value
        insns = self._mk([
            ("lea", "rax, [rbp - 0x28]"),   # scanf 槽 (choice)
            ("mov", "rdi, rax"),
            ("call", "0x70"),                # scanf
            ("mov", "edx, dword ptr [rbp - 0x24]"),  # size 栈变量 (非常量)
            ("lea", "rax, [rbp - 0x20]"),    # read buf
            ("mov", "rsi, rax"),
            ("mov", "edi, 0"),
            ("call", "0x60"),                # read
        ])
        buf_off = _buf_stack_offset(insns, 7, "rsi")
        assert buf_off == 0x20, f"read buf 应 0x20: {buf_off}"
        sz = _size_value(insns, 7, "rdx")
        assert sz is None, "栈变量 size 应判未知 (非常量)"
        # 端到端: 主流程 padding 用危险 buf 偏移 (0x20+8=40), 不是函数最大 lea (0x28+8=48)
        from intelpwn.core.analysis.overflow import _analyze_overflow_from_insns
        r = _analyze_overflow_from_insns(insns, 64, "x", plt_map={0x60: "read", 0x70: "scanf"})
        assert r and r[0]["calculated_padding"] == 0x20 + 8, f"padding 应 40: {r}"

    def test_padding_fallback_stack_size(self):
        """危险调用无 buf 偏移 (未知) → stack_size 兜底"""
        from intelpwn.core.analysis.overflow import _analyze_overflow_from_insns
        insns = self._mk([
            ("lea", "rax, [rbp - 0x40]"),
            ("mov", "rdi, rax"),
            ("call", "0x50"),   # gets (无界)
        ])
        r = _analyze_overflow_from_insns(insns, 64, "x", plt_map={0x50: "gets"})
        assert r and r[0]["calculated_padding"] == 0x40 + 8, f"padding 应 72: {r}"
