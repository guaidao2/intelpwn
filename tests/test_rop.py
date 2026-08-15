

class TestRet2Csu:
    """ret2csu / pop_pop_ret 序列识别"""

    class _I:
        def __init__(self, m, o, a=0):
            self.mnemonic, self.op_str, self.address = m, o, a

    def test_ret2csu_full_sequence(self):
        from intelpwn.core.analysis.rop import find_gadgets_capstone
        insns = [self._I("pop", "rbx", 0x1000), self._I("pop", "rbp", 0x1001),
                 self._I("pop", "r12", 0x1002), self._I("pop", "r13", 0x1003),
                 self._I("pop", "r14", 0x1004), self._I("pop", "r15", 0x1005),
                 self._I("ret", "", 0x1006)]
        r = find_gadgets_capstone(insns, 64)
        assert r["ret2csu"] == "0x1000"

    def test_ret2csu_short_sequence_no_false_positive(self):
        from intelpwn.core.analysis.rop import find_gadgets_capstone
        insns = [self._I("pop", "rbx", 0x3000), self._I("ret", "", 0x3001)]
        r = find_gadgets_capstone(insns, 64)
        assert r["ret2csu"] == "未找到"

    def test_pop_pop_ret_x86(self):
        from intelpwn.core.analysis.rop import find_gadgets_capstone
        insns = [self._I("pop", "eax", 0x2000), self._I("pop", "ebx", 0x2001),
                 self._I("ret", "", 0x2002)]
        r = find_gadgets_capstone(insns, 32)
        assert r["pop_pop_ret"] == "0x2000"
