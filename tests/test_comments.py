"""注释引擎单元测试 — 纯函数, 无需 ELF/gdb, Windows 可跑"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intelpwn.core.analysis.comments import annotate_disasm

ENTRY = {
    "function": "vulnerable",
    "address": "0x401185",
    "dangerous_call": "read@plt",
    "call_site": "0x4011a9",
    "calculated_padding": 72,
    "stack_size": 0x20,
}

LINES = [
    {"addr": 0x401185, "mnemonic": "push", "op_str": "rbp"},
    {"addr": 0x401186, "mnemonic": "mov", "op_str": "rbp, rsp"},
    {"addr": 0x401189, "mnemonic": "sub", "op_str": "rsp, 0x20"},
    {"addr": 0x4011a0, "mnemonic": "lea", "op_str": "rsi, [rbp - 0x20]"},
    {"addr": 0x4011a4, "mnemonic": "mov", "op_str": "edx, 0x100"},
    {"addr": 0x4011a9, "mnemonic": "call", "op_str": "0x401050"},
    {"addr": 0x4011ae, "mnemonic": "test", "op_str": "rax, rax"},
    {"addr": 0x4011b1, "mnemonic": "jne", "op_str": "0x4011c0"},
    {"addr": 0x4011c0, "mnemonic": "mov", "op_str": "eax, 0x3b"},
    {"addr": 0x4011c5, "mnemonic": "syscall", "op_str": ""},
    {"addr": 0x4011c7, "mnemonic": "mov", "op_str": "rax, qword ptr fs:[0x28]"},
    {"addr": 0x4011d0, "mnemonic": "leave", "op_str": ""},
    {"addr": 0x4011d1, "mnemonic": "ret", "op_str": ""},
]

SYM = {0x401050: "read@plt", 0x401040: "system@plt", 0x4011c0: "win"}


def _by_addr(notes, addr):
    for n in notes:
        if n["addr"] == addr:
            return n
    return None


def test_red_call_site():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011a9)
    assert n["note_level"] == "red"
    assert "危险输入点" in n["note"] and "72" in n["note"]


def test_red_buffer_lea():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011a0)
    assert n["note_level"] == "red"
    assert "缓冲 0x20" in n["note"]


def test_spaced_buf_ref_real_capstone():
    """回归: Capstone x86 Intel 实际输出带空格 [rbp - 0x20] (原正则不匹配 → 注释死代码)"""
    lines = [
        {"addr": 0x10, "mnemonic": "lea", "op_str": "rsi, [rbp - 0x20]"},
        {"addr": 0x14, "mnemonic": "mov", "op_str": "edx, 0x100"},
        {"addr": 0x19, "mnemonic": "call", "op_str": "0x401050"},
    ]
    entry = {"call_site": "0x19", "calculated_padding": 72, "stack_size": 0x20, "function": "f"}
    out = annotate_disasm(lines, entry, SYM)
    assert _by_addr(out, 0x10)["note_level"] == "red"
    assert "缓冲 0x20" in _by_addr(out, 0x10)["note"]


def test_red_size_overflow():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011a4)
    assert n["note_level"] == "red"
    assert "可溢出 224" in n["note"]


def test_red_ret():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011d1)
    assert n["note_level"] == "red"
    assert "返回地址可被溢出改写" in n["note"]


def test_yellow_syscall_execve():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011c0)
    assert n["note_level"] == "yellow"
    assert "execve" in n["note"]


def test_yellow_syscall_insn():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011c5)
    assert n["note_level"] == "yellow"


def test_yellow_canary():
    out = annotate_disasm(LINES, ENTRY, SYM)
    n = _by_addr(out, 0x4011c7)
    assert n["note_level"] == "yellow"
    assert "canary" in n["note"]


def test_yellow_sensitive_call():
    # system 调用 → 黄
    lines = [{"addr": 0x10, "mnemonic": "call", "op_str": "0x401040"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note_level"] == "yellow"
    assert "system" in out[0]["note"]


def test_gray_prologue_and_frame():
    out = annotate_disasm(LINES, ENTRY, SYM)
    assert _by_addr(out, 0x401185)["note_level"] == "gray"      # push rbp
    assert _by_addr(out, 0x401186)["note_level"] == "gray"      # mov rbp, rsp
    assert _by_addr(out, 0x401189)["note_level"] == "gray"      # sub rsp
    assert "分配栈空间" in _by_addr(out, 0x401189)["note"]


def test_gray_leave():
    out = annotate_disasm(LINES, ENTRY, SYM)
    assert _by_addr(out, 0x4011d0)["note_level"] == "gray"
    assert "恢复栈帧" in _by_addr(out, 0x4011d0)["note"]


def test_gray_call_resolution():
    lines = [{"addr": 0x10, "mnemonic": "call", "op_str": "0x401050"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note_level"] == "gray"
    # sym_map 含 @plt 后缀时显示去重: "call read" (不出现 read@plt@plt)
    assert out[0]["note"] == "call read"


def test_gray_xor_zero():
    lines = [{"addr": 0x10, "mnemonic": "xor", "op_str": "eax, eax"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note_level"] == "gray"
    assert "清零" in out[0]["note"]


def test_gray_endbr64():
    lines = [{"addr": 0x10, "mnemonic": "endbr64", "op_str": ""}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note_level"] == "gray"


def test_no_entry_no_red():
    out = annotate_disasm(LINES, None, SYM)
    assert all(n["note_level"] != "red" for n in out)
    # 无漏洞上下文时 call 不标红
    assert _by_addr(out, 0x4011a9)["note_level"] == "gray"


def test_red_ret_only_epilogue():
    """多返回值函数: 只有尾声 ret 标红, 中间 ret 不标"""
    lines = [
        {"addr": 0x10, "mnemonic": "mov", "op_str": "edi, 0"},
        {"addr": 0x12, "mnemonic": "call", "op_str": "0x401050"},
        {"addr": 0x15, "mnemonic": "ret", "op_str": ""},
        {"addr": 0x20, "mnemonic": "mov", "op_str": "eax, 0"},
        {"addr": 0x22, "mnemonic": "ret", "op_str": ""},
    ]
    entry = {"call_site": "0x12", "calculated_padding": 72, "stack_size": 0x20, "function": "f"}
    out = annotate_disasm(lines, entry, SYM)
    assert _by_addr(out, 0x15)["note_level"] is None
    assert _by_addr(out, 0x22)["note_level"] == "red"


def test_indirect_call_no_resolve():
    """间接调用 (含 []) 不解析目标, 也不报灰"""
    lines = [{"addr": 0x10, "mnemonic": "call", "op_str": "qword ptr [rip + 0x2000]"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note"] is None


def test_lea_wrong_dest_reg_not_annotated():
    """目标寄存器不是缓冲寄存器时 (read → 应为 rsi), lea 不标红"""
    lines = [
        {"addr": 0x10, "mnemonic": "lea", "op_str": "rdi, [rbp - 0x20]"},
        {"addr": 0x14, "mnemonic": "mov", "op_str": "edx, 0x100"},
        {"addr": 0x19, "mnemonic": "call", "op_str": "0x401050"},
    ]
    entry = {"call_site": "0x19", "calculated_padding": 72, "stack_size": 0x20, "function": "f"}
    out = annotate_disasm(lines, entry, SYM)
    assert _by_addr(out, 0x10)["note_level"] is None


def test_unrelated_no_note():
    lines = [{"addr": 0x10, "mnemonic": "mov", "op_str": "edi, 0x7fff"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note"] is None
