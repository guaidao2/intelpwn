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
    {"addr": 0x4011a0, "mnemonic": "lea", "op_str": "rsi, [rbp-0x20]"},
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
    assert "read@plt" in out[0]["note"]


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


def test_unrelated_no_note():
    lines = [{"addr": 0x10, "mnemonic": "mov", "op_str": "edi, 0x7fff"}]
    out = annotate_disasm(lines, None, SYM)
    assert out[0]["note"] is None
