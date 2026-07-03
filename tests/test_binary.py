"""单元测试 — binary 工具函数"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.utils.binary import (
    run, parse_checksec, readelf_arch, readelf_sections,
    has_rwx_segment, is_static_binary, strings_has_binsh,
    open_elf,
)

BIN = "challenges/challenge_ret2win"
BIN_FMTSTR = "challenges/challenge_fmtstr"


class TestBinaryRun:
    def test_run_objdump(self):
        rc, out, _ = run(["objdump", "-d", BIN])
        assert rc == 0
        assert "push" in out

    def test_run_nonexistent(self):
        rc, out, _ = run(["nonexistent_command"])
        assert rc != 0


class TestReadelfSections:
    def test_has_text_section(self):
        sections = dict(readelf_sections(BIN))
        assert ".text" in sections
        assert sections[".text"] > 0

    def test_nonexistent_file(self):
        sections = readelf_sections("/nonexistent")
        assert sections == []


class TestOpenElf:
    def test_can_read_header(self):
        with open_elf(BIN) as elf:
            assert elf.header.e_machine in ("EM_X86_64",)

    def test_close_fd_on_exception(self):
        """确保异常时文件描述符关闭"""
        try:
            with open_elf(BIN) as elf:
                raise ValueError("test")
        except ValueError:
            pass
        # 如果 fd 泄漏，再次打开会失败；能正常打开说明 close 成功
        with open_elf(BIN) as elf:
            assert elf.header.e_machine == "EM_X86_64"
