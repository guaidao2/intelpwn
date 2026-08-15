"""CET (SHSTK/IBT) 检测测试 — 纯解析, Windows 可跑"""

import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.protections import (cet_properties, analyze_protections,
    GNU_PROPERTY_X86_FEATURE_1_AND, GNU_PROPERTY_X86_FEATURE_1_IBT, GNU_PROPERTY_X86_FEATURE_1_SHSTK)


def _make_property_data(feature_flags):
    """构造 .note.gnu.property 段数据 (namesz=4 descsz=16 type=0x04)"""
    name = b"GNU"
    prop_data = struct.pack('<II', GNU_PROPERTY_X86_FEATURE_1_AND, 4) + struct.pack('<I', feature_flags)
    note = struct.pack('<III', len(name), len(prop_data), 0x05) + name  # NT_GNU_PROPERTY_TYPE_0
    note += b"\x00" * ((4 - (len(name) % 4)) % 4)  # name 对齐
    note += prop_data
    return note


def test_no_property_section():
    """无 .note.gnu.property → 全 False"""
    r = cet_properties("challenges/challenge_ret2win")
    assert r == {"ibt": False, "shstk": False}


def test_parse_shstk_ibt_flags():
    """解析标志: bit0=IBT, bit1=SHSTK (x86-64/x86 共用类型号)"""
    from intelpwn.core.analysis.protections import _parse_property_data
    assert GNU_PROPERTY_X86_FEATURE_1_SHSTK == 2
    assert GNU_PROPERTY_X86_FEATURE_1_IBT == 1
    assert GNU_PROPERTY_X86_FEATURE_1_AND == 0xc0000002

    r_shstk = _parse_property_data(_make_property_data(GNU_PROPERTY_X86_FEATURE_1_SHSTK))
    assert r_shstk == {"ibt": False, "shstk": True}
    r_ibt = _parse_property_data(_make_property_data(GNU_PROPERTY_X86_FEATURE_1_IBT))
    assert r_ibt == {"ibt": True, "shstk": False}
    r_both = _parse_property_data(_make_property_data(GNU_PROPERTY_X86_FEATURE_1_SHSTK | GNU_PROPERTY_X86_FEATURE_1_IBT))
    assert r_both == {"ibt": True, "shstk": True}


def test_analyze_protections_has_cet_fields():
    """analyze_protections 返回 shstk/ibt/cet 字段 (64 位 + 32 位靶子)"""
    for b in ("challenges/challenge_ret2win", "challenges/challenge_x86_vuln"):
        p = analyze_protections(b)
        assert "shstk" in p and "ibt" in p and "cet" in p
        assert p["cet"] == (p["shstk"] or p["ibt"])
