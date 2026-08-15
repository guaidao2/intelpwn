"""函数调用图单元测试 — 纯 pyelftools/capstone, Windows 可跑"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelpwn.core.analysis.callgraph import build_call_graph

BIN = "challenges/challenge_ret2win"


def test_basic_graph():
    g = build_call_graph(BIN)
    assert g["error"] is None
    assert g["nodes"], "应有函数节点"
    assert g["edges"], "应有调用边"


def test_vuln_and_danger_marked():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable",
                             "dangerous_call": "read@plt"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n for n in g["nodes"]}
    assert by_name["vulnerable"]["vuln"] is True
    assert by_name["read@plt"]["danger"] is True  # 敏感 PLT
    assert by_name["main"]["entry"] is True


def test_attack_path():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n for n in g["nodes"]}
    # vulnerable 沿入边反向可达: main → vulnerable → read@plt 全在攻击路径上
    assert by_name["vulnerable"]["on_path"] is True
    assert by_name["main"]["on_path"] is True
    assert by_name["read@plt"]["on_path"] is True


def test_edge_main_to_vulnerable():
    results = {"overflow": [{"address": "0x401185", "function": "vulnerable"}]}
    g = build_call_graph(BIN, results=results)
    by_name = {n["name"]: n["id"] for n in g["nodes"]}
    edge_set = {(e["source"], e["target"]) for e in g["edges"]}
    assert (by_name["main"], by_name["vulnerable"]) in edge_set, "main 应调用 vulnerable"
