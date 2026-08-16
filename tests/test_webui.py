"""单元测试 — --web 可视化服务冒烟 (起服务打 API, 纯 pyelftools 无 pwn 依赖)"""

import http.client
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

BIN = "challenges/challenge_ret2win"


def _start_server(results, port=5099):
    from intelpwn.core.webui import serve
    t = threading.Thread(target=serve, args=(results, BIN, "127.0.0.1", port),
                         kwargs={"explicit_port": True, "open_browser": False},
                         daemon=True)
    t.start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return t
        except OSError:
            time.sleep(0.1)
    raise AssertionError("服务未启动")


def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, body


class TestWebUI:
    def test_apis_and_static(self):
        results = {"overflow": [], "path": BIN}
        port = 5099
        _start_server(results, port)

        # 静态资源
        assert _get(port, "/")[0] == 200
        assert _get(port, "/static/app.js")[0] == 200
        assert _get(port, "/static/cytoscape.min.js")[0] == 200

        # 报告 + 函数
        st, body = _get(port, "/api/report")
        assert st == 200 and json.loads(body)["path"] == BIN
        st, body = _get(port, "/api/functions")
        assert st == 200
        funcs = json.loads(body)
        assert funcs, "应有函数列表"

        # 调用图 (全局关系) — 空 results 下只断言结构 + 不依赖结果的标注
        st, body = _get(port, "/api/callgraph")
        assert st == 200
        cg = json.loads(body)
        assert cg["nodes"] and cg["edges"], "调用图应有节点和边"
        by_name = {n["name"]: n for n in cg["nodes"]}
        assert by_name["read@plt"]["danger"], "read@plt 应标为危险调用目标 (PLT 名判定, 不依赖 results)"
        assert any(n["entry"] for n in cg["nodes"]), "应有入口函数"

        # disasm + cfg: 找一个在 .text 里确实有指令的函数 (跳过 _init 等段外符号)
        target = None
        for f in funcs:
            st, body = _get(port, f"/api/disasm/{f['start']}")
            if st == 200 and json.loads(body).get("lines"):
                target = f["start"]
                break
        assert target is not None, "应在 .text 找到可反汇编的函数"

        st, body = _get(port, f"/api/cfg/{target}")
        assert st == 200
        cfg = json.loads(body)
        assert cfg["nodes"], "应有基本块"

        # hex 地址同样可解析
        st, body = _get(port, f"/api/cfg/0x{target:x}")
        assert st == 200

        # 路径穿越被拦
        st, _ = _get(port, "/static/../config.yaml")
        assert st in (403, 404)

        # 不存在的函数 → 400/错误 JSON
        st, _ = _get(port, "/api/disasm/0x999999")
        assert st in (200, 400)

    def test_api_report_with_shared_blackboard(self):
        """analyze_all 真实 results 含黑板缓存 _shared (capstone insns 不可序列化) — /api/report 不得 500"""
        results = {"overflow": [], "path": BIN, "_shared": {"insns": ["<capstone object>"], "func_bounds": []}}
        port = 5101
        _start_server(results, port)
        st, body = _get(port, "/api/report")
        assert st == 200, f"/api/report 应 200, 实际 {st}: {body[:100]}"
        data = json.loads(body)
        assert "_shared" not in data, "_shared 不应出现在 API 响应"
        assert data["path"] == BIN


def test_sym_map_for_plt_resolution():
    """PLT stub 解析: read@plt 应在 sym_map 中 (symtab 无此条目, 经 _build_plt_map 解析)"""
    from intelpwn.core.webui import _sym_map_for
    m = _sym_map_for("challenges/challenge_ret2win")
    assert 0x401185 in m and m[0x401185] == "vulnerable"  # symtab 符号仍在
    assert m.get(0x401050) == "read@plt"                  # PLT stub → read@plt


def test_anonymous_funcs_stripped_fallback():
    """stripped (无符号表) 场景: _anonymous_funcs 从 .text 切分, 每个函数可反汇编"""
    from intelpwn.core.analysis.overflow import disassemble_text
    from intelpwn.core.webui import _anonymous_funcs
    pre = disassemble_text(BIN)
    assert pre, "应能反汇编"
    fns = _anonymous_funcs(pre[0])
    assert fns, "stripped fallback 应生成匿名函数"
    for s, e, n in fns[:2]:
        cnt = sum(1 for i in pre[0] if s <= i.address < e)
        assert cnt > 0, f"{n} 无 .text 指令"


def test_api_functions_filters_non_text():
    """_api_functions 只列 .text 内函数 (防御 st_size>0 的 _init/_fini 等)"""
    from intelpwn.core.webui import _Handler, _func_bounds
    h = _Handler.__new__(_Handler)
    h.binary = BIN
    h.results = {"overflow": []}
    fns = h._api_functions()
    assert fns, "应有函数"
    from intelpwn.core.analysis.overflow import disassemble_text
    pre = disassemble_text(BIN)
    insns = pre[0]
    for f in fns:
        assert insns[0].address <= f["start"] < insns[-1].address + 1, \
            f"{f['name']} 不在 .text 范围"


def test_stripped_e2e_functions_disasm_cfg():
    """stripped (无符号表) 端到端: /api/functions 每个函数在 disasm/cfg 可解"""
    import intelpwn.core.webui as webui
    from intelpwn.core.webui import _Handler
    orig = webui._func_bounds
    try:
        webui._func_bounds = lambda path: []  # 模拟 stripped
        h = _Handler.__new__(_Handler)
        h.binary = BIN
        h.results = {"overflow": []}
        fns = h._api_functions()
        assert fns, "stripped 应有匿名函数列表"
        for f in fns:
            d = h._api_disasm(f["start"])
            assert not d.get("error"), f"{f['name']} disasm: {d.get('error')}"
            c = h._api_cfg(f["start"])
            assert not c.get("error"), f"{f['name']} cfg: {c.get('error')}"
    finally:
        webui._func_bounds = orig


def test_shutdown_endpoint_stops_server():
    """/api/shutdown 一键停止 (Ctrl-C 失效兜底): GET 后服务退出, 端口关闭"""
    import http.client
    results = {"overflow": [], "path": BIN}
    port = 5103
    t = _start_server(results, port)
    # 服务就绪
    for _ in range(50):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/api/report"); r = c.getresponse(); c.close()
            assert r.status == 200
            break
        except OSError:
            time.sleep(0.2)
    # 触发 shutdown
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    c.request("GET", "/api/shutdown"); r = c.getresponse()
    body = r.read(); c.close()
    assert r.status == 200 and b"ok" in body
    # 服务应退出 (serve 线程结束)
    t.join(timeout=6)
    assert not t.is_alive(), "shutdown 后 serve 线程未退出"
    # 端口应关闭
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        c.request("GET", "/api/report")
        assert False, "服务应已停止"
    except OSError:
        pass
