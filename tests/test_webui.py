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
            return
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


def test_sym_map_for_plt_resolution():
    """PLT stub 解析: read@plt 应在 sym_map 中 (symtab 无此条目, 经 _build_plt_map 解析)"""
    from intelpwn.core.webui import _sym_map_for
    m = _sym_map_for("challenges/challenge_ret2win")
    assert 0x401185 in m and m[0x401185] == "vulnerable"  # symtab 符号仍在
    assert m.get(0x401050) == "read@plt"                  # PLT stub → read@plt
