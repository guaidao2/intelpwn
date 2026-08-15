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
                         kwargs={"open_browser": False}, daemon=True)
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

        # disasm + cfg (用列表第一个函数的十进制 start)
        st, body = _get(port, f"/api/disasm/{funcs[0]['start']}")
        assert st == 200 and json.loads(body)["lines"]
        st, body = _get(port, f"/api/cfg/{funcs[0]['start']}")
        assert st == 200
        cfg = json.loads(body)
        assert cfg["nodes"], "应有基本块"

        # hex 地址同样可解析
        st, body = _get(port, f"/api/cfg/0x{funcs[0]['start']:x}")
        assert st == 200

        # 路径穿越被拦
        st, _ = _get(port, "/static/../config.yaml")
        assert st in (403, 404)

        # 不存在的函数 → 400/错误 JSON
        st, _ = _get(port, "/api/disasm/0x999999")
        assert st in (200, 400)
