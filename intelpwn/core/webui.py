"""--web 本地可视化服务 (CTF 分析工具)

- 监听 0.0.0.0 (Kali VM 上跑, 宿主机浏览器可访问 VM IP)
- 默认端口 5000, 被占自动 +1 递增; --web-port 显式指定则严格使用
- JSON API + 静态单页前端 (cytoscape 交互式 CFG 图)

API:
  /                     → index.html
  /static/<file>        → 静态资源 (js/css)
  /api/report           → 完整分析结果
  /api/functions        → 函数列表 + 漏洞标记
  /api/disasm/<addr>    → 函数反汇编 (带高亮标记)
  /api/cfg/<addr>       → 函数基本块 CFG (标记块)
"""

import json
import logging
import os
import re
import signal
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from intelpwn.utils.binary import open_elf
from .analysis.overflow import disassemble_text
from .analysis.cfg import build_function_cfg

WEBUI_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "webui", "static")

# 每二进制缓存: 反汇编 + 函数边界 (防 LAN 并发请求反复重算拖垮 CPU)
_disas_cache = {}
_bounds_cache = {}
_sym_map_cache = {}
_disas_lock = threading.Lock()
_bounds_lock = threading.Lock()
_sym_lock = threading.Lock()
# 并发上限: 避免无界线程耗尽资源
_heavy_sem = threading.Semaphore(4)

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".map": "application/json",
}


def _func_bounds(path):
    """符号表函数边界 [(start, end, name)] — 缓存"""
    if path in _bounds_cache:
        return _bounds_cache[path]
    with _bounds_lock:
        if path in _bounds_cache:
            return _bounds_cache[path]
        funcs = []
        try:
            with open_elf(path) as elf:
                symtab = elf.get_section_by_name(".symtab")
                if symtab:
                    for sym in symtab.iter_symbols():
                        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                            funcs.append((sym['st_value'], sym['st_value'] + sym['st_size'], sym.name))
        except Exception:
            pass
        _bounds_cache[path] = funcs
        return funcs


def _anonymous_funcs(insns):
    """stripped (无符号表) 时从 .text 指令按函数启发切分: endbr64 / 函数尾 (ret) 后边界"""
    funcs = []
    cur_start = insns[0].address if insns else None
    for k, insn in enumerate(insns):
        is_boundary = False
        if insn.mnemonic == 'endbr64':
            is_boundary = True
        elif insn.mnemonic == 'ret' and k + 1 < len(insns):
            nxt = insns[k + 1]
            if nxt.address - (insn.address + insn.size) > 4:  # ret 后有 padding → 函数尾
                is_boundary = True
        if is_boundary and cur_start is not None and insn.address > cur_start:
            funcs.append((cur_start, insn.address, "func_%x" % cur_start))
            cur_start = insn.address
    if cur_start is not None and insns:
        funcs.append((cur_start, insns[-1].address + 1, "func_%x" % cur_start))
    return funcs


def _sym_map_for(path):
    """符号表 {addr: 函数名} — 按二进制缓存. 含 PLT stub 解析 (symtab 无 read@plt 类条目).

    PLT 解析复用 win_targets._build_plt_map (pyelftools, 支持 .rela.plt/.rel.plt/.plt.sec,
    跨平台无 pwntools 依赖).
    """
    with _sym_lock:
        if path in _sym_map_cache:
            return _sym_map_cache[path]
    smap = {}
    try:
        with open_elf(path) as elf:
            for sec_name in ('.symtab', '.dynsym'):
                sec = elf.get_section_by_name(sec_name)
                if sec:
                    for sym in sec.iter_symbols():
                        if sym.name and sym['st_info']['type'] == 'STT_FUNC':
                            smap[sym['st_value']] = sym.name
            bits = 32 if elf.elfclass == 32 else 64
        from intelpwn.core.analysis.win_targets import _build_plt_map
        for stub, name in _build_plt_map(path, bits).items():
            smap[stub] = name + "@plt"
    except Exception as e:  # PLT 解析失败会丢 call 注释 — 记日志而非静默
        logging.getLogger("intelpwn").warning("符号表/PLT 解析失败 %s: %s", path, e)
    with _sym_lock:
        _sym_map_cache[path] = smap
    return smap


def _get_disas(path):
    """共享反汇编 (缓存, 防并发重复计算)"""
    if path in _disas_cache:
        return _disas_cache[path]
    with _disas_lock:
        if path in _disas_cache:
            return _disas_cache[path]
        pre = disassemble_text(path)
        _disas_cache[path] = pre
        return pre


def _parse_call_addr(dangerous_call):
    m = re.search(r'0x[0-9a-fA-F]+', dangerous_call or "")
    return int(m.group(0), 16) if m else None


def _vuln_call_site(v) -> int:
    """漏洞条目 → 调用点地址 (call_site 优先, 回退解析 dangerous_call 目标)"""
    cs = v.get("call_site")
    if cs:
        try:
            return int(cs, 16)
        except (TypeError, ValueError):
            pass
    return _parse_call_addr(v.get("dangerous_call"))


def _resolve_func_addr(raw: str, binary: str):
    """地址解析: 前端发十进制; 仅当字符串形如 hex (0x 前缀或含 a-f) 才按 hex 解析"""
    # 用 .text 内函数边界 (含 stripped 匿名函数) 消歧 — 与 _api_functions 一致
    from intelpwn.core.webui import _Handler
    h = _Handler.__new__(_Handler)
    h.binary = binary
    bounds = {s: e for s, e, _ in h._api_bounds()}
    stripped = raw.strip()
    candidates = []
    if stripped.lower().startswith("0x") or any(ch in "abcdefABCDEF" for ch in stripped):
        try:
            candidates.append(int(stripped, 16))
        except ValueError:
            pass
    try:
        candidates.append(int(stripped, 10))
    except ValueError:
        pass
    for a in candidates:
        if a in bounds:
            return a
    return candidates[0] if candidates else None


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.0: 每请求后关闭连接 → handler 线程不被 keep-alive 永久 park,
    # Ctrl-C 时 server_close() 的 join 能立即返回 (HTTP/1.1 keep-alive 会让
    # 浏览器连接常驻, 线程阻塞在 recv 导致进程杀不掉)
    protocol_version = "HTTP/1.0"
    results = {}
    binary = ""

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path == "/":
                self._serve_static("index.html")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
            elif path == "/api/report":
                self._json(self.results)
            elif path == "/api/functions":
                with _heavy_sem:
                    self._json(self._api_functions())
            elif path.startswith("/api/disasm/"):
                with _heavy_sem:
                    self._json(self._api_disasm(_resolve_func_addr(path[len("/api/disasm/"):], self.binary)))
            elif path.startswith("/api/cfg/"):
                with _heavy_sem:
                    self._json(self._api_cfg(_resolve_func_addr(path[len("/api/cfg/"):], self.binary)))
            elif path == "/api/callgraph":
                with _heavy_sem:
                    self._json(self._api_callgraph())
            elif path == "/api/shutdown":
                # 浏览器一键停止 (Ctrl-C 失效场景的兜底出口)
                self._json({"ok": True, "note": "服务正在停止"})
                threading.Thread(target=_shutdown_server, daemon=True).start()
            else:
                self.send_error(404)
        except (ValueError, IndexError):
            self.send_error(400)
        except Exception:
            self.send_error(500)

    # ── API 实现 ─────────────────────────────────────────────

    def _api_bounds(self):
        """函数边界: 符号表优先; stripped (无符号表) 回退匿名函数切分.
        _api_functions/_api_disasm/_api_cfg 共用, 保证列表与反汇编一致"""
        bounds = _func_bounds(self.binary)
        if not bounds:
            pre = _get_disas(self.binary)
            if pre and pre[0]:
                bounds = _anonymous_funcs(pre[0])
        return bounds

    def _api_functions(self):
        """函数列表 + 漏洞标记 (溢出调用点地址)

        只列 .text 内的函数 — 符号表含 _init/_fini (在 .init/.fini 段) 等
        无 .text 指令的符号, 前端默认选中会渲染空白。
        stripped (无符号表) 时从 .text 反汇编按函数启发切分匿名函数。
        """
        pre = _get_disas(self.binary)
        text_range = None
        insns = None
        if pre and pre[0]:
            insns = pre[0]
            text_range = (insns[0].address, insns[-1].address + 1)
        funcs = []
        bounds = self._api_bounds()
        for start, end, name in bounds:
            if text_range and not (text_range[0] <= start < text_range[1]):
                continue  # 不在 .text (如 _init/.fini/PLT stub) — 不可反汇编
            funcs.append({"name": name, "start": start, "end": end})
        vuln_map = {}
        for v in self.results.get("overflow", []):
            try:
                vuln_map[int(v.get("address", "0x0"), 16)] = v
            except ValueError:
                pass
        for f in funcs:
            v = vuln_map.get(f["start"])
            f["vuln"] = bool(v)
            f["padding"] = v.get("calculated_padding") if v else None
            f["call_addr"] = _parse_call_addr(v.get("dangerous_call")) if v else None
        return funcs

    def _api_disasm(self, func_addr):
        """函数反汇编, 高亮标记 + 三级自动注释 (漏洞链/风险/语义)"""
        bounds = {s: e for s, e, _ in self._api_bounds()}
        end = bounds.get(func_addr)
        if not end:
            return {"error": "函数不存在"}
        entry = None
        for v in self.results.get("overflow", []):
            try:
                if int(v.get("address", "0x0"), 16) == func_addr:
                    entry = v
                    break
            except ValueError:
                pass
        pre = _get_disas(self.binary)
        if not pre:
            return {"error": "反汇编失败"}
        insns, bits = pre[0], pre[1]
        ins = [i for i in insns if func_addr <= i.address < end]
        if not ins:
            return {"error": "该函数无 .text 指令 (可能位于 .init/.fini/PLT 段)",
                    "function": func_addr, "lines": []}
        lines = []
        for i in ins:
            lines.append({
                "addr": i.address,
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "mark": i.address == _vuln_call_site(entry) if entry else False,
                "lea_stack": i.mnemonic == 'lea' and ('rbp' in i.op_str or 'ebp' in i.op_str),
                "call": i.mnemonic == 'call',
            })
        # 三级自动注释
        try:
            from intelpwn.core.analysis.comments import annotate_disasm
            sym_map = _sym_map_for(self.binary)
            bits = pre[1] if pre else 64
            lines = annotate_disasm(lines, entry, sym_map, bits=bits)
        except Exception as e:  # 注释引擎失败不阻断反汇编 — 记日志
            logging.getLogger("intelpwn").warning("注释引擎异常: %s", e)
            for ln in lines:
                ln.setdefault("note", None)
                ln.setdefault("note_level", None)
        return {"function": func_addr, "lines": lines}

    def _api_callgraph(self):
        """全二进制函数调用图 (全局关系分析) — 复用缓存的函数边界/符号表/反汇编"""
        from intelpwn.core.analysis.callgraph import build_call_graph
        pre = _get_disas(self.binary)
        insns = pre[0] if pre else None
        bits = pre[1] if pre else None
        return build_call_graph(self.binary, results=self.results,
                                func_bounds=_func_bounds(self.binary),
                                sym_map=_sym_map_for(self.binary),
                                insns=insns, bits=bits)

    def _api_cfg(self, func_addr):
        """函数基本块 CFG, 标记漏洞调用点所在块"""
        bounds = {s: e for s, e, _ in self._api_bounds()}
        end = bounds.get(func_addr)
        if not end:
            return {"error": "函数不存在"}
        mark_addrs = []
        for v in self.results.get("overflow", []):
            try:
                if int(v.get("address", "0x0"), 16) == func_addr:
                    ca = _vuln_call_site(v)
                    if ca:
                        mark_addrs.append(ca)
            except ValueError:
                pass
        pre = _get_disas(self.binary)
        insns = pre[0] if pre else None
        bits = pre[1] if pre else None
        cfg = build_function_cfg(self.binary, func_addr, end,
                                 insns=insns, bits=bits, mark_addrs=mark_addrs)
        if not cfg.get("nodes"):
            cfg["error"] = "该函数无 .text 指令 (可能位于 .init/.fini/PLT 段)"
        return cfg

    # ── 基础响应 ─────────────────────────────────────────────

    def _serve_static(self, rel):
        base = os.path.normpath(os.path.abspath(WEBUI_STATIC))
        fp = os.path.normpath(os.path.join(base, rel))
        if not (fp == base or fp.startswith(base + os.sep)):  # 路径穿越防护 (含分隔符)
            self.send_error(403)
            return
        try:
            with open(fp, "rb") as f:
                data = f.read()
        except OSError:
            self.send_error(404)
            return
        ext = os.path.splitext(rel)[1].lower()
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj):
        if isinstance(obj, dict) and "_shared" in obj:
            # 黑板缓存 (capstone insns 等不可 JSON 序列化) 不进 API 响应
            obj = {k: v for k, v in obj.items() if k != "_shared"}
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


_ACTIVE_HTTPD = None
_ACTIVE_HTTPD_LOCK = threading.Lock()


def _shutdown_server():
    """停止正在运行的 HTTP 服务 (由 /api/shutdown 触发; Ctrl-C 失效时的兜底出口)"""
    with _ACTIVE_HTTPD_LOCK:
        httpd = _ACTIVE_HTTPD
    if httpd:
        try:
            httpd.block_on_close = False
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
        print("\n[+] 服务已停止 (通过 /api/shutdown)")
    # daemon handler 线程随进程退出, 主线程随后返回


def _pick_port(preferred: int, max_tries: int = 20):
    """端口选择: 显式指定则严格使用; 否则从 preferred 起递增找空闲"""
    import socket
    for p in range(preferred, preferred + max_tries):
        with socket.socket() as s:
            try:
                s.bind(("0.0.0.0", p))
                return p
            except OSError:
                continue
    return None


def serve(results: dict, binary: str, host: str = "0.0.0.0",
          port: int = 5000, explicit_port: bool = False,
          open_browser: bool = True) -> None:
    """启动可视化服务并阻塞 (Ctrl-C 退出)

    host 默认 0.0.0.0 (Kali VM 场景宿主机可访问); 在敌对网络上可
    用 --web-host 127.0.0.1 锁定本机。
    """
    _Handler.results = results
    _Handler.binary = binary

    if explicit_port:
        # 显式指定: 严格使用, 被占直接报错 (不自动递增)
        final_port = port
        try:
            httpd = ThreadingHTTPServer((host, final_port), _Handler)
        except OSError:
            print(f"[!] 端口 {port} 已被占用, 请用 --web-port 换一个")
            sys.exit(1)
    else:
        final_port = _pick_port(port)
        if final_port is None:
            print(f"[!] 端口 {port}-{port + 19} 均被占用, 请用 --web-port 指定")
            sys.exit(1)
        httpd = ThreadingHTTPServer((host, final_port), _Handler)
    url = f"http://{host}:{final_port}/"
    print(f"[+] 可视化服务已启动: {url}")
    print(f"    分析目标: {binary}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"    [注意] 监听 {host}: 局域网内其他主机可访问该分析页面, "
              f"敌对网络请用 --web-host 127.0.0.1 锁定")
    print("    退出: Ctrl-C / 浏览器访问 /api/shutdown / kill <pid>")
    global _ACTIVE_HTTPD
    with _ACTIVE_HTTPD_LOCK:
        _ACTIVE_HTTPD = httpd
    # SIGTERM 优雅退出 (kill <pid> / pkill 场景)
    def _on_sigterm(signum, frame):
        print("\n[+] 收到 SIGTERM, 服务已停止")
        httpd.block_on_close = False
        threading.Thread(target=_shutdown_server, daemon=True).start()
    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):
        pass  # 非主线程等无法注册信号的场景忽略
    if open_browser:
        try:
            webbrowser.open(f"http://127.0.0.1:{final_port}/")
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] 服务已停止")
        # 兜底: 跳过 join 仍存活 handler 线程 (HTTP/1.0 下通常已无), daemon 线程随进程退出
        httpd.block_on_close = False
        httpd.server_close()
