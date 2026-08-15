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
import os
import re
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


def _plt_stub_map(elf):
    """pyelftools 解析 .rela.plt → {stub_addr: name@plt}.

    不依赖 pwntools (其 .plt 填充在无 pkg_resources 的环境失败).
    x86_64/arm64 .plt 布局: PLT0 16B + 每个 stub 16B; 第 i 条重定位对应第 i+1 个 stub.
    """
    smap = {}
    try:
        rela = elf.get_section_by_name('.rela.plt')
        plt_sec = elf.get_section_by_name('.plt')
        dynsym = elf.get_section_by_name('.dynsym')
        if not (rela and plt_sec and dynsym):
            return smap
        plt_base = plt_sec['sh_addr']
        plt_end = plt_base + plt_sec['sh_size']
        for i, reloc in enumerate(rela.iter_relocations()):
            sym_idx = reloc['r_info_sym']
            if sym_idx < dynsym.num_symbols():
                name = dynsym.get_symbol(sym_idx).name
                if name:
                    stub = plt_base + 16 * (i + 1)
                    if stub < plt_end:
                        smap[stub] = name + "@plt"
    except Exception:
        pass
    return smap


def _sym_map_for(path):
    """符号表 {addr: 函数名} — 按二进制缓存. 含 PLT stub 解析 (symtab 无 read@plt 类条目)"""
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
            smap.update(_plt_stub_map(elf))
    except Exception:
        pass
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
    bounds = {s: e for s, e, _ in _func_bounds(binary)}
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
            else:
                self.send_error(404)
        except (ValueError, IndexError):
            self.send_error(400)
        except Exception:
            self.send_error(500)

    # ── API 实现 ─────────────────────────────────────────────

    def _api_functions(self):
        """函数列表 + 漏洞标记 (溢出调用点地址)"""
        funcs = []
        for start, end, name in _func_bounds(self.binary):
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
        bounds = {s: e for s, e, _ in _func_bounds(self.binary)}
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
            lines = annotate_disasm(lines, entry, sym_map)
        except Exception:
            for ln in lines:
                ln.setdefault("note", None)
                ln.setdefault("note_level", None)
        return {"function": func_addr, "lines": lines}

    def _api_cfg(self, func_addr):
        """函数基本块 CFG, 标记漏洞调用点所在块"""
        bounds = {s: e for s, e, _ in _func_bounds(self.binary)}
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
        return build_function_cfg(self.binary, func_addr, end,
                                  insns=insns, bits=bits, mark_addrs=mark_addrs)

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
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


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
    print("    按 Ctrl-C 停止服务")
    if open_browser:
        try:
            webbrowser.open(f"http://127.0.0.1:{final_port}/")
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] 服务已停止")
        httpd.server_close()
