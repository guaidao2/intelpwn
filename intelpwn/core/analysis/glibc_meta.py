"""glibc 版本识别 + tcache 行为表 — P2.3 堆助手

从 libc 二进制读版本字符串 ("GNU C Library ... version 2.39") 判定 (major, minor),
映射到 tcache/safe-linking/__free_hook 行为, 供堆利用选择攻击面.
"""

import re

from intelpwn.utils.binary import open_elf

_KNOWN_LIBCS = (
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/i386-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib32/libc.so.6",
    "/usr/lib/libc.so.6",
    "/lib64/libc.so.6",
)


def _version_from_string(raw: bytes):
    m = re.search(rb'version\s+(\d+)\.(\d+)', raw)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


def glibc_version(libc_path=None):
    """返回 (major, minor) 或 None"""
    candidates = [libc_path] if libc_path else []
    candidates += [p for p in _KNOWN_LIBCS if p != libc_path]
    for path in candidates:
        if not path:
            continue
        try:
            with open_elf(path) as elf:
                # "GNU C Library" 版本串通常在 .rodata
                for sec_name in ('.rodata', '.data'):
                    sec = elf.get_section_by_name(sec_name)
                    if not sec:
                        continue
                    data = sec.data()
                    idx = data.find(b'GNU C Library')
                    if idx < 0:
                        continue
                    # 向后找 "version X.Y"
                    ver = _version_from_string(data[idx:idx + 300])
                    if ver:
                        return ver
        except Exception:
            continue
    return None


# glibc 版本 → tcache 行为标注
def tcache_behavior(version):
    """按 glibc (major, minor) 给出 tcache/堆利用相关行为"""
    if version is None:
        return {"note": "未识别 glibc 版本 (需 --libc 或系统 libc)"}
    maj, minor = version
    if (maj, minor) < (2, 26):
        return {
            "tcache": "无 tcache (glibc < 2.26)",
            "safe_linking": False,
            "free_hook": True,
            "攻击面": "fastbin dup / unsorted bin",
        }
    if (maj, minor) < (2, 32):
        return {
            "tcache": "tcache 启用, 无 safe-linking",
            "safe_linking": False,
            "free_hook": True,
            "攻击面": "tcache dup (无加密), __free_hook 覆写",
            "note": "tcache double-free 检测较弱, 同 chunk 可连续 free",
        }
    if (maj, minor) < (2, 34):
        return {
            "tcache": "tcache + safe-linking (指针加密)",
            "safe_linking": True,
            "free_hook": True,
            "攻击面": "tcache dup 需 heap 泄露 (safe-linking), __free_hook 仍可用",
            "note": "泄露 heap 基址后即可解 tcache 加密",
        }
    return {
        "tcache": "tcache + safe-linking",
        "safe_linking": True,
        "free_hook": False,
        "攻击面": "__free_hook 已移除 → tls_dtor_list / exit handler / 直接劫持函数指针",
        "note": f"glibc {maj}.{minor}: 现代堆利用需 tls_dtor_list 或 IO_FILE 方向",
    }


def detect_glibc_meta(libc_path=None) -> dict:
    """堆助手元数据: {version, tcache_behavior}"""
    ver = glibc_version(libc_path)
    meta = {"version": f"{ver[0]}.{ver[1]}" if ver else None}
    meta.update(tcache_behavior(ver))
    return meta
