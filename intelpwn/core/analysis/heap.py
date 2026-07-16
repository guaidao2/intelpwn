"""堆操作检测"""

from .plt import analyze_plt
from .cfg import analyze_cfg


def detect_heap(path: str) -> dict:
    """检测堆操作函数使用情况"""
    plt = analyze_plt(path)
    heap_funcs = [f for f in plt if f in ('malloc', 'calloc', 'realloc', 'free', 'mmap', 'brk')]
    if not heap_funcs:
        return {
            "has_heap": False,
            "functions": [],
            "function_count": 0,
            "heap_function_list": [],
            "complexity": 0,
        }

    cfg = analyze_cfg(path)
    return {
        "has_heap": True,
        "functions": heap_funcs,
        "function_count": len(heap_funcs),
        "heap_function_list": heap_funcs,
        "complexity": cfg.get("cyclomatic", 0),
    }
