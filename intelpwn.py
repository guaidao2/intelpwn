#!/usr/bin/env python3
"""IntelPwn — 二进制漏洞智能分析系统

用法:
  intelpwn.py analyze <binary>                   分析 + 中文报告
  intelpwn.py analyze <binary> --libc <path>     分析 + 生成 exploit
  intelpwn.py analyze <binary> --libc <path> --remote h:p  远程利用
  intelpwn.py analyze <binary> --json            输出 JSON 格式结果
  intelpwn.py analyze --dir <dir> [--json]       批量扫描目录下所有 ELF
  intelpwn.py verify <binary>                    定点验证 (崩溃/边界/偏移)
"""

import argparse
import os
import sys


def _use_venv():
    """若存在 ~/.intelpwn-venv 且当前不在 venv 内, 用 venv python 重新执行。

    install.sh 把 angr 等重型依赖装进独立 venv (不污染系统 python),
    此垫片让 `python3 intelpwn.py` 直接可用。设置 INTELPWN_NO_VENV=1
    可跳过垫片 (调试用)。
    注意: venv 的 python3 通常是系统 python 的软链, 不能用 realpath
    判断, 必须用 sys.prefix != sys.base_prefix 判断是否已在 venv。
    """
    if os.environ.get("INTELPWN_NO_VENV"):
        return
    if sys.prefix != sys.base_prefix:
        return  # 已在 venv 内
    venv_py = os.path.expanduser("~/.intelpwn-venv/bin/python3")
    if os.name == "posix" and os.path.exists(venv_py):
        os.execv(venv_py, [venv_py] + sys.argv)


_use_venv()

from intelpwn.utils.output import (
    print_banner, print_info, print_success, print_warning, Colors, print_section_header,
)
from intelpwn.core.analysis import analyze_all
from intelpwn.core.report import print_results, print_json_summary
from intelpwn.core.exploit import generate as gen_exploit


def _is_elf(path: str) -> bool:
    """按魔数判断是否为 ELF 文件"""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except Exception:
        return False


def cmd_analyze_dir(args):
    """批量扫描目录下所有 ELF 文件"""
    import io, contextlib, logging, json
    root = args.dir
    if not os.path.isdir(root):
        print(f"{Colors.RED}[错误]{Colors.END} 目录不存在: {root}")
        return

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d != '__pycache__']
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if os.path.isfile(p) and _is_elf(p):
                files.append(p)
    if not files:
        print(f"{Colors.YELLOW}[警告]{Colors.END} 未在 {root} 下找到 ELF 文件")
        return

    if not args.json:
        print_section_header(f"批量扫描: {root} ({len(files)} 个 ELF)")
    logging.getLogger('pwnlib').setLevel(logging.ERROR)

    results_all = []
    for i, p in enumerate(files, 1):
        if not args.json:
            print(f"\n{Colors.CYAN}[{i}/{len(files)}]{Colors.END} {os.path.basename(p)}")
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                results = analyze_all(p, args.libc, semantic_mode=args.semantic)
        except Exception as e:
            print(f"{Colors.RED}[错误]{Colors.END} {os.path.basename(p)}: {e}")
            continue
        results_all.append(results)
        if not args.json:
            print_results(results, p)

    if args.json:
        # 批量 JSON: 输出数组 (供 jq/CI 使用)
        print(json.dumps([json.loads(print_json_summary(r)) for r in results_all],
                         ensure_ascii=False, indent=2))
        return

    # 汇总表
    print()
    print_section_header(f"批量扫描汇总 ({len(results_all)} 个成功)")
    sev_tag = {"严重": f"{Colors.RED}[严重]{Colors.END}",
               "高危": f"{Colors.RED}[高危]{Colors.END}",
               "中危": f"{Colors.YELLOW}[中危]{Colors.END}",
               "低危": f"{Colors.GREEN}[低危]{Colors.END}",
               "信息": f"{Colors.CYAN}[信息]{Colors.END}"}
    for r in results_all:
        ms = r.get("summary", {}).get("max_severity", "低危")
        print(f"  {sev_tag.get(ms, ms)} {r.get('file')}")


def cmd_analyze(args):
    """全量分析 + 中文报告 + 可选 exploit 生成"""
    if args.dir:
        return cmd_analyze_dir(args)
    path = args.binary
    if not os.path.exists(path):
        print(f"{Colors.RED}[错误]{Colors.END} 文件不存在: {path}")
        return

    if args.json:
        # JSON 模式: 静默分析，只打印 JSON
        import io, contextlib, logging
        logging.getLogger('pwnlib').setLevel(logging.ERROR)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            results = analyze_all(path, args.libc, semantic_mode=args.semantic)
            # --verify: 动态验证 + 交叉验证也纳入 JSON
            verify_on = bool(getattr(args, 'verify', False)) and not getattr(args, 'no_verify', False)
            if args.remote:
                verify_on = False
            if verify_on and os.access(path, os.X_OK):
                from intelpwn.core.verify import verify_dynamic
                from intelpwn.core.cross_validate import cross_validate
                dynamic = verify_dynamic(path, results)
                results["dynamic"] = dynamic
                results["cross_validation"] = cross_validate(results, dynamic)
        print(print_json_summary(results))
        return

    print_section_header(f"分析目标: {os.path.basename(path)}")
    results = analyze_all(path, args.libc, semantic_mode=args.semantic)

    # 动态验证 + 交叉验证 (--verify 默认关; --remote/不可执行时自动跳过)
    verify_on = bool(getattr(args, 'verify', False)) and not getattr(args, 'no_verify', False)
    if args.remote:
        verify_on = False
    if verify_on and os.access(path, os.X_OK):
        from intelpwn.core.verify import verify_dynamic
        from intelpwn.core.cross_validate import cross_validate
        print_info("执行动态验证 (cyclic 偏移提取 + 边界测试 + fmtstr 偏移)...")
        dynamic = verify_dynamic(path, results)
        results["dynamic"] = dynamic
        results["cross_validation"] = cross_validate(results, dynamic)
        print_section_header("交叉验证 (静态 vs 动态)")
    elif verify_on:
        print_warning("目标不可执行, 跳过动态验证 (仅静态分析)")

    # 报告
    print_results(results, path)

    # exploit 生成 (--libc 或 有栈溢出/格式化字符串/angr主动发现时自动生成)
    has_overflow = bool(results.get("overflow"))
    has_fmtstr = bool(results.get("format_string", {}).get("vulnerable"))
    has_angr = any(d.get("status") != "truncated" and "padding" in d
                   for d in results.get("angr_check", {}).get("discovered", []))
    if args.libc or ((has_overflow or has_fmtstr or has_angr) and not args.no_exploit):
        libc_path = args.libc
        if libc_path and not os.path.exists(libc_path):
            print(f"{Colors.YELLOW}[警告]{Colors.END} libc 文件不存在: {libc_path}")
            libc_path = None
        gen_exploit(results, path, libc_path, args.remote)

    if args.remote:
        print_info(f"远程目标: {args.remote}")

    print_success("Analysis complete.")

    # --web 可视化服务 (仅单文件分析; json/dir 模式忽略)
    if getattr(args, 'web', False):
        if args.json:
            print_warning("--web 与 --json 不兼容, 跳过可视化服务")
        elif args.dir:
            print_warning("--web 仅支持单文件分析, 批量模式跳过可视化服务")
        else:
            from intelpwn.core.webui import serve
            serve(results, path, host=args.web_host,
                  port=args.web_port if args.web_port is not None else 5000,
                  explicit_port=args.web_port is not None)


def cmd_verify(args):
    """定点验证 — analyze --verify 的别名 (静态 + 动态 + 交叉验证)"""
    args.verify = True
    args.no_verify = False
    args.dir = None
    cmd_analyze(args)


def main():
    parser = argparse.ArgumentParser(description="IntelPwn — 二进制漏洞智能分析系统")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("analyze", help="全量分析 + 中文报告")
    p.add_argument("binary", nargs="?", help="目标二进制路径 (与 --dir 二选一)")
    p.add_argument("--dir", help="批量扫描目录下所有 ELF 文件")
    p.add_argument("--libc", help="指定 libc 文件路径 (生成 exploit)")
    p.add_argument("--remote", help="远程目标地址 host:port")
    p.add_argument("--verify", action="store_true", help="执行动态验证 + 交叉验证 (默认关)")
    p.add_argument("--no-verify", action="store_true", help="显式关闭动态验证")
    p.add_argument("--web", action="store_true",
                   help="分析后启动本地可视化服务 (默认 0.0.0.0, 端口 5000)")
    p.add_argument("--web-port", type=int, default=None,
                   help="可视化服务端口 (默认 5000, 被占自动递增; 显式指定则严格使用)")
    p.add_argument("--web-host", default="0.0.0.0",
                   help="可视化服务监听地址 (默认 0.0.0.0; 敌对网络可锁 127.0.0.1)")
    p.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
    p.add_argument("--no-exploit", action="store_true", help="不自动生成 exploit 脚本")
    p.add_argument("--semantic", choices=["throttled", "force"],
                   default="throttled",
                   help="语义分析模式: throttled(默认, 轻量数据流+angr 节流兜底) / "
                        "force(纯 angr 符号执行, 慢但更彻底)")

    p = sub.add_parser("verify", help="定点验证 = analyze --verify (静态+动态+交叉)")
    p.add_argument("binary", help="目标二进制路径")
    p.add_argument("--libc", help="指定 libc 文件路径 (生成 exploit)")
    p.add_argument("--remote", help="远程目标地址 host:port")
    p.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
    p.add_argument("--no-exploit", action="store_true", help="不自动生成 exploit 脚本")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    if args.command == "analyze" and not args.binary and not args.dir:
        parser.error("analyze 需要 <binary> 或 --dir")
    # --json 模式下不输出 banner 和进度信息
    if not getattr(args, 'json', False):
        print_banner()
    match args.command:
        case "analyze": cmd_analyze(args)
        case "verify": cmd_verify(args)


if __name__ == "__main__":
    main()
