#!/usr/bin/env python3
"""IntelPwn — 二进制漏洞智能分析系统

用法:
  intelpwn.py analyze <binary>                   分析 + 中文报告
  intelpwn.py analyze <binary> --libc <path>     分析 + 生成 exploit
  intelpwn.py analyze <binary> --libc <path> --remote h:p  远程利用
  intelpwn.py analyze <binary> --json            输出 JSON 格式结果
  intelpwn.py fuzz <binary>                      定点 Fuzz
"""

import argparse
import os
import sys

from intelpwn.utils.output import (
    print_banner, print_info, print_success, Colors, print_section_header,
)
from intelpwn.core.analysis import analyze_all
from intelpwn.core.report import print_results, print_json_summary
from intelpwn.core.exploit import generate as gen_exploit
from intelpwn.core.fuzzer import fuzz_by_analysis


def cmd_analyze(args):
    """全量分析 + 中文报告 + 可选 exploit 生成"""
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
            results = analyze_all(path, args.libc)
        print(print_json_summary(results))
        return

    print_section_header(f"分析目标: {os.path.basename(path)}")
    results = analyze_all(path, args.libc)

    # 报告
    print_results(results, path)

    # exploit 生成 (--libc 或 有栈溢出时自动生成)
    has_overflow = bool(results.get("overflow"))
    if args.libc or (has_overflow and not args.no_exploit):
        libc_path = args.libc
        if libc_path and not os.path.exists(libc_path):
            print(f"{Colors.YELLOW}[警告]{Colors.END} libc 文件不存在: {libc_path}")
            libc_path = None
        gen_exploit(results, path, libc_path, args.remote)

    if args.remote:
        print_info(f"远程目标: {args.remote}")

    print_success("Analysis complete.")


def cmd_fuzz(args):
    """分析引导的定点 Fuzz"""
    path = args.binary
    if not os.path.exists(path):
        print(f"{Colors.RED}[错误]{Colors.END} 文件不存在: {path}")
        return

    print_section_header(f"Fuzz: {os.path.basename(path)}")
    findings, results = fuzz_by_analysis(path, args.libc)

    # exploit 生成
    if args.libc or args.no_exploit:
        libc_path = args.libc
        if libc_path and not os.path.exists(libc_path):
            print(f"{Colors.YELLOW}[警告]{Colors.END} libc 文件不存在: {libc_path}")
            libc_path = None
        gen_exploit(results, path, libc_path, args.remote)

    print()
    print(f"  {Colors.BOLD}[Fuzz 发现]{Colors.END}")
    if findings:
        for f in findings:
            sev = f.get("严重度", "信息")
            tag = {"严重": f"{Colors.RED}[严重]{Colors.END}",
                   "高危": f"{Colors.RED}[高危]{Colors.END}",
                   "中危": f"{Colors.YELLOW}[中危]{Colors.END}"}.get(sev, f"{Colors.CYAN}[信息]{Colors.END}")
            print(f"  {tag} {f['类型']}: {f['详情']}")
    else:
        print(f"  {Colors.CYAN}[信息]{Colors.END} 未发现异常")

    print()
    print_results(results, path)


def main():
    parser = argparse.ArgumentParser(description="IntelPwn — 二进制漏洞智能分析系统")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("analyze", help="全量分析 + 中文报告")
    p.add_argument("binary", help="目标二进制路径")
    p.add_argument("--libc", help="指定 libc 文件路径 (生成 exploit)")
    p.add_argument("--remote", help="远程目标地址 host:port")
    p.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
    p.add_argument("--no-exploit", action="store_true", help="不自动生成 exploit 脚本")

    p = sub.add_parser("fuzz", help="定点 Fuzz 验证")
    p.add_argument("binary", help="目标二进制路径")
    p.add_argument("--libc", help="指定 libc 文件路径 (生成 exploit)")
    p.add_argument("--remote", help="远程目标地址 host:port")
    p.add_argument("--no-exploit", action="store_true", help="不自动生成 exploit 脚本")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    # --json 模式下不输出 banner 和进度信息
    if not getattr(args, 'json', False):
        print_banner()
    match args.command:
        case "analyze": cmd_analyze(args)
        case "fuzz": cmd_fuzz(args)


if __name__ == "__main__":
    main()
