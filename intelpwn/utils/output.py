"""SQLMap-style terminal output (matching PwnPasi convention)"""

import datetime
import sys


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    DIM = '\033[2m'

    INFO = '\033[1;34m'
    SUCCESS = '\033[1;32m'
    WARNING = '\033[1;33m'
    ERROR = '\033[1;31m'
    CRITICAL = '\033[1;35m'
    PAYLOAD = '\033[1;36m'


def timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


def print_info(message, prefix="[*]"):
    print(f"{Colors.INFO}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_success(message, prefix="[+]"):
    print(f"{Colors.SUCCESS}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_warning(message, prefix="[!]"):
    print(f"{Colors.WARNING}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_error(message, prefix="[-]"):
    print(f"{Colors.ERROR}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_critical(message, prefix="[CRITICAL]"):
    print(f"{Colors.CRITICAL}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_payload(message, prefix="[PAYLOAD]"):
    print(f"{Colors.PAYLOAD}{prefix}{Colors.END} {Colors.BOLD}[{timestamp()}]{Colors.END} {message}")


def print_section_header(title):
    line = "─" * 60
    print(f"\n{Colors.BOLD}{Colors.BLUE}┌{line}┐{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}│{Colors.END} {Colors.BOLD}{title.center(58)}{Colors.END} {Colors.BOLD}{Colors.BLUE}│{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}└{line}┘{Colors.END}")


def print_progress(current, total, task_name):
    percentage = int((current / total) * 100)
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    print(f"\r{Colors.INFO}[*]{Colors.END} {task_name}: {Colors.CYAN}[{bar}]{Colors.END} {percentage}%", end='', flush=True)
    if current == total:
        print()


def print_table(headers, rows):
    """Print a formatted table."""
    col_widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0)) for i, h in enumerate(headers)]
    sep = " │ "
    header_line = sep.join(f"{Colors.BOLD}{h:^{w}}{Colors.END}" for h, w in zip(headers, col_widths))
    rule = sep.join("─" * w for w in col_widths)
    print(header_line)
    print(rule)
    for row in rows:
        print(sep.join(f"{str(v):<{w}}" for v, w in zip(row, col_widths)))


def print_banner():
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
    ██████╗ ██████╗ ███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗
   ██╔════╝██╔═══██╗██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║
   ██║     ██║   ██║█████╗  ██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║
   ██║     ██║   ██║██╔══╝  ██║     ██║   ██║██║███╗██║██║╚██╗██║
   ╚██████╗╚██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║
    ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
{Colors.END}
{Colors.BOLD}    智能二进制漏洞分析系统{Colors.END}
{Colors.GREEN}    玄幕安全团队研发{Colors.END}
"""
    print(banner)
