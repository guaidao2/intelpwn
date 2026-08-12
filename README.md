
<p align="center">
  <img src="https://img.shields.io/badge/IntelPwn-v1.1-blue?style=flat-square" alt="version">
  <img src="https://img.shields.io/badge/license-GPLv3-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/python-3.10+-orange?style=flat-square" alt="python">
  <img src="https://img.shields.io/badge/CTF-Pwn-red?style=flat-square" alt="ctf">
</p>

# IntelPwn — 智能二进制漏洞分析系统

> **纯算法驱动** — IntelPwn 通过 capstone 反汇编 + pwntools + angr 符号执行 + 静态/动态分析，自动检测二进制漏洞并生成可直接运行的 exploit 脚本。

```
    ██████╗ ██████╗ ███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗
   ██╔════╝██╔═══██╗██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║
   ██║     ██║   ██║█████╗  ██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║
   ██║     ██║   ██║██╔══╝  ██║     ██║   ██║██║███╗██║██║╚██╗██║
   ╚██████╗╚██████╔╝██║     ███████╗╚██████╔╝╚███╔██╔╝██║ ╚████║
    ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
```

---

## 功能特性

### 分析能力

| 检测项 | 方法 | 说明 |
|---|---|---|
| **栈缓冲区溢出** | capstone 反汇编: 有界读 (read/fgets/memcpy/strncpy/snprintf) 比大小, 无界写 (gets/strcpy/sprintf/strcat) 看目标地址 | 双重判定 + 置信度 |
| **scanf 精确判定** | 解析格式串: 仅无宽度 %s 判险, %d/%x 不误报 | 消除旧版无条件误报 |
| **格式化字符串** | 静态 + 黑盒, 合并 4 批加速 | 偏移自动定位 |
| **安全保护** | Canary / NX / PIE / RELRO / RWX 段 / 静态链接 | 带风险评级 |
| **PLT 危险函数** | 自动标注 system/execve/gets/printf 等 | 用途分类 |
| **ROP gadgets** | capstone 定向扫描 (pop_rdi/rsi/rdx, ret, int 0x80, **jmp_rsp, syscall;ret**) + pwntools 回退 | ~0.1s |
| **BSS 可写区** | ELF 符号表扫描大尺寸 BSS 符号 | 用于 shellcode 存储 |
| **CFG 复杂度** | 指令流直接计数边和节点 (去 NetworkX) | 5ms vs 500ms |
| **堆漏洞线索** | 同函数多 free (double-free) / malloc 大小算术运算 (整数溢出) / 循环内 free (UAF 场景) | 启发式提示 |
| **angr 符号执行** | 主动发现: 全量枚举危险调用点 (可达性 + 栈目标 + 大小 taint), 静态漏检的 strcpy 等无界写也能发现并算 padding; 溢出点符号化 padding 交叉确认 | 可选插件 |
| **利用策略生成** | 基于保护状态 + 可用函数 + ROP → 自动推导方案 | 多种策略 |

### Exploit 生成

| 场景 | 模板 | 状态 |
|---|---|---|
| **ret2win** (有 win 函数) | `gen_ret2win` | 直接可用 |
| **ret2system** (`system@plt` + `/bin/sh`) | `gen_ret2system` | 直接可用 |
| **ret2libc** (leak + ret2system) | `gen_ret2libc` | 有 pop_rdi 时完全自动, 支持 `--remote` |
| **ret2dlresolve** (无 libc) | `gen_ret2dlresolve` | read@plt + 可写 BSS + 非 Full RELRO; **注意 glibc>=2.40 已失效, 模板自动检测并 WARN** |
| **SROP** (sigreturn) | `gen_srop` | 有 syscall;ret + pop 三件套 + read@plt — **Kali 实测打穿** |
| **shellcode 注入** (NX 关闭) | `gen_shellcode` | 无 jmp_rsp gadget 时不生成断路径 |
| **Canary 爆破 + ret2win** | `gen_canary_ret2win` | 支持 `--remote` fork 服务器 |
| **格式化字符串** (GOT 覆写) | `gen_fmtstr` | 有 puts@got+system@plt 时生成实际 payload |
| **tcache dup** (堆) | `gen_tcache_dup` | 原语骨架; glibc<2.34 目标 __free_hook, >=2.34 自动标注 tls_dtor_list 现代路径 |
| **one_gadget 自动定位** | ret2libc 内嵌 | 有 one_gadget 工具时自动填充偏移 |
| **ROP 骨架** (无自动路径时) | — | 输出 gadget 列表 + 推荐工具 |

所有 exp 模板:
- 使用**绝对路径**定位 binary
- 自动设置 `context.binary` (pwntools 自动检测 arch)
- `read()` 系溢出使用 `send()` 而非 `sendline()`
- 关键 gadget 缺失时输出 `# [WARN]` 注释 + 修复命令
- 无法自动利用时明确标注 `[骨架]`, 不输出看似可用实则必崩的脚本

### 输出格式

- **终端报告**: 中文报告 (漏洞汇总 + 保护状态 + 栈布局 + ROP 列表 + angr 符号执行 + 修复建议)
- **JSON 输出**: `--json` 参数 → schema v1.1 (见 `schema/intelpwn.schema.json`), 可管道给 jq / CI
- **批量扫描**: `--dir <目录>` 扫描目录下所有 ELF, 输出汇总表或 JSON 数组

---

## 安装

```bash
git clone https://github.com/guaidao2/intelpwn.git
cd intelpwn

# Kali/Debian 一键安装 (系统工具 apt 安装, Python 依赖装入隔离 venv)
bash install.sh
```

安装完成后直接可用:

```bash
python3 intelpwn.py --help
```

说明:
- 系统 python 仅通过 apt 安装系统包 (binutils/gdb/checksec 等), **不被 pip 污染**
- Python 依赖 (pwntools/capstone/pyelftools/angr) 装入 `~/.intelpwn-venv` 隔离环境
- `intelpwn.py` 启动时自动切换到 venv (`INTELPWN_NO_VENV=1` 可禁用), 因此 `python3 intelpwn.py` 直接可用
- angr 为可选依赖: 未安装时工具正常使用, 仅 `angr_check` 插件跳过

---

## 基本用法

```bash
# 全量分析 + 中文报告 (自动生成 exploit)
python3 intelpwn.py analyze <binary>

# 分析并生成 libc 利用
python3 intelpwn.py analyze <binary> --libc /usr/lib/x86_64-linux-gnu/libc.so.6

# 远程利用
python3 intelpwn.py analyze <binary> --libc <path> --remote 10.0.0.1:1337

# JSON 输出 (机器可读, schema v1.1)
python3 intelpwn.py analyze <binary> --json

# 批量扫描目录下所有 ELF
python3 intelpwn.py analyze --dir <目录> [--json]

# 定点验证 = analyze --verify (静态 + 动态 + 交叉验证)
python3 intelpwn.py verify <binary>

# 抑制 exploit 自动生成
python3 intelpwn.py analyze <binary> --no-exploit
```

### 运行测试

```bash
# 单元测试 (28 个用例)
python3 -m pytest tests/ -v
```

---

## 支持的 Challenge 类型

项目包含 8 道预设 CTF 练习题，覆盖主流 pwn 题型:

| Challenge | 保护 | 漏洞 | 自动 exp |
|---|---|---|---|
| `challenge_ret2win` | NX, NoCanary, NoPIE | 栈溢出 72 padding | ret2win |
| `challenge_ret2win_canary` | NX, Canary, NoPIE | 栈溢出 + Canary | canary 爆破 + ret2win |
| `challenge_ret2libc` | NX, NoCanary, NoPIE | 栈溢出 72 padding | (需 pop_rdi) |
| `challenge_fmtstr` | NX, NoCanary, NoPIE | 格式化字符串 | 偏移探测 + [骨架] |
| `challenge_fmtstr_canary` | NX, Canary, NoPIE | 格式化字符串+Canary | 含 canary 定位 |
| `challenge_shellcode` | ExecStack, NoCanary | 栈溢出 136 padding | shellcode 注入 |
| `challenge_srop` | NX, NoCanary, NoPIE | 栈溢出 72 padding | SROP (实测打穿) |
| `challenge_ret2dlresolve` | NX, NoCanary, NoPIE | 栈溢出 72 padding | ret2dlresolve (glibc<2.40) |
| `challenge_tcache` | NX, NoCanary, NoPIE | UAF + tcache poisoning | 手动 exploit (现代 glibc 实测打穿) |
| `challenge_angr_hidden` | NX, NoCanary, NoPIE | 子函数 strcpy 栈溢出 | angr 主动发现 (静态漏检) |
| `challenge_rop` | NX, NoCanary | 栈溢出 24 padding | 骨架 + gadget 列表 |
| `challenge_pie` | NX, PIE, NoCanary | 栈溢出 + PIE | 解析运行时地址 |

---

## 架构

```
intelpwn.py                          CLI 入口 (含 venv 垫片)
├── intelpwn/core/analysis/          分析引擎 (模块化 + 插件注册表)
│   ├── __init__.py                  analyze_all() 编排器 + register_analyzer()
│   ├── protections.py               checksec/readelf 保护分析
│   ├── plt.py                       PLT/GOT 扫描
│   ├── overflow.py                  capstone 反汇编 → 栈溢出检测 (有界/无界双判定)
│   ├── fmtstr.py                    格式化字符串 (静态+黑盒)
│   ├── rop.py                       capstone 定向 ROP + 链分析
│   ├── bss.py                       BSS 符号扫描
│   ├── cfg.py                       CFG 圈复杂度 (无 NetworkX)
│   ├── heap.py                      堆函数检测 + 静态线索
│   ├── findings.py                  漏洞总结 + 策略生成
│   └── angr_analysis.py             angr 插件 (主动发现/可达性/padding, 自注册)
├── intelpwn/core/report.py          中文报告 + JSON 输出 (schema v1.1)
├── intelpwn/core/exploit.py         exploit 模板生成器
├── intelpwn/core/verify.py          定点验证 (cyclic 偏移提取)
├── intelpwn/utils/binary.py         工具函数 (open_elf, run, checksec...)
├── intelpwn/utils/output.py         终端输出样式
├── challenges/                      8 道 CTF 练习题
├── tests/                           28 个单元测试
├── schema/intelpwn.schema.json      JSON 输出 schema
└── install.sh                       依赖安装 (apt + 隔离 venv)
```

### 数据处理流

```
binary
  │
  ▼
analyze_all()
  │
  ├─ protections.py      → 保护状态 + 风险评级
  ├─ plt.py              → PLT/GOT 函数表
  ├─ disassemble_text()  ← 只反汇编一次, 共享给 overflow + fmtstr + rop
  ├─ overflow.py         → 栈溢出检测 + padding 计算 (有界读/无界写双判定)
  ├─ fmtstr.py           → 格式化字符串 (静态分析 + 4 批黑盒)
  ├─ rop.py              → capstone 定向扫描 + pwntools 回退
  ├─ bss.py              → BSS 可写符号
  ├─ cfg.py              → 圈复杂度 (O(n) 直接计数)
  ├─ heap.py             → 堆函数检测 + double-free/整溢线索
  ├─ angr_analysis.py    → 插件: 溢出调用点可达性 + 大小符号化验证
  └─ findings.py         → 综合漏洞总结
  │
  ▼
report.py               → 中文报告 / --json 输出 (schema v1.1)
exploit.py              → 模板自动选择 (ret2win/ret2libc/ret2dlresolve/SROP/shellcode/fmtstr/...)
```

### 插件机制

```python
# 新建 intelpwn/core/analysis/my_plugin.py
from . import register_analyzer

@register_analyzer("my_check")
def my_check(path, results):
    ...  # 返回 dict, 自动写入 results["my_check"]
    return {...}
```

`analyze_all` 会在内置流程之后自动执行所有已注册插件, 无需修改编排器。

### 算法优化

| 优化项 | 优化前 | 优化后 | 加速比 |
|---|---|---|---|
| CFG 圈复杂度 | networkx.DiGraph (500ms, 50MB) | O(n) 指令扫描 (5ms, 1KB) | 100x |
| 格式化字符串黑盒 | 8 轮串行 subprocess (<=24s) | 4 批合并 (<=11s) | 2.2x |
| 溢出函数过滤 | O(NxF) 列表推导 | O(N) + bisect 二分查找 | 100x |
| ROP 扫描 | pwntools 全量 (3-5s) | capstone 定向 8 pattern (0.1s) | 50x |
| 反汇编 | overflow + fmtstr 各跑一次 | 预反汇编 + 共享 | 2x |
| padding 验证 | 每次跑 GDB (2s 固定) | 静态一致时跳过 (~0.2s) | 10x |

---

## 与同类工具对比

| 特性 | IntelPwn | checksec.sh | pwntools | ROPgadget |
|---|---|---|---|---|
| 一键全量分析 | 支持 | 不支持 | 不支持 | 不支持 |
| 栈溢出 padding 计算 | 支持 (三重验证 + angr) | 不支持 | 不支持 | 不支持 |
| 格式化字符串检测 | 支持 静态+黑盒 | 不支持 | 不支持 | 不支持 |
| Exp 自动生成 | 支持 10+ 模板 | 不支持 | 不支持 | 不支持 |
| 符号执行验证 | 支持 (angr 插件) | 不支持 | 不支持 | 不支持 |
| 批量扫描 + JSON | 支持 (--dir + schema) | 不支持 | 不支持 | 不支持 |
| 中文报告 | 支持 | 不支持 | 不支持 | 不支持 |
| 单元测试 | 28 用例 | - | - | - |

---

## 依赖

- **Python** >= 3.10
- **pwntools** >= 4.9.0 (ELF 解析 + ROP 扫描)
- **capstone** >= 5.0 (反汇编引擎)
- **pyelftools** >= 0.29 (ELF 结构解析)
- **angr** >= 9.2 (可选, 符号执行插件, 经 install.sh 装入 venv)
- **one_gadget** (可选, ret2libc 模板自动填充)
- **系统工具**: binutils, gdb, checksec, ROPgadget, file

---

## 设计理念

1. **纯算法, 零 ML** — 所有分析基于反汇编 + 符号执行 + 静态/动态分析，无模型依赖，结果可解释可复现
2. **模块化 + 插件化** — 分析引擎拆为独立模块, 新检测项通过 `register_analyzer` 自注册
3. **实用优先** — 生成的 exploit 脚本可直接运行; 无法自动利用时诚实标注 [骨架], 绝不输出必崩脚本
4. **性能意识** — CFG 去 NetworkX、定向 ROP、条件 GDB、共享反汇编, 一次全量分析 ~3-5s
5. **环境安全** — 安装脚本用隔离 venv 装 Python 依赖, 不污染系统 python

---

## 开发

```bash
# 安装开发依赖
pip3 install pytest

# 运行全部测试
python3 -m pytest tests/ -v

# 测试所有 challenge 分析
python3 intelpwn.py analyze --dir challenges

# 添加新检测项: 在 intelpwn/core/analysis/ 下新建模块并 register_analyzer
```

---

## License

GPLv3 — 玄幕安全团队-guaidao2
