
<p align="center">
  <img src="https://img.shields.io/badge/IntelPwn-v2.0-blue?style=flat-square" alt="version">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="license">
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
| **ROP gadgets** | capstone 定向扫描 (x64: pop_rdi/rsi/rdx, ret, jmp_rsp, syscall;ret · x86: pop_eax/ebx/ecx/edx, int 0x80) + pwntools 回退 | ~0.1s |
| **x86 32 位支持** | cdecl 栈传参检测 (lea [ebp-X] → push/mov[esp]), scanf %s 格式串 vaddr→offset 映射, 三重 padding 验证自适应 (eip/esp/ebp + p32) | 全链路覆盖 |
| **静态链接专项** | libc 内置符号识别 (system/execve/binsh 固定地址), 危险函数符号表 fallback (静态链接无 PLT 也能识别 gets/read), fmtstr 无 GOT 覆写返回地址路径 | 能力包 |
| **复杂 ROP 组装** | ret2csu (__libc_csu_init) 识别 + x86 pop;pop;ret 多参链 | 链可行性分析 |
| **堆助手** | glibc 版本识别 + tcache/safe-linking/__free_hook 行为表 (按版本给攻击面) | 独立模块 |
| **BSS 可写区** | ELF 符号表扫描大尺寸 BSS 符号 | 用于 shellcode 存储 |
| **CFG 复杂度** | 指令流直接计数边和节点 (去 NetworkX) | 5ms vs 500ms |
| **堆漏洞线索** | 同函数多 free (double-free) / malloc 大小算术运算 (整数溢出) / 循环内 free (UAF 场景) | 启发式提示 |
| **angr 符号执行** | 主动发现: 全量枚举危险调用点 (可达性 + 栈目标 + 大小 taint), 静态漏检的 strcpy 等无界写也能发现并算 padding; 溢出点符号化 padding 交叉确认 | 可选插件 |
| **汇编自动注释** | 三级注释引擎: 漏洞链(红, 危险输入点/可溢出字节数/返回地址改写点, 来自分析结论) · 风险提示(黄, syscall 号/canary/敏感函数, 规则猜测) · 语义标注(灰, 序言/栈帧/PLT 调用解析); 供 `--web` 反汇编视图 | 规则引擎 |
| **菜单交互识别** | scanf 数字菜单双通道识别 (rodata "N. 名称" 菜单项 + cmp/je 分支链) → options 映射表 {选项: {handler, 参数结构}}; 伪菜单防护 (仅明确触发漏洞函数的选项才自动交互) | 通用基础设施 |
| **利用策略生成** | 基于保护状态 + 可用函数 + ROP → 自动推导方案 | 多种策略 |

### Exploit 生成

| 场景 | 模板 | 状态 |
|---|---|---|
| **ret2win** (有 win 函数) | `gen_ret2win` | x64/x86 通用 (p64/p32) |
| **int 0x80 execve 链** (x86 32 位) | `gen_int80_execve` | pop_eax/ebx/ecx/edx + int 0x80, eax=0x0b |
| **ret2system** (`system@plt` + `/bin/sh`) | `gen_ret2system` | 64 位需 pop_rdi; **32 位栈传参免 gadget**; **静态链接固定地址 (static_libc)** |
| **ret2libc** (leak + ret2system) | `gen_ret2libc` | 64 位有 pop_rdi 时自动; **32 位栈传参布局** |
| **leak 解法** (无 system/no-read, glibc>=2.40 通用) | `gen_leak_ret2libc` | puts@got 泄漏 → libc 基址 → ret2system; 自动栈对齐 (重入帧偏移), 有 `--libc` 全自动否则引导查偏移 |
| **ret2dlresolve** (无 libc) | `gen_ret2dlresolve` | read@plt **或 gets@plt** + 可写 BSS + 非 Full RELRO; **glibc>=2.40 本地场景脚本运行时自检+指引, 远程不误杀** |
| **SROP** (sigreturn) | `gen_srop` | 有 syscall;ret + pop 三件套 + read@plt — **Kali 实测打穿** |
| **shellcode 注入** (NX 关闭) | `gen_shellcode` | 无 jmp_rsp gadget 时不生成断路径 |
| **Canary 爆破 + ret2win** | `gen_canary_ret2win` | 4/8 字节自适应; 支持 `--remote` fork 服务器 |
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
- **菜单题自动预交互**: 识别到数字菜单且明确触发漏洞函数的选项时, 自动注入 `recvuntil(锚点) + sendline(选项)` (所有模板受益, 无需手动选菜单)

### 输出格式

- **终端报告**: 中文报告 (漏洞汇总 + 保护状态 + 栈布局 + ROP 列表 + angr 符号执行 + 修复建议)
- **JSON 输出**: `--json` 参数 → schema v2.0 (见 `schema/intelpwn.schema.json`), 可管道给 jq / CI
- **批量扫描**: `--dir <目录>` 扫描目录下所有 ELF, 输出汇总表或 JSON 数组
- **Web 可视化**: `--web` 参数 → 本地交互界面 (总览 + 反汇编三级注释 + CFG 图, 见下节)

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

# JSON 输出 (机器可读, schema v2.0)
python3 intelpwn.py analyze <binary> --json

# 批量扫描目录下所有 ELF
python3 intelpwn.py analyze --dir <目录> [--json]

# 定点验证 = analyze --verify (静态 + 动态 + 交叉验证)
python3 intelpwn.py verify <binary>

# 抑制 exploit 自动生成
python3 intelpwn.py analyze <binary> --no-exploit

# 可视化分析 (本地 web 界面: 总览 + 反汇编三级注释 + 交互 CFG 图)
python3 intelpwn.py analyze <binary> --web
# 默认监听 0.0.0.0:5000 (Kali VM 场景宿主机可访问); 可指定端口/锁定本机
python3 intelpwn.py analyze <binary> --web --web-port 9000 --web-host 127.0.0.1
```

### 可视化分析 (`--web`)

`analyze --web` 在本地起一个 web 服务 (默认 `0.0.0.0:5000`, Kali VM 场景宿主机浏览器直接访问 VM IP), 把分析结果渲染成可交互的漏洞视图:

| 视图 | 内容 |
|---|---|
| **总览** | 保护状态 / 溢出 / ret2text 目标 / 交叉验证结论 摘要 |
| **反汇编** | 每行指令带**三级自动注释**: 漏洞链(红, 危险输入点/可溢出字节数/padding/返回地址改写点) · 风险提示(黄, syscall 号/canary/敏感函数, 规则猜测) · 语义标注(灰, 序言/栈帧/PLT 调用解析); 红注释始终显示, 黄/灰可开关 |
| **CFG 交互图** | IDA 式控制流图 (cytoscape/dagre), 漏洞块红色高亮自动选中, 点节点在右侧独立面板查看块内反汇编 |

API: `GET /api/functions` `/api/disasm/<addr>` `/api/cfg/<addr>` `/api/report` (JSON, 供二次开发)。

> 安全提示: 默认 0.0.0.0 会把分析数据暴露给局域网; 敌对网络请用 `--web-host 127.0.0.1` 锁定本机。

### 运行测试

```bash
# 单元测试 (155 个用例; Windows 上缺 objdump/readelf 的用例自动跳过)
python3 -m pytest tests/ -v
```

---

## 支持的 Challenge 类型

项目包含 14 道预设 CTF 练习题 (含 32 位 x86 与静态链接), 覆盖主流 pwn 题型:

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
| `challenge_x86_vuln` | x86 32 位, NX, NoCanary, NoPIE | gets 栈溢出 52 padding | ret2win (实测打穿) / ret2system (32 位栈传参) |
| `challenge_static_vuln` | 静态链接, NX, NoCanary, NoPIE | gets 栈溢出 72 padding | static_libc 符号识别 + 静态 ret2system |
| `challenge_rop` | NX, NoCanary | 栈溢出 24 padding | 骨架 + gadget 列表 |
| `challenge_pie` | NX, PIE, NoCanary | 栈溢出 + PIE | 解析运行时地址 |

---

## 架构

```
intelpwn.py                          CLI 入口 (含 venv 垫片)
├── intelpwn/core/analysis/          分析引擎 (模块化 + 插件注册表)
│   ├── __init__.py                  analyze_all() 编排器 + register_analyzer() + 黑板缓存物化 (_shared)
│   ├── protections.py               checksec/readelf 保护分析
│   ├── plt.py                       PLT/GOT 扫描
│   ├── overflow.py                  capstone 反汇编 → 栈溢出检测 (有界/无界双判定)
│   ├── fmtstr.py                    格式化字符串 (静态+黑盒)
│   ├── rop.py                       capstone 定向 ROP + 链分析
│   ├── bss.py                       BSS 符号扫描
│   ├── cfg.py                       CFG 圈复杂度 (无 NetworkX)
│   ├── heap.py                      堆函数检测 + 静态线索 + glibc 版本行为表
│   ├── comments.py                  汇编三级自动注释引擎 (漏洞链/风险/语义)
│   ├── findings.py                  漏洞总结 + 策略生成
│   ├── menu.py                      菜单交互识别 (scanf 数字菜单 → options 映射, 通用基础设施)
│   └── angr_analysis.py             angr 插件 (主动发现/可达性/padding, 自注册)
├── intelpwn/core/report.py          中文报告 + JSON 输出 (schema v2.0)
├── intelpwn/core/exploit.py         exploit 模板生成器 (注册表驱动, 插件可挂模板)
├── intelpwn/core/verify.py          定点验证 (cyclic 偏移提取)
├── intelpwn/core/cross_validate.py  静态 vs 动态交叉验证 (确认/未复现/动态发现/canary拦截)
├── intelpwn/core/webui.py           --web 可视化服务 (总览/反汇编注释/CFG 交互图)
├── intelpwn/webui/static/           前端单页 (app.js/index.html/style.css + cytoscape/dagre)
├── intelpwn/utils/binary.py         工具函数 (open_elf, run, checksec...)
├── intelpwn/utils/output.py         终端输出样式
├── challenges/                      14 道 CTF 练习题 (含 32 位 + 静态链接)
├── tests/                           155 个单元测试
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
report.py               → 中文报告 / --json 输出 (schema v2.0)
exploit.py              → 模板自动选择 (ret2win/ret2libc/ret2dlresolve/SROP/shellcode/fmtstr/...)
```

### 插件机制

> 想写你的第一个能力包? 见 **[CONTRIBUTING.md](CONTRIBUTING.md)** — 插件三件套完整指南 (分析器注册 / 黑板协议 / exploit 模板 / 测试与提交流程)。

一个能力包 = 三个口子, 挂上即通 (核心零改动):

**1. 分析器口子** — 检测结果写入 results, 前端自动展示:

```python
# 新建 intelpwn/core/analysis/my_plugin.py
from . import register_analyzer

@register_analyzer("my_check")
def my_check(path, results):
    ...  # 返回 dict, 自动写入 results["my_check"]
    return {...}
```

`analyze_all` 会在内置流程之后自动执行所有已注册插件, 无需修改编排器。

**2. exploit 模板口子** — 按条件路由, 可覆盖内置模板:

```python
from intelpwn.core.exploit import register_exploit_template

def predicate(results, libc_path):
    return results.get("my_check", {}).get("vuln")   # 适用条件

def gen(results, libc_path, host, port):
    return "# 生成的 exploit 脚本\n"                  # 完整脚本

# priority 越小越先 (内置 10-110, 插件默认 500, 骨架 999); priority=5 可覆盖内置
register_exploit_template("my_exploit", predicate, gen, priority=5)
```

**3. 前端兜底渲染** — 分析器输出的任何 key, 未硬编码时自动渲染为"其他发现"折叠卡片 (JSON 结构化, XSS 转义), 无需改 `webui/static/app.js`。

**4. 通配 CLI** — 终端报告的"扩展分析输出"区块自动显示所有插件/扩展分析器的结果 (通用键值渲染 + 菜单/静态链接 libc 专项), 新增插件无需改 `report.py`。

> 能力包示例: 静态链接专项 / 复杂 ROP 组装 / 堆助手等, 均可按此三件套接入。

### 算法优化

| 优化项 | 优化前 | 优化后 | 加速比 |
|---|---|---|---|
| CFG 圈复杂度 | networkx.DiGraph (500ms, 50MB) | O(n) 指令扫描 (5ms, 1KB) | 100x |
| 格式化字符串黑盒 | 8 轮串行 subprocess (<=24s) | 4 批合并 (<=11s) | 2.2x |
| 溢出函数过滤 | O(NxF) 列表推导 | O(N) + bisect 二分查找 | 100x |
| ROP 扫描 | pwntools 全量 (3-5s) | capstone 定向 8 pattern (0.1s) | 50x |
| 反汇编 | overflow + fmtstr 各跑一次 | 预反汇编 + 共享 | 2x |
| **黑板基础设施缓存** | 各分析器重复 open_elf + 符号表 + PLT 解析 | `analyze_all` 一次性物化 `_shared` (insns/func_bounds/sym_by_addr/plt_map), overflow/menu 消费 | 大二进制省 4-5 次重复解析 |
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
| 单元测试 | 155 用例 | - | - | - |

---

## 依赖

- **Python** >= 3.10
- **pwntools** >= 4.9.0 (ELF 解析 + ROP 扫描)
- **capstone** >= 5.0 (反汇编引擎)
- **pyelftools** >= 0.29 (ELF 结构解析)
- **angr** >= 9.2 (可选, 符号执行插件, 经 install.sh 装入 venv)
- **one_gadget** (可选, ret2libc 模板自动填充)
- **系统工具**: binutils, gdb, checksec, ROPgadget, file, gcc-multilib (编 x86 32 位靶子)

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

MIT — 玄幕安全团队-guaidao2 (见 [LICENSE](LICENSE))
