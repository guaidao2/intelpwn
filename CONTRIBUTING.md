# Contributing to IntelPwn

欢迎贡献。IntelPwn 是面向 CTF pwn 的智能二进制漏洞分析工具，核心价值是**把"分析 → 利用 → 展示"做成可插拔的三端口能力包**：任何新检测/新利用模板/新展示都能挂上即通，核心零改动。

本文档约定贡献规范，重点是插件开发三件套与黑板协议。

---

## 1. 快速开始

```bash
git clone https://github.com/guaidao2/intelpwn.git
cd intelpwn
bash install.sh            # 自动创建 venv + 装依赖 (pwntools/capstone/pyelftools/angr 可选)
python3 intelpwn.py analyze challenges/challenge_ret2win
```

验证环境：任意 **x86_64 Linux**（Kali/Ubuntu 均可）。Windows 本地可开发，但全量测试以 Linux 为准
（部分用例依赖 objdump/readelf，Windows 上自动跳过）。

## 2. 架构速览：黑板 + 三端口

```
        ┌─────────────────────────────┐
        │  results (共享黑板 dict)      │ ← analyze_all 产出, 插件读写
        └──────┬──────────┬───────────┘
    read/write│          │read/write
     ┌────────▼──┐   ┌───▼────────┐   ┌────────────┐
     │ 分析器插件  │   │ exploit模板 │   │ 展示层       │
     │ register_ │   │ register_  │   │ CLI/wildcard│
     │ analyzer  │   │ template   │   │ web 兜底渲染 │
     └───────────┘   └────────────┘   └────────────┘
```

- **黑板**：`results` dict 是唯一通信渠道。`analyze_all` 物化基础设施缓存 `results["_shared"]`
  （`insns / bits / func_bounds / sym_by_addr / plt_map`），各分析器**消费不重扫**。
- **三端口**：分析器（知识源）、exploit 模板（利用生成）、展示层（CLI/wildcard + web 兜底）——挂一个能力包通常只写分析器即可，展示自动通配。

## 3. 插件开发：分析器（最常见）

```python
# intelpwn/core/analysis/my_check.py
from . import register_analyzer          # 注册表 (定义在 __init__ 顶部, 导入安全)

@register_analyzer("my_check")
def my_check(path: str, results: dict) -> dict:
    """你的检测逻辑。返回 JSON 友好 dict — CLI/web 会自动通配显示。"""
    shared = results.get("_shared") or {}    # 黑板缓存: 优先消费, 不重复扫描
    insns = shared.get("insns")
    ...
    return {"found": True, "detail": "..."}
```

规则：
- 签名固定 `fn(path, results) -> dict`；结果写入 `results[name]`（run_extra_analyzers 自动做）。
- **优先消费 `results["_shared"]`**（黑板已物化 insns/func_bounds/plt_map，见 §4）。
- 输出必须是 JSON 友好结构（dict/list/标量），CLI 的"扩展分析输出"与 web 兜底卡片会直接渲染。
- 注册文件必须被 `analysis/__init__.py` 的 `from . import <module>` 导入（或依赖自动导入），
  否则装饰器不生效 —— **这是最常见的"写了没生效"坑**（曾有真实案例：模块没 import，插件静默消失）。
- 单个分析器异常会被捕获写入 `results[name] = {"error": ...}`，不影响其他分析器。

## 4. 黑板协议（基础设施缓存）

`analyze_all` 一次性物化 `results["_shared"]`，各分析器共享：

| 字段 | 内容 | 说明 |
|---|---|---|
| `insns` | capstone 指令列表 | `.text` 全反汇编一次 |
| `bits` | 32 / 64 | |
| `func_bounds` | `[(start, end, name), ...]` | 符号表 STT_FUNC |
| `sym_by_addr` | `{addr: name}` | 函数地址 → 名 |
| `plt_map` | `{plt_addr: name}` | **pyelftools 主解析** (跨平台), pwntools 兜底 |

规范：
- **新增分析器优先从黑板取**，不要自己 `open_elf` + capstone 重扫（大静态二进制会重复 4-5 次解析）。
- 独立调用（不经过 analyze_all）时允许自扫 fallback，但实现应复用
  `_build_shared_blackboard` + `disassemble_text`（参考 `menu.py` 的瘦身写法）。
- `plt_map` 解析失败会显式告警（不静默）；下游在 plt_map 为空时回退符号表。

## 5. 插件开发：exploit 模板

```python
from intelpwn.core.exploit import register_exploit_template

def predicate(results, libc_path) -> bool:   # 是否命中本模板
    return bool(results.get("overflow")) and not win

def gen(results, libc_path, host, port) -> str:  # 返回完整脚本字符串
    return "#!/usr/bin/env python3\n..."

register_exploit_template("my_route", predicate, gen, priority=500)
```

规则：
- `priority` 越小越先（内置 10-110，插件默认 500，骨架 999）；`priority=5` 可覆盖内置模板。
- 模板生成**完整可运行脚本**（含 `from pwn import *`、`io = process/remote(...)`）。
- **不要生成必败脚本**：关键 gadget 缺失时返回 None 或带 `# [WARN]` 提示，让路由落到下一个模板。
- 菜单题自动预交互由 generate() 统一注入（检测到 `results["menu"]`），模板无需自行处理。

## 6. 展示层：无需改动

- **CLI**：新分析器输出自动出现在终端报告的"扩展分析输出"区块（report.py 兜底渲染）。
- **Web**：新 key 自动渲染为"其他发现"折叠卡片（app.js 兜底）。想做成精美主力卡片才需要改前端。
- `_shared` 是内部键，已被两处展示层排除，不要对外输出它。

## 7. 测试规范

```bash
# 本地 (Windows 可跑, 部分用例跳过)
python -m pytest tests/ -q

# Linux 全量 (权威)
python -m pytest tests/ -q          # 当前 158 用例
```

- 新增分析器/模板必须带单元测试（放 `tests/`）。
- **黑板一致性**：能走黑板路径的能力包，加"黑板 vs 独立调用结果一致"断言（参考 `tests/test_blackboard.py`）。
- 生成脚本的断言要匹配**实际输出字节**（转义/引号层数核对，参考 `tests/test_exploit.py` 的 ast 断言）。
- 模板字符串类测试在 Windows 可跑（纯字符串生成）；需要真实二进制执行的在 Linux 跑。

## 8. 代码风格

- 注释用中文，标识符/路径/命令保持英文。
- **README 禁止 emoji**（文档一致性约定）。
- 涉及新能力/新文件时，**同步更新 readme.md**（分析能力表 / 目录结构 / 测试数）。
- 不用格式化工具强约束，但保持模块内风格一致（已有模块为准）。

## 9. 提交流程

1. 本地跑相关测试（`pytest tests/test_你的模块.py`）。
2. Linux 环境跑全量（`pytest tests/ -q`），确认无回归。
3. 自查黑板协议（§4）+ 展示通配（§6）是否被破坏。
4. 提交信息遵循现有风格（`feat/fix/refactor/docs:` 前缀 + 中文要点）。
5. 推送前确认 README 同步（§8）。

> 推送说明：本仓库 `main` 分支推 GitHub。

## 10. 安全与伦理

- intelpwn 是 **CTF 练习/教学工具**：只用于你有权测试的目标（练习靶机、自建环境、授权渗透测试）。
- 禁止用于未授权系统。分析结果中的利用脚本仅限靶场环境。
- 漏洞挖掘功能（analyze + fuzz 交叉验证）面向授权目标。

---

感谢贡献。有任何疑问开 issue，或对照现有实现（`static_libc` / `menu` 是最佳参考插件）写你的第一个能力包。
