"""交叉验证 — 静态分析结果 vs 动态验证结果 的四态判定

状态:
  - 确认:     静态报 + 动态确认 (偏移一致/崩溃复现)
  - 未复现:   静态报 + 动态未崩溃 (降置信度, 不能否定 — 可能输入构造不完整)
  - 动态发现: 静态未报 + 动态崩溃 (高危信号, 反哺静态盲区)
  - canary:   canary/栈保护拦截 (SIGABRT/stack smashing) — 静态发现仍有效, 需先 leak
  - 冲突:     静态 padding 与动态实测偏移不一致 (静态算错提示)
  - 跳过:     动态未运行 (--remote / 不可执行 / 未开 --verify)

原则: "崩了"是强证据 (确认), "没崩"是弱信号 (只能降级不能否定)。
"""


def cross_validate(results: dict, dynamic: dict) -> dict:
    """静态 results + 动态 dynamic → 交叉验证表

    Args:
        results: analyze_all 的完整结果 dict
        dynamic: verify_dynamic 的结构化动态结果 dict
    Returns:
        {"entries": [...], "verdict": str}
    """
    entries = []
    dyn_crash = dynamic.get("overflow_crash") if dynamic else None
    so_list = results.get("overflow", [])

    # ── 1. 栈溢出 ──
    if so_list:
        static_pad = so_list[0].get("calculated_padding", 0)
        item = {"item": "栈溢出", "static": f"padding={static_pad}"}
        if dyn_crash is None:
            entries.append({**item, "dynamic": "动态跳过", "state": "跳过"})
        elif dyn_crash.get("error"):
            entries.append({**item, "dynamic": dyn_crash["error"], "state": "跳过",
                            "note": "动态工具不可用"})
        elif dyn_crash.get("canary_hit"):
            entries.append({**item, "dynamic": "canary 拦截 (stack smashing)",
                            "state": "canary", "note": "静态发现仍有效, 需先泄露 canary"})
        elif dyn_crash.get("cyclic_offset") is not None:
            off = dyn_crash["cyclic_offset"]
            match = abs(off - static_pad) <= 8
            entries.append({**item, "dynamic": f"实测偏移={off}",
                            "state": "确认" if match else "冲突",
                            "note": None if match else "静态 padding 与实测不符, 以实测为准"})
        elif dyn_crash.get("crash"):
            entries.append({**item, "dynamic": f"崩溃 ({dyn_crash.get('signal')}) 未提取到偏移",
                            "state": "崩溃未关联",
                            "note": "崩溃未与静态发现关联, 可能是无关的启动/运行时崩溃"})
        else:
            entries.append({**item, "dynamic": "未崩溃",
                            "state": "未复现", "note": "可能输入构造不完整, 不否定静态发现"})
    else:
        if dyn_crash and dyn_crash.get("crash") and not dyn_crash.get("canary_hit"):
            off = dyn_crash.get("cyclic_offset")
            entries.append({
                "item": "栈溢出", "static": "未报",
                "dynamic": f"崩溃 offset={off}" if off is not None else "崩溃",
                "state": "动态发现",
            })

    # ── 2. 格式化字符串偏移 ──
    fs = results.get("format_string", {})
    doff = dynamic.get("fmtstr_offset") if dynamic else None
    if fs.get("vulnerable"):
        soff = fs.get("best_offset")
        if not dynamic:
            entries.append({"item": "fmtstr 偏移", "static": soff,
                            "dynamic": "动态跳过", "state": "跳过"})
        elif doff is not None:
            match = (soff == doff)
            entries.append({
                "item": "fmtstr 偏移", "static": soff, "dynamic": doff,
                "state": "确认" if match else "冲突",
                "note": None if match else "静态偏移与实测不一致",
            })
        else:
            entries.append({"item": "fmtstr 偏移", "static": soff,
                            "dynamic": "未定位到", "state": "未复现",
                            "note": "黑盒探测未找到 AAAA 偏移"})

    # ── 3. angr 闭环 ──
    angr_res = results.get("angr_check", {})
    if angr_res.get("available") and dyn_crash:
        reachable = any(c.get("reachability", {}).get("reachable")
                        for c in angr_res.get("checks", []))
        if reachable and dyn_crash.get("crash"):
            entries.append({"item": "angr 可达性", "static": "可达",
                            "dynamic": "崩溃确认", "state": "确认"})

    # ── 结论 ──
    states = [e["state"] for e in entries]
    if "动态发现" in states:
        verdict = "动态发现 (静态盲区, 需人工复核)"
    elif "冲突" in states:
        verdict = "静态-动态冲突 (以动态实测为准)"
    elif "崩溃未关联" in states:
        verdict = "存在未关联崩溃 (需人工判断是否与静态发现相关)"
    elif "canary" in states:
        verdict = "canary 拦截 (需先泄露)"
    elif "未复现" in states:
        verdict = "存在未复现项 (降置信度)"
    elif "确认" in states:
        verdict = "静态-动态交叉确认"
    else:
        verdict = "无交叉验证项"

    return {"entries": entries, "verdict": verdict}
