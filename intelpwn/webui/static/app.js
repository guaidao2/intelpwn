/* IntelPwn 可视化前端 — 总览 / 反汇编 / CFG 三视图 */
"use strict";

// dagre 布局插件注册 (cytoscape-dagre 依赖 window.dagre, 已在 index.html 先行加载)
if (typeof cytoscape !== "undefined" && typeof cytoscapeDagre !== "undefined") {
  cytoscape.use(cytoscapeDagre);
}

let currentFunc = null;
let funcs = [];
let cy = null;

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

function esc(s) {
  const div = document.createElement("div");
  div.textContent = String(s ?? "");
  return div.innerHTML;
}

/* ── 总览 ─────────────────────────────────────────── */
function renderOverview(report) {
  const el = document.getElementById("tab-overview");
  el.innerHTML = "";
  const addCard = (title, bodyHtml) => {
    const c = document.createElement("div");
    c.className = "card";
    c.innerHTML = `<h3>${esc(title)}</h3>${bodyHtml}`;
    el.appendChild(c);
  };

  // 保护
  const p = report.protections || {};
  addCard("安全保护", `
    <div class="kv">
      <span class="k">Canary</span><span>${p.canary ? '开启' : '关闭'}</span>
      <span class="k">NX</span><span>${p.nx ? '开启' : '关闭'}</span>
      <span class="k">PIE</span><span>${p.pie ? '开启' : '关闭'}</span>
      <span class="k">RELRO</span><span>${esc(p.relro)}</span>
      <span class="k">CET SHSTK</span><span class="${p.shstk ? 'sev-high' : ''}">${p.shstk ? '开启 (ROP被硬件阻断)' : '关闭'}</span>
      <span class="k">CET IBT</span><span class="${p.ibt ? 'sev-mid' : ''}">${p.ibt ? '开启' : '关闭'}</span>
    </div>`);

  // 溢出发现
  const ov = report.overflow || [];
  addCard(`栈溢出发现 (${ov.length})`, ov.map(v => `
    <div class="kv">
      <span class="k">函数</span><span class="sev-high">${esc(v.function)}</span>
      <span class="k">padding</span><span>${esc(v.calculated_padding)}</span>
      <span class="k">危险调用</span><span>${esc(v.dangerous_call)}</span>
      <span class="k">置信度</span><span>${esc(v.confidence)}</span>
    </div>`).join("") || "<span class='hint'>无</span>");

  // 命令执行目标 (ret2text)
  const wt = report.win_targets || [];
  if (wt.length) {
    addCard("命令执行目标 (ret2text)", wt.map(t => `
      <div class="kv">
        <span class="k">地址</span><span class="sev-high">${esc(t.address)}</span>
        <span class="k">调用</span><span>${esc(t.call)}</span>
        <span class="k">参数</span><span>${esc(t.string)}</span>
      </div>`).join(""));
  }

  // 交叉验证
  const cv = report.cross_validation || {};
  if (cv.entries && cv.entries.length) {
    addCard(`交叉验证 (${esc(cv.verdict)})`, cv.entries.map(e => `
      <div class="kv">
        <span class="k">${esc(e.item)}</span>
        <span class="${e.state === '确认' ? 'sev-low' : e.state === '未复现' ? 'sev-mid' : 'sev-high'}">${esc(e.state)}</span>
        <span class="k">静态</span><span>${esc(e.static)}</span>
        <span class="k">动态</span><span>${esc(e.dynamic)}</span>
      </div>`).join(""));
  }

  // 综合发现
  const s = report.summary || {};
  addCard(`综合发现 (${esc(s.max_severity)})`, (s.findings || []).map(f => `
    <div class="kv">
      <span class="k">${esc(f.type)}</span>
      <span class="${f.severity === '高危' || f.severity === '严重' ? 'sev-high' : 'sev-mid'}">${esc(f.severity)}</span>
      <span class="k">详情</span><span>${esc(f.detail)}</span>
    </div>`).join("") || "<span class='hint'>无</span>");

  // 格式化字符串
  const fs = report.format_string || {};
  addCard("格式化字符串", fs.vulnerable ? `
    <div class="kv"><span class="k">状态</span><span class="sev-high">发现漏洞</span></div>
    ${fs.best_offset ? `<div class="kv"><span class="k">最佳偏移</span><span>${esc(fs.best_offset)} (可用 %${esc(fs.best_offset)}$p 泄露)</span></div>` : ""}
    <div class="kv"><span class="k">证据</span><span>${esc((fs.evidence || []).join("; ")) || "—"}</span></div>
    <div class="kv"><span class="k">利用</span><span>%n 覆写 GOT → 劫持控制流</span></div>`
    : "<span class='hint'>未检测到格式化字符串漏洞</span>");

  // 栈布局 (推导自 overflow[0])
  const ov0 = ov[0];
  if (ov0 && ov0.stack_size != null) {
    const bitsSz = /64/.test(String(p.bits || "")) ? 8 : 4;
    const padN = parseInt(ov0.calculated_padding || 0, 10) || 0;
    const stk = parseInt(ov0.stack_size || 0, 10) || 0;
    const align = padN - stk - bitsSz;
    addCard("栈布局", `
      <div class="kv">
        <span class="k">布局</span>
        <span>[bof(${stk})]${align > 0 ? ` + [对齐(${align})]` : ""} + [saved_rbp(${bitsSz})] + [ret_addr]</span>
      </div>
      <div class="kv"><span class="k">padding</span><span class="sev-high">${padN}</span></div>
      <div class="kv"><span class="k">含义</span><span>填充 ${padN} 字节后覆盖返回地址</span></div>`);
  }

  // ROP Gadgets
  const rop = report.rop || {};
  const known = { pop_rdi: "ret2libc 必备", pop_rsi: "第二参数", pop_rdx: "第三参数",
                  ret: "栈对齐 (绕过 movaps)", pop_eax: "syscall 编号", int_0x80: "系统调用",
                  ret2csu: "__libc_csu_init 三参调用", pop_pop_ret: "x86 多参清理" };
  const ropList = Object.entries(known)
    .map(([g, hint]) => [g, rop[g]])
    .filter(([, a]) => a && a !== "未找到" && typeof a !== "object");
  addCard("ROP Gadgets", ropList.length ? ropList.map(([g, a]) => `
    <div class="kv"><span class="k">${esc(g)}</span><span>${esc(a)} <span class="hint">← ${esc(known[g])}</span></span></div>`).join("")
    + `<div class="kv"><span class="k">共</span><span>${ropList.length} 个可用 gadgets</span></div>`
    : "<span class='hint'>未找到关键 ROP gadgets</span>");

  // GOT 表
  const got = report.got || {};
  const gotList = Object.entries(got);
  if (gotList.length) {
    const leakTag = { puts: "LEAK", write: "LEAK", printf: "FMT", read: "BOF", gets: "BOF" };
    addCard(`GOT 表 (${gotList.length})`, gotList.map(([n, a]) => `
      <div class="kv"><span class="k">${esc(n)}</span><span>${esc(a)}${leakTag[n] ? ` <span class="hint">[${leakTag[n]}]</span>` : ""}</span></div>`).join(""));
  }

  // BSS / 可写内存
  const bss = report.bss_writable || [];
  if (bss.length) {
    addCard(`BSS / 可写内存 (${bss.length})`, bss.map(b => `
      <div class="kv"><span class="k">${esc(b.name)}</span><span>${esc(b.addr)}, size=${esc(b.size)}</span></div>`).join(""));
  }

  // 关键资源
  const hasBinsh = report.has_binsh;
  if (hasBinsh != null) {
    addCard("关键资源", `<div class="kv"><span class="k">/bin/sh</span>` +
      (hasBinsh ? `<span class="sev-low">存在于二进制 → 可直接 ret2system</span>` : `<span>不在二进制 → 需从 libc 找</span>`) + `</div>`);
  }

  // 静态链接 libc 符号 (主力卡片: 固定地址可直接利用)
  const sl = report.static_libc;
  if (sl && Object.keys(sl).length) {
    const syms = sl.symbols || {};
    addCard("静态链接 libc 符号", `
      <div class="kv"><span class="k">system</span><span class="sev-low">${esc(sl.system_addr)}</span></div>
      <div class="kv"><span class="k">execve</span><span>${esc(sl.execve_addr)}</span></div>
      <div class="kv"><span class="k">/bin/sh</span><span class="sev-low">${esc(sl.binsh_addr)}</span></div>
      <div class="kv"><span class="k">说明</span><span>静态链接: 固定地址, 无需 libc leak</span></div>
      ${Object.keys(syms).length ? `<div class="kv"><span class="k">符号</span><span>${esc(Object.keys(syms).join(", "))}</span></div>` : ""}
    `);
  }

  // 堆分析
  const heap = report.heap_analysis || {};
  if (heap && heap.has_heap) {
    const gv = heap.glibc || {};
    addCard("堆分析", `
      <div class="kv"><span class="k">堆函数</span><span>${esc((heap.functions || []).join(", "))}</span></div>
      <div class="kv"><span class="k">复杂度</span><span>${esc(heap.complexity)} (函数数 ${esc(heap.function_count)})${heap.complexity > 30 ? " <span class='sev-mid'>→ 可能含堆漏洞</span>" : ""}</span></div>
      ${gv.version ? `<div class="kv"><span class="k">glibc</span><span class="sev-mid">${esc(gv.version)}</span></div>
      <div class="kv"><span class="k">tcache</span><span>${esc(gv.tcache || "?")}</span></div>
      <div class="kv"><span class="k">safe-linking</span><span>${gv.safe_linking ? '开启 (需 heap 泄露)' : '关闭'}</span></div>
      <div class="kv"><span class="k">__free_hook</span><span>${gv.free_hook ? '可用' : '已移除'}</span></div>
      <div class="kv"><span class="k">攻击面</span><span>${esc(gv["攻击面"] || "?")}</span></div>` : ""}
      ${(heap.clues || []).map(c => `<div class="kv"><span class="${c.severity === '高危' || c.severity === '严重' ? 'sev-high' : 'sev-mid'}">${esc(c.severity)}</span><span>${esc(c.detail)}</span></div>`).join("")}
      ${(heap.uaf_chains || []).map(u => `<div class="kv"><span class="sev-high">UAF</span><span>选项 ${esc(u.free_option)} (free@${esc(u.free_addr)}) → 选项 ${esc(u.use_option)} (${esc(u.use_callee)}@${esc(u.use_addr)}) 同一对象数组 ${esc(u.array_base)}</span></div>`).join("")}`);
  }

  // angr 符号执行
  const angr = report.angr_check || {};
  if (angr && Object.keys(angr).length) {
    let body;
    if (!angr.available) {
      body = "<span class='hint'>angr 未安装, 已跳过 (可选: pip install angr)</span>";
    } else {
      body = (angr.checks || []).map(ch => {
        const rch = ch.reachability || {};
        const sc = ch.size_check || {};
        let line = `<div class="kv"><span class="k">${esc(ch.function)}</span>`;
        if (rch.reachable) {
          line += `<span class="sev-low">可达</span>`;
          if (sc.status === "concrete")
            line += `<span class="${sc.dangerous ? 'sev-high' : 'sev-low'}">大小=${esc(sc.size)} ${sc.dangerous ? "超过栈缓冲" : "未超过"}</span>`;
          else if (sc.status === "symbolic")
            line += `<span class="${sc.dangerous ? 'sev-high' : 'sev-mid'}">符号大小, 最大=${esc(sc.max_possible)}</span>`;
        } else if (rch.reachable === false) {
          line += `<span class="sev-mid">不可达 (疑似死代码)</span>`;
        } else {
          line += `<span class="hint">可达性未知 (${esc(rch.reason || "")})</span>`;
        }
        return line + `</div>`;
      }).join("");
      body += (angr.int_overflow || []).map(i => `<div class="kv"><span class="k">整数溢出</span><span class="sev-mid">${esc(i.detail)}</span></div>`).join("");
      body += (angr.discovered || []).map(d => {
        let desc = "";
        if (d.status === "truncated") desc = d.reason || "符号执行截断";
        else if (d.vuln === "unbounded_write")
          desc = "无界写 → 栈上溢出" + (d.padding != null ? ` padding=${d.padding}` : "");
        else if (d.size_symbolic)
          desc = `大小符号化 最大=${d.size_max}` + (d.dangerous ? " 可能溢出" : "");
        else if (d.dangerous) desc = `大小=${d.size_max} 超过栈缓冲`;
        if (d.discovered_by === "angr") desc += " [angr 主动发现]";
        const tag = (d.dangerous || d.vuln) ? "sev-high" : d.status === "truncated" ? "sev-mid" : "hint";
        return `<div class="kv"><span class="k">${esc(d.callee)}</span><span class="${tag}">${esc(desc)}${d.stack_buf ? " 栈上" : ""}</span></div>`;
      }).join("");
    }
    addCard("符号执行 (angr)", body || "<span class='hint'>无</span>");
  }

  // 兜底: 未硬编码渲染的 key → 通用折叠卡片 (插件分析器输出即所见, 不再改前端)
  const KNOWN_KEYS = new Set(["protections", "overflow", "format_string", "got", "rop",
    "bss_writable", "has_binsh", "heap_analysis", "angr_check", "win_targets",
    "cross_validation", "summary", "path", "bits", "plt", "static_libc"]);
  const extraKeys = Object.keys(report).filter(k => !KNOWN_KEYS.has(k));
  for (const k of extraKeys) {
    const body = `<details><summary>原始数据 (插件输出)</summary>` +
                 `<pre style="white-space:pre-wrap;max-height:280px;overflow:auto">` +
                 esc(JSON.stringify(report[k], null, 2)) + `</pre></details>`;
    addCard(`其他发现: ${esc(k)}`, body);
  }

  document.getElementById("binary-name").textContent =
    report.path ? "目标: " + report.path : "";
}

/* ── 函数列表 ─────────────────────────────────────── */
function renderFuncList(list) {
  funcs = list;
  const ul = document.getElementById("func-list");
  ul.innerHTML = "";
  for (const f of list) {
    const li = document.createElement("li");
    li.className = f.vuln ? "vuln" : "";
    li.innerHTML = `<span class="name">${esc(f.name)}</span>` +
                   (f.padding != null ? `<span class="pad">pad=${esc(f.padding)}</span>` : "");
    li.onclick = () => selectFunc(f, li);
    ul.appendChild(li);
  }
  // 默认选第一个有漏洞的函数
  const first = list.find(f => f.vuln) || list[0];
  if (first) selectFunc(first, ul.querySelector(".vuln") || ul.children[0]);
}

function selectFunc(f, li) {
  currentFunc = f;
  document.querySelectorAll("#func-list li").forEach(x => x.classList.remove("active"));
  if (li) li.classList.add("active");
  document.getElementById("disasm-title").textContent =
    `反汇编: ${f.name} @ 0x${f.start.toString(16)}`;
  document.getElementById("cfg-title").textContent =
    `CFG: ${f.name} @ 0x${f.start.toString(16)}`;
  renderDisasm(f);
  renderCFG(f);
}

/* ── 反汇编 ───────────────────────────────────────── */
async function renderDisasm(f) {
  const box = document.getElementById("disasm-box");
  box.textContent = "加载中...";
  try {
    const d = await getJSON(`/api/disasm/${f.start}`);
    if (d.error) { box.textContent = d.error; return; }
    box.innerHTML = "";
    for (const line of d.lines) {
      const div = document.createElement("div");
      div.className = "dline" + (line.mark ? " mark" : "") +
                      (line.lea_stack ? " lea" : "") +
                      (line.call ? " call" : "");
      div.innerHTML = `<span class="a">0x${line.addr.toString(16)}</span>` +
                      `<span class="m">${esc(line.mnemonic)}</span>` +
                      `<span class="o">${esc(line.op_str)}</span>` +
                      (line.note ? `<span class="n n-${esc(line.note_level)}">; ${esc(line.note)}</span>` : "");
      box.appendChild(div);
    }
  } catch (e) {
    box.textContent = "反汇编加载失败: " + e.message;
  }
}

/* ── CFG 图 ───────────────────────────────────────── */
async function renderCFG(f) {
  const div = document.getElementById("cy");
  div.textContent = "";
  try {
    const cfg = await getJSON(`/api/cfg/${f.start}`);
    if (cfg.error || !cfg.nodes.length) {
      div.innerHTML = "<p class='hint'>该函数无 CFG 数据</p>";
      return;
    }
    const marked = new Set(cfg.marked);
    const elements = [];
    for (const n of cfg.nodes) {
      const insns = n.insns.slice(0, 12);
      const isVuln = marked.has(n.id);
      elements.push({
        data: {
          id: String(n.id),
          label: `0x${n.start.toString(16)}`,
          insns,  // 供右侧详情面板渲染 (完整)
          html: insns.slice(0, 6)   // 节点标签只显示前 6 行, 防止节点过高互相重叠
            .map(i => `${i.mnemonic} ${i.op_str}`.trim())
            .map(esc).join("<br>"),
          // 注意: 普通块不写 vuln 字段 (cytoscape 的 [vuln] 选择器匹配"字段存在",
          // 若给普通块写 vuln:false 会导致全部命中红色样式)
          ...(isVuln ? { vuln: true } : {}),
        },
      });
    }
    for (const [a, b] of cfg.edges) {
      elements.push({ data: { id: `${a}->${b}`, source: String(a), target: String(b) } });
    }
    if (cy) cy.destroy();
    cy = cytoscape({
      container: div,
      elements,
      style: [
        // 普通块: 深蓝底
        { selector: "node", style: {
            "background-color": "#1f3a5f",
            "border-color": "#30363d", "border-width": 1,
            "color": "#c9d1d9", "font-size": "11px",
            "text-valign": "bottom", "text-margin-y": 2,
            "label": "data(label)",
            "width": 130, "height": "label",
            "shape": "round-rectangle",
            "text-wrap": "wrap", "text-max-width": 130,
            "padding": "6px",
          } },
        // 漏洞块: 红色底 + 红边 (定点标记)
        { selector: "node[vuln]", style: {
            "background-color": "#f85149",
            "border-color": "#ff7b72", "border-width": 2,
            "color": "#ffffff", "font-weight": "bold",
          } },
        { selector: "edge", style: {
            "curve-style": "bezier", "target-arrow-shape": "triangle",
            "line-color": "#30363d", "target-arrow-color": "#30363d",
          } },
      ],
      layout: { name: "dagre", spacingFactor: 1.5 },
    });
    // 点节点 → 右侧独立面板显示块内反汇编 (不浮在图上)
    cy.on("tap", "node", evt => {
      const node = evt.target;
      const det = document.getElementById("cfg-detail");
      det.innerHTML = "";
      const h = document.createElement("div");
      h.className = "cfg-detail-title";
      h.innerHTML = `块 @ <b>${node.data("label")}</b>` +
        (node.data("vuln") ? ' <span style="color:#f85149;font-weight:bold">[漏洞块]</span>' : "");
      det.appendChild(h);
      for (const i of node.data("insns") || []) {
        const d = document.createElement("div");
        d.className = "dline";
        d.innerHTML = `<span class="a">0x${i.addr.toString(16)}</span>` +
                      `<span class="m">${esc(i.mnemonic)}</span>` +
                      `<span class="o">${esc(i.op_str)}</span>`;
        det.appendChild(d);
      }
    });
    // 初始自动选中漏洞块
    const vulnNode = cy.$("node[vuln]").first();
    if (vulnNode.length) { vulnNode.emit("tap"); cy.center(vulnNode); }
  } catch (e) {
    div.innerHTML = "<p class='hint'>CFG 加载失败: " + esc(e.message) + "</p>";
  }
}

/* ── 调用图 (全局关系) ─────────────────────────── */
let cg = null;
let cgLoaded = false;
let showCrt = false;   // CRT 样板函数默认隐藏 (噪音)

async function renderCallGraph() {
  const div = document.getElementById("cy-callgraph");
  div.textContent = "";
  if (cg) cg.destroy();
  cg = null;
  try {
    const g = await getJSON("/api/callgraph");
    if (g.error || !g.nodes.length) {
      div.innerHTML = "<p class='hint'>无调用图数据: " + esc(g.error || "") + "</p>";
      return;
    }
    const visible = new Set();
    for (const n of g.nodes) {
      if (!showCrt && n.crt) continue;
      visible.add(String(n.id));
    }
    const elements = [];
    for (const n of g.nodes) {
      if (!visible.has(String(n.id))) continue;
      const tag = n.entry ? "entry" : n.vuln ? "vuln" : n.danger ? "danger" : "norm";
      elements.push({
        data: { id: String(n.id), label: n.name,
                addr: n.addr, tag, onPath: !!n.on_path },
      });
    }
    for (const e of g.edges) {
      if (visible.has(String(e.source)) && visible.has(String(e.target))) {
        elements.push({ data: { id: `${e.source}->${e.target}`, source: String(e.source), target: String(e.target) } });
      }
    }
    cg = cytoscape({
      container: div,
      elements,
      style: [
        { selector: "node", style: {
            "background-color": "#1f3a5f", "border-color": "#30363d", "border-width": 1,
            "color": "#c9d1d9", "font-size": "11px", "label": "data(label)",
            "width": "label", "height": 26, "shape": "round-rectangle",
            "text-valign": "center", "padding": "6px",
            "text-wrap": "wrap", "text-max-width": 170,  // 长函数名换行, 节点不自适应撑宽
          } },
        { selector: "node[tag = 'vuln']", style: {
            "background-color": "#f85149", "border-color": "#ff7b72", "border-width": 3,
            "color": "#ffffff", "font-weight": "bold" } },
        { selector: "node[tag = 'danger']", style: {
            "background-color": "#6b5a1e", "border-color": "#d29922", "border-width": 2 } },
        { selector: "node[tag = 'entry']", style: {
            "background-color": "#1f6f43", "border-color": "#3fb950", "border-width": 2 } },
        // 攻击路径: 蓝色粗边框
        { selector: "node[onPath = 'true']", style: {
            "border-color": "#58a6ff", "border-width": 2 } },
        { selector: "node[tag = 'vuln'][onPath = 'true']", style: { "border-width": 4 } },
        { selector: "edge", style: {
            "curve-style": "bezier", "target-arrow-shape": "triangle",
            "line-color": "#30363d", "target-arrow-color": "#30363d", "width": 1 } },
      ],
      layout: { name: "dagre", spacingFactor: 1.3, rankDir: "LR" },
    });
    // 点节点 → 右侧面板显示该函数反汇编
    const det = document.getElementById("cfg-detail-callgraph");
    cg.on("tap", "node", async evt => {
      const node = evt.target;
      det.innerHTML = "加载中...";
      try {
        const d = await getJSON(`/api/disasm/${node.data("addr")}`);
        if (d.error) { det.innerHTML = esc(d.error); return; }
        det.innerHTML = "";
        const h = document.createElement("div");
        h.className = "cfg-detail-title";
        const tagTxt = node.data("tag") === "vuln" ? ' <span style="color:#f85149;font-weight:bold">[漏洞]</span>'
                     : node.data("tag") === "danger" ? ' <span style="color:#d29922;font-weight:bold">[危险]</span>'
                     : node.data("tag") === "entry" ? ' <span style="color:#3fb950">[入口]</span>' : "";
        h.innerHTML = `函数 @ <b>${esc(node.data("label"))}</b>${tagTxt}`;
        det.appendChild(h);
        for (const l of d.lines) {
          const row = document.createElement("div");
          row.className = "dline" + (l.mark ? " mark" : "");
          row.innerHTML = `<span class="a">0x${l.addr.toString(16)}</span>` +
                          `<span class="m">${esc(l.mnemonic)}</span>` +
                          `<span class="o">${esc(l.op_str)}</span>` +
                          (l.note ? `<span class="n n-${esc(l.note_level)}">; ${esc(l.note)}</span>` : "");
          det.appendChild(row);
        }
      } catch (e) {
        det.innerHTML = "加载失败: " + esc(e.message);
      }
    });
    // 自动选中第一个漏洞函数并居中
    const v = cg.$("node[tag = 'vuln']").first();
    if (v.length) { v.emit("tap"); cg.center(v); }
  } catch (e) {
    div.innerHTML = "<p class='hint'>调用图加载失败: " + esc(e.message) + "</p>";
  }
}

/* ── Tab 切换 ─────────────────────────────────────── */
document.querySelectorAll(".tab").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "cfg" && cy) cy.resize();
    if (btn.dataset.tab === "callgraph" && !cgLoaded) { cgLoaded = true; renderCallGraph(); }
    if (btn.dataset.tab === "callgraph" && cg) cg.resize();
  };
});

/* 黄/灰注释开关 (红注释始终显示) */
const notesToggle = document.getElementById("notes-toggle");
if (notesToggle) {
  notesToggle.onchange = () => {
    document.getElementById("disasm-box").classList.toggle("hide-sub", !notesToggle.checked);
  };
}

/* CRT 样板函数开关 (调用图) */
const crtToggle = document.getElementById("crt-toggle");
if (crtToggle) {
  crtToggle.onchange = () => {
    showCrt = crtToggle.checked;
    if (cgLoaded) renderCallGraph();
  };
}

/* 可拖拽分隔条: 图 / 汇编面板宽度手调 (自适应) — 基于拖拽增量, 双向对称 */
function enableDragHandle(handleId, panelId, cyRef) {
  const handle = document.getElementById(handleId);
  const panel = document.getElementById(panelId);
  if (!handle || !panel) return;
  let startX = 0, startW = 0, dragging = false;
  handle.addEventListener("mousedown", e => {
    dragging = true;
    startX = e.clientX;
    startW = panel.getBoundingClientRect().width;
    handle.classList.add("dragging");
    e.preventDefault();
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    // 左拖 (clientX 减小) → 面板变宽; 右拖 → 变窄
    let w = startW + (startX - e.clientX);
    w = Math.max(240, Math.min(w, 560));
    // 窄窗口: 面板不超过容器可用宽 (图至少留 80px)
    const wrapW = handle.parentElement.clientWidth;
    if (wrapW > 0) w = Math.min(w, wrapW - 80);
    w = Math.max(240, w);
    panel.style.width = w + "px";
    // 图容器尺寸变了, 实时重排 canvas (自适应)
    const inst = cyRef ? cyRef() : null;
    if (inst) inst.resize();
  });
  document.addEventListener("mouseup", () => {
    if (dragging) { dragging = false; handle.classList.remove("dragging"); }
  });
}
enableDragHandle("cfg-handle", "cfg-detail", () => cy);
enableDragHandle("cg-handle", "cfg-detail-callgraph", () => cg);

/* ── 初始化 ───────────────────────────────────────── */
(async function init() {
  try {
    const [report, list] = await Promise.all([
      getJSON("/api/report"),
      getJSON("/api/functions"),
    ]);
    renderOverview(report);
    renderFuncList(list);
  } catch (e) {
    document.getElementById("func-list").innerHTML =
      "<li class='hint'>加载失败: " + esc(e.message) + "</li>";
  }
})();
