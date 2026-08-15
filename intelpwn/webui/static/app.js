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
                      `<span class="o">${esc(line.op_str)}</span>`;
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

/* ── Tab 切换 ─────────────────────────────────────── */
document.querySelectorAll(".tab").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "cfg" && cy) cy.resize();
  };
});

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
