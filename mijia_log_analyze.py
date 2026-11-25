#!/usr/bin/env python3
"""mijia_log_analyze.py — 统计每条自动化策略与节点的执行频率，输出自包含 HTML。

数据源（mijia_gw_out/，由 mijia_geek_client.py 在线抓取生成）：
  mijia_strategies.json  规则图（节点/连边）
  mijia_logs_raw.json    原始日志（3|ts|类型|gid|...）
  mijia_id_map.json      规则/设备/变量 ID → 实际名字

输出：
  mijia_log_analysis.html  自包含 HTML（mermaid.js 走 CDN 渲染框图；
    - 顶部：策略执行频率总表（按次数排序，点击跳转对应策略卡片）
    - 每条策略卡片：
        * Mermaid 框图（节点按执行频次着色：灰=0 蓝=低 黄=中 红=高）
        * 点击框图节点 或 右侧节点表行 → 弹出该节点执行频率详情
        * 「策略执行频率」按钮 → 展开按天分布柱状图 + 高峰时段
    离线打开时 mermaid CDN 不可用则框图不渲染，节点表仍可点击查看。

用法：
  python mijia_log_analyze.py [--gw-out DIR] [--out FILE]
"""

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mijia_flow  # noqa: E402  复用 node_label / render_rule_mermaid / _mermaid_node_id


# ---------------------------------------------------------------- 数据计算

def load_inputs(gw_out: Path):
    strat = json.loads((gw_out / "mijia_strategies.json").read_text(encoding="utf-8-sig"))
    raw = json.loads((gw_out / "mijia_logs_raw.json").read_text(encoding="utf-8"))
    idmap = json.loads((gw_out / "mijia_id_map.json").read_text(encoding="utf-8-sig"))
    return strat, raw, idmap


def build_names(strat, idmap):
    """设备/变量/规则名映射（优先 id_map，退回 strategies 内 names）。"""
    names = strat.get("names") or {}
    devs = dict(names.get("设备") or idmap.get("设备") or {})
    varn = dict(names.get("变量") or idmap.get("变量") or {})
    rules = dict(names.get("规则") or idmap.get("规则") or {})
    for r in strat.get("rules", []):
        gid = str((r.get("cfg") or {}).get("id"))
        rules.setdefault(gid, (r.get("cfg") or {}).get("name")
                          or (r.get("cfg", {}).get("userData") or {}).get("name") or gid)
    return devs, varn, rules


def analyze(raw, strat, rules_name):
    """扫日志，产出 每规则/每节点 的 i 触发统计。"""
    dev_rule = {}  # gid -> rule dict
    for r in strat.get("rules", []):
        dev_rule[str((r.get("cfg") or {}).get("id"))] = r

    stat = {}      # gid -> {...}
    for gid, r in dev_rule.items():
        stat[gid] = {
            "name": rules_name.get(gid, gid),
            "total": 0, "last": 0,
            "byDay": Counter(), "hours": Counter(),
            "nodes": {},          # nid -> {label,cnt,ok,bad,vals,byDay}
            "node_cnt": Counter(),
        }
    node_owner = {}  # 全局 nid -> gid（节点一般唯一属于一条规则）
    for gid, r in dev_rule.items():
        for n in r.get("nodes", []):
            node_owner.setdefault(str(n.get("id")), gid)

    t0, t1 = 1 << 62, 0
    for ln in raw:
        p = ln.split("|")
        if len(p) < 6 or p[2] != "i":
            continue
        try:
            ts = int(p[1])
        except ValueError:
            continue
        gid, nid, info = p[3], p[4], p[5]
        st = stat.get(gid)
        if st is None:
            continue
        st["total"] += 1
        st["last"] = max(st["last"], ts)
        day = time.strftime("%m-%d", time.localtime(ts / 1000))
        st["byDay"][day] += 1
        st["hours"][time.localtime(ts / 1000).tm_hour] += 1
        t0, t1 = min(t0, ts), max(t1, ts)

        nd = st["nodes"].get(nid)
        if nd is None:
            nd = st["nodes"][nid] = {"cnt": 0, "ok": 0, "bad": 0,
                                      "vals": Counter(), "byDay": Counter()}
        nd["cnt"] += 1
        if info == "success":
            nd["ok"] += 1
        else:
            nd["bad"] += 1
            nd["vals"][info[:60]] += 1
        nd["byDay"][day] += 1
        st["node_cnt"][nid] += 1

    if t0 > t1:
        t0, t1 = 0, 0
    return stat, t0, t1, dev_rule, node_owner


# ---------------------------------------------------------------- HTML 生成

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0f18;color:#c7d2ea;font:14px/1.55 'Segoe UI','Microsoft YaHei',sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:20px 24px 60px}
h1{font-size:20px;color:#e8eefb;margin:6px 0 2px}
.meta{color:#8fa3c8;font-size:12px;margin-bottom:18px}
.card{background:#101623;border:1px solid #1c2740;border-radius:12px;padding:14px 16px;margin-bottom:16px}
h2{font-size:16px;color:#e8eefb;margin:0 0 10px}
table{border-collapse:collapse;width:100%}
th,td{padding:5px 8px;border-bottom:1px solid #1c2740;text-align:left;vertical-align:middle}
th{color:#8fa3c8;font-size:12px;font-weight:600}
.bar{height:10px;background:#26324d;border-radius:5px;overflow:hidden;min-width:120px}
.bar i{display:block;height:100%;background:#4f8cff}
a{color:#5b9bff;text-decoration:none;cursor:pointer}
.rule{background:#101623;border:1px solid #1c2740;border-radius:12px;margin-bottom:14px;overflow:hidden}
.rule .head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;
  background:linear-gradient(90deg,#141d33,#101623);border-bottom:1px solid #1c2740}
.rule .head .nm{font-size:15px;font-weight:600;color:#e8eefb}
.tag{font-size:11px;padding:1px 8px;border-radius:9px;background:#1c2740;color:#8fa3c8}
.tag.on{background:#1e4429;color:#7ee0a1}
.tag.off{background:#4d1f24;color:#f2a3a3}
.rule .body{display:grid;grid-template-columns:minmax(320px,1.2fr) minmax(300px,1fr);gap:14px;padding:14px 16px}
@media(max-width:900px){.rule .body{grid-template-columns:1fr}}
.mbox{min-height:220px}
.node-table{max-height:520px;overflow:auto;border:1px solid #1c2740;border-radius:8px}
.node-table table{font-size:12px}
.node-table tr{cursor:pointer}
.node-table tr:hover td{background:#18233d}
.legend{font-size:11px;color:#8fa3c8;margin:4px 0 0}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px -1px 10px;vertical-align:baseline}
.btn{background:#1c2b4a;color:#9fc1f0;border:1px solid #2a3c66;border-radius:6px;font-size:12px;
  padding:3px 10px;cursor:pointer}
.btn:hover{background:#24375f}
#panel{position:fixed;right:16px;bottom:16px;width:360px;max-width:calc(100vw - 32px);max-height:70vh;
  overflow:auto;background:#141d33;border:1px solid #2a3c66;border-radius:12px;padding:14px 16px;
  box-shadow:0 10px 40px rgba(0,0,0,.6);display:none;z-index:9}
#panel h3{margin:0 0 6px;font-size:14px;color:#e8eefb}
#panel .x{float:right;cursor:pointer;color:#8fa3c8}
.days{margin:8px 0}
.days .row{display:flex;align-items:center;gap:6px;font-size:11px;margin:2px 0}
.days .lb{width:44px;color:#8fa3c8;text-align:right}
.days .tr{flex:1;height:10px;background:#1c2740;border-radius:5px;overflow:hidden}
.days .tr i{display:block;height:100%;background:#4f8cff}
.days .v{width:38px;color:#c7d2ea;font-size:11px}
.warn{color:#ffb454;font-size:12px;margin-top:6px}
"""


def _bars(counter: Counter, total: int) -> str:
    """Counter -> 按天柱状 HTML（升序天）。"""
    if not counter:
        return ""
    mx = max(counter.values())
    out = ['<div class="days">']
    for day in sorted(counter):
        c = counter[day]
        w = int(100 * c / mx) if mx else 0
        out.append(f'<div class="row"><span class="lb">{day}</span>'
                   f'<span class="tr"><i style="width:{w}%"></i></span>'
                   f'<span class="v">{c}</span></div>')
    out.append("</div>")
    return "".join(out)


def _fmt_ts(ts):
    return time.strftime("%m-%d %H:%M:%S", time.localtime(ts / 1000)) if ts else "—"


def build_html(stat, dev_rule, node_owner, dev_name, var_name, t0, t1):
    # ---- 每规则节点标签 & 频次着色 ----
    gid_rank = sorted(stat, key=lambda g: -stat[g]["total"])
    data_rules = []
    mermaids = {}
    for gid in gid_rank:
        st = stat[gid]
        r = dev_rule.get(gid) or {}
        nodes = r.get("nodes", [])
        labels = {str(n.get("id")): mijia_flow.node_label(n, dev_name, var_name)
                  for n in nodes}
        rule_node_data = {}
        for nid, nd in st["nodes"].items():
            rule_node_data[nid] = {
                "label": labels.get(nid, nid),
                "cnt": nd["cnt"], "ok": nd["ok"], "bad": nd["bad"],
                "vals": nd["vals"].most_common(5),
                "byDay": dict(nd["byDay"]),
            }
        data_rules.append({
            "gid": gid, "name": st["name"], "total": st["total"],
            "nNodes": len(nodes), "last": st["last"],
            "byDay": dict(st["byDay"]),
            "hours": st["hours"].most_common(6),
            "nodes": rule_node_data,
        })
        # ---- mermaid：基图 + 着色 + 点击 ----
        if nodes:
            src = mijia_flow.render_rule_mermaid(r, dev_name, var_name).splitlines()
            src.append('classDef c0 fill:#242c44,stroke:#39415a,color:#aeb8d0')
            src.append('classDef c1 fill:#173d63,stroke:#2f5f8f,color:#bcd4f5')
            src.append('classDef c2 fill:#6b4a12,stroke:#b07818,color:#ffe2a8')
            src.append('classDef c3 fill:#6b1a15,stroke:#c0392b,color:#ffb0a8')
            cls = {"c0": [], "c1": [], "c2": [], "c3": []}
            for n in nodes:
                nid = str(n.get("id"))
                c = st["node_cnt"].get(nid, 0)
                key = "c3" if c >= 1000 else "c2" if c >= 100 else "c1" if c >= 1 else "c0"
                cls[key].append(mijia_flow._mermaid_node_id(nid))
            for k, ids in cls.items():
                if ids:
                    src.append(f"class {','.join(ids)} {k}")
            # mermaid 10.9 的 click 指令必须带 call 关键字，参数才能传字符串
            for n in nodes:
                nid = str(n.get("id"))
                src.append(f'click {mijia_flow._mermaid_node_id(nid)} '
                           f'call nodeClick("{gid}","{nid}")')
            mermaids[gid] = "\n".join(src)
    payload = {
        "range": [t0, t1],
        "rules": data_rules,
    }
    js_data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")

    # ---- 顶部总表 ----
    mx = max((x["total"] for x in data_rules), default=1)
    rows = []
    for i, dr in enumerate(data_rules, 1):
        w = int(100 * dr["total"] / mx) if mx else 0
        rows.append(
            f'<tr><td style="width:34px;color:#5d6b8f">{i:02d}</td>'
            f'<td><a href="#rule-{dr["gid"]}" onclick="showRule({i})">{dr["name"]}</a></td>'
            f'<td style="width:150px"><div class="bar"><i style="width:{w}%"></i></div></td>'
            f'<td style="width:80px;text-align:right">{dr["total"]:,}</td>'
            f'<td style="width:60px;color:#8fa3c8">{dr["nNodes"]}</td>'
            f'<td style="width:90px;color:#8fa3c8">{_fmt_ts(dr["last"])}</td></tr>')
    span_d = (t1 - t0) / 86400000 if t1 > t0 else 0
    span_s = (t1 - t0) / 1000 if t1 > t0 else 0

    # ---- 策略卡片（框图 + 节点表 + 频率详情） ----
    cards = []
    for i, dr in enumerate(data_rules, 1):
        m = mermaids.get(dr["gid"], "")
        mer_div = (f'<pre class="mermaid">{m}</pre>' if m
                   else '<div class="warn">该规则无节点</div>')
        # 节点表：按频次降序
        nitems = sorted(dr["nodes"].items(), key=lambda kv: -kv[1]["cnt"])
        trows = []
        for nid, nd in nitems:
            extra = ""
            if nd["bad"]:
                vv = ", ".join(v[0][:18] for v in nd["vals"][:2])
                extra = f'<span class="warn">值:{vv}</span>'
            trows.append(
                f'<tr onclick="nodeClick(\'{dr["gid"]}\',\'{nid}\')">'
                f'<td>{nd["label"]}</td>'
                f'<td style="text-align:right">{nd["cnt"]:,}</td>'
                f'<td style="text-align:right;color:#5d6b8f">{nid}</td></tr>')
        cards.append(f"""
<div class="rule" id="rule-{dr['gid']}">
  <div class="head" onclick="toggleRule({i})">
    <span class="tag on">启用</span><span class="nm">{dr['name']}</span>
    <span class="tag">{dr['nNodes']} 节点</span>
    <span class="tag">触发 {dr['total']:,} 次</span>
    <span style="flex:1"></span>
    <button class="btn" onclick="event.stopPropagation();toggleRule({i})">策略执行频率 ▾</button>
  </div>
  <div class="body">
    <div class="mbox">{mer_div}
      <div class="legend">节点颜色=执行频次<i style="background:#242c44"></i>0 <i style="background:#173d63"></i>1-99 <i style="background:#6b4a12"></i>100-999 <i style="background:#6b1a15"></i>≥1000　（点击节点查看频率）</div>
    </div>
    <div class="node-table"><table>
      <tr><th>节点</th><th style="text-align:right">执行次数</th><th style="text-align:right">节点 ID</th></tr>
      {''.join(trows)}
    </table></div>
  </div>
  <div id="rdetail-{i}" style="display:none;padding:12px 16px;border-top:1px solid #1c2740">
    <b>策略执行频率</b>：共 {dr['total']:,} 次（近 {span_d:.1f} 天，日均 {dr['total']/max(1,span_d):.1f} 次）
    <span class="btn" style="float:right" onclick="toggleRule({i})">收起 ▴</span>
    {_bars(Counter({d: c for d, c in dr['byDay'].items()}), dr['total'])}
    <div style="font-size:12px;color:#8fa3c8">高峰时段：{' / '.join(f'{h:02d} 时（{c} 次）' for h, c in dr['hours'])}　·　最近触发：{_fmt_ts(dr['last'])}</div>
  </div>
</div>""")

    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>米家极客版 · 策略执行频率分析</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>米家极客版 · 策略执行频率分析</h1>
<div class="meta">日志区间：{_fmt_ts(t0)} ~ {_fmt_ts(t1)}（{span_d:.1f} 天）· {len(data_rules)} 条策略 ·
i 事件合计 {sum(x['total'] for x in data_rules):,} 次 · 生成于 {datetime.now():%Y-%m-%d %H:%M}</div>

<div class="card"><h2>策略执行频率总表（按次数排序，点击展开对应策略）</h2>
<table><tr><th>#</th><th>策略</th><th>相对频率</th><th>触发次数</th><th>节点数</th><th>最近触发</th></tr>
{''.join(rows)}
</table></div>

{''.join(cards)}

<div id="panel"></div>
</div>

<script>
const DATA = {js_data};
function _escH(s){{return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function showRule(i){{toggleRule(i, true)}}
function toggleRule(i, force){{
  const el = document.getElementById('rdetail-' + i);
  if(!el) return;
  el.style.display = (el.style.display === 'none' || force) ? 'block' : 'none';
}}
function dayBars(byDay){{
  const days = Object.keys(byDay).sort();
  if(!days.length) return '<div class="warn">无数据</div>';
  const mx = Math.max(...days.map(d=>byDay[d]));
  return '<div class="days">' + days.map(d =>
    '<div class="row"><span class="lb">'+d+'</span><span class="tr"><i style="width:'
    + (100*byDay[d]/mx) + '%"></i></span><span class="v">'+byDay[d]+'</span></div>'
  ).join('') + '</div>';
}}
function nodeClick(gid, nid){{
  const r = DATA.rules.find(x=>x.gid===gid); if(!r) return;
  const n = r.nodes[nid]; if(!n) return;
  const okRate = n.cnt ? Math.round(100*n.ok/n.cnt) : 0;
  let vals = (n.vals||[]).map(v=>_escH(v[0])+' ×'+v[1]).join('，');
  document.getElementById('panel').innerHTML =
    '<span class="x" onclick="this.parentNode.style.display=\\"none\\"">✕</span>'
    + '<h3>'+_escH(n.label)+'</h3>'
    + '<div style="font-size:12px;color:#8fa3c8">策略：<b style="color:#c7d2ea">'+_escH(r.name)+'</b>　节点 ID：'+_escH(nid)+'</div>'
    + '<div style="margin:8px 0;font-size:13px">执行 <b style="color:#ffb454">'+n.cnt.toLocaleString()+'</b> 次'
    + (n.ok ? '（回执 success '+n.ok+'，占 '+okRate+'%）' : '')
    + '</div>'
    + (vals ? '<div style="font-size:12px;color:#8fa3c8;margin-bottom:4px">下发值 Top：'+vals+'</div>' : '')
    + dayBars(n.byDay||{{}})
    + '<div style="font-size:11px;color:#5d6b8f">占该策略 i 事件 '+(r.total?Math.round(100*n.cnt/r.total):0)+'%　·　策略共 '+(r.total).toLocaleString()+' 次</div>';
  document.getElementById('panel').style.display = 'block';
}}
</script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>
if (window.mermaid) {{
  mermaid.initialize({{startOnLoad: true, securityLevel: 'loose', theme: 'dark'}});
}} else {{
  document.querySelectorAll('.mermaid').forEach(el => {{
    el.insertAdjacentText('afterbegin', '（mermaid CDN 不可用，框图未渲染；节点表仍可点击查询频率）');
  }});
}}
</script>
</body></html>"""
    return html


def main():
    ap = argparse.ArgumentParser(description="米家日志 → 策略/节点执行频率 HTML 报告")
    ap.add_argument("--gw-out", default=None, help="在线输出目录（默认 <脚本目录>/mijia_gw_out）")
    ap.add_argument("--out", default=None, help="HTML 输出路径（默认 <gw-out>/mijia_log_analysis.html）")
    args = ap.parse_args()

    gw = Path(args.gw_out) if args.gw_out else _HERE / "mijia_gw_out"
    out = Path(args.out) if args.out else gw / "mijia_log_analysis.html"
    for f in ("mijia_strategies.json", "mijia_logs_raw.json", "mijia_id_map.json"):
        if not (gw / f).exists():
            print(f"缺少 {gw / f}，请先运行 mijia_geek_client.py 在线抓取")
            sys.exit(1)

    strat, raw, idmap = load_inputs(gw)
    dev_name, var_name, rules_name = build_names(strat, idmap)
    stat, t0, t1, dev_rule, _ = analyze(raw, strat, rules_name)
    html = build_html(stat, dev_rule, {}, dev_name, var_name, t0, t1)
    out.write_text(html, encoding="utf-8")
    total = sum(s["total"] for s in stat.values())
    top = sorted(stat.values(), key=lambda s: -s["total"])[:5]
    print(f"已生成 {out}（{out.stat().st_size/1024:.0f} KB）")
    print(f"日志 {len(raw):,} 行 · 策略 {len(stat)} 条 · i 事件 {total:,}")
    print("Top5 策略：" + "，".join(f"{s['name']}({s['total']})" for s in top))


if __name__ == "__main__":
    main()
