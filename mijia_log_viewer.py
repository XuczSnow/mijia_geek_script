#!/usr/bin/env python3
"""mijia_log_viewer.py — 把米家网关日志导出为可筛选的自包含 HTML。

数据源（mijia_gw_out/，由 mijia_geek_client.py 在线抓取生成）：
  mijia_logs_raw.json      原始日志行（必需）
  mijia_strategies.json    策略图（可选，用于 节点→设备/变量 实际名字翻译）
  mijia_id_map.json        ID→实际名字对照表（可选）
没有 strategies.json 时，自动退回 <脚本目录>/mijia_bak_out/ 里最新的 .bak 解析 JSON
做节点翻译（设备名同样享受「在线 id_map 优先」的来源规则）。

输出：
  mijia_log_viewer.html    自包含、零依赖、离线可打开。支持：
    - 时间筛选（起止时间输入 + 全部/最近24小时/最近7天/今天 快捷键）
    - 日志类型筛选（l 链路 / i 节点 / e 错误 / r 规则事件）
    - 策略 / 设备 / 变量 下拉筛选
    - 关键字搜索（内容 + 策略名 + 设备名）
    - 分页浏览、筛选结果导出 CSV
    节点名已翻译为实际设备/变量名（与 mijia_logs.txt 一致口径）。

用法：
  python mijia_log_viewer.py [--gw-out DIR] [--out FILE]
"""

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mijia_flow  # noqa: E402  复用 node_label（节点 → 实际名字）

TYPE_KEYS = ["l", "i", "e", "r"]
TYPE_LABEL = ["链路", "节点", "错误", "规则事件"]


# ---------------------------------------------------------------- 数据加载

def load_inputs(gw_out: Path, bak_dir: Path):
    raw = json.loads((gw_out / "mijia_logs_raw.json").read_text(encoding="utf-8"))

    doc, src = None, ""
    s = gw_out / "mijia_strategies.json"
    if s.exists():
        doc = json.loads(s.read_text(encoding="utf-8-sig"))
        src = "mijia_strategies.json（在线抓取）"
    else:
        cands = sorted(bak_dir.glob("*.json"))
        if cands:
            doc = json.loads(cands[-1].read_text(encoding="utf-8-sig"))
            src = f"mijia_bak_out/{cands[-1].name}（离线 .bak 解析）"
    doc = doc or {}

    idmap = {}
    im = gw_out / "mijia_id_map.json"
    if im.exists():
        try:
            idmap = json.loads(im.read_text(encoding="utf-8-sig"))
        except Exception:
            idmap = {}

    names = doc.get("names") or {}
    dev = dict(names.get("设备") or idmap.get("设备") or {})
    var = dict(names.get("变量") or idmap.get("变量") or {})
    rules = dict(names.get("规则") or idmap.get("规则") or {})
    if not rules:
        for r in doc.get("rules", []):
            cfg = r.get("cfg") or {}
            gid = str(cfg.get("id"))
            rules.setdefault(gid, r.get("name") or cfg.get("name") or gid)
    return raw, doc, dev, var, rules, src


def build_node_index(doc: dict, dev: dict, var: dict):
    """节点 ID -> (实际名字标签, 设备 did, 变量 vid)。"""
    labels, ndev, nvar = {}, {}, {}
    for rule in doc.get("rules", []):
        for nd in rule.get("nodes", []):
            nid = str(nd.get("id"))
            if not nid:
                continue
            labels[nid] = mijia_flow.node_label(nd, dev, var)
            props = nd.get("props") or {}
            if "did" in props:
                ndev[nid] = str(props["did"])
            elif isinstance(props.get("id"), (str, int)):
                nvar[nid] = str(props["id"])
    return labels, ndev, nvar


def _unwrap(info: str) -> str:
    s = info.strip()
    if s.startswith("[") or s.startswith("{"):
        try:
            v = json.loads(s)
            if isinstance(v, list):
                return ",".join(str(x) for x in v)
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return s
    return s


def build_records(raw, labels, ndev, nvar, rules: dict):
    """逐行转为紧凑记录 [ts, 类型idx, 策略idx, 设备idx, 变量idx, 文本池idx]。"""
    gid_list = list(rules.keys())
    gid2idx = {g: i + 1 for i, g in enumerate(gid_list)}
    rules_arr = ["(未知规则)"] + [rules[g] for g in gid_list]

    devs, vars_ = [], []
    di_idx, vi_idx = {}, {}

    def dev_i(did):
        if not did:
            return -1
        if did not in di_idx:
            di_idx[did] = len(devs)
            devs.append(_DEV.get(did, f"设备{did}"))
        return di_idx[did]

    def var_i(vid):
        if not vid:
            return -1
        if vid not in vi_idx:
            vi_idx[vid] = len(vars_)
            vars_.append(_VAR.get(vid, f"变量{vid}"))
        return vi_idx[vid]

    pool = {}

    def pidx(s):
        i = pool.get(s)
        if i is None:
            i = len(pool)
            pool[s] = i
        return i

    recs = []
    for ln in raw:
        p = ln.split("|")
        if len(p) < 4 or not p[1].isdigit():
            continue
        ts = int(p[1])
        tkey = p[2]
        tidx = TYPE_KEYS.index(tkey) if tkey in TYPE_KEYS else 1
        ri = gid2idx.get(p[3], 0)
        di = vi = -1
        if tkey in ("l", "e"):
            sn = p[4].rsplit(".", 1)[0] if len(p) > 4 else "?"
            dn = (p[5].rsplit(".", 1)[0] if len(p) > 5 else sn)
            val = p[6] if len(p) > 6 else ""
            rest = (f"{labels.get(sn, sn)} -> {labels.get(dn, dn)} {val}").rstrip()
            did = ndev.get(dn) or ndev.get(sn)
            vid = nvar.get(dn) or nvar.get(sn)
            di = dev_i(did)
            vi = var_i(vid)
        elif tkey == "r":
            rest = ("规则事件 " + (p[4] if len(p) > 4 else "")).rstrip()
        else:  # i
            nid = p[4] if len(p) > 4 else "?"
            info = p[5] if len(p) > 5 else ""
            rest = f"{labels.get(nid, nid)} {_unwrap(info)}"
            di = dev_i(ndev.get(nid))
            vi = var_i(nvar.get(nid))
        recs.append([ts, tidx, ri, di, vi, pidx(rest)])
    return rules_arr, devs, vars_, list(pool.values()), recs


_DEV = {}
_VAR = {}


def build_html(raw, recs, rules_arr, devs, vars_, texts, src, t0, t1):
    payload = {
        "rules": rules_arr,
        "devs": devs,
        "vars": vars_,
        "texts": texts,
        "L": recs,
        "meta": {
            "total": len(recs),
            "range": [t0, t1],
            "src": src,
            "generated": Path(__file__).name,
        },
    }
    js = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return _TPL.replace("__DATA__", js).replace("__SRC__", src)


# ---------------------------------------------------------------- HTML 模板

_TPL = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>米家极客版 · 日志浏览器</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0f18;color:#c7d2ea;font:14px/1.5 'Segoe UI','Microsoft YaHei',sans-serif}
.wrap{max-width:1500px;margin:0 auto;padding:18px 24px 60px}
h1{font-size:19px;color:#e8eefb;margin:4px 0 2px}
.meta{color:#8fa3c8;font-size:12px;margin-bottom:12px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:#101623;border:1px solid #1c2740;
  border-radius:10px;padding:10px 14px;margin-bottom:10px}
.bar label{font-size:12px;color:#8fa3c8;display:inline-flex;gap:6px;align-items:center}
input,select,button{background:#141d33;color:#c7d2ea;border:1px solid #26324d;border-radius:6px;
  font-size:12px;padding:4px 8px;font-family:inherit}
button{cursor:pointer}
button:hover{background:#24375f}
.chip{font-size:12px;color:#8fa3c8;border:1px solid #26324d;border-radius:12px;padding:2px 10px;cursor:pointer}
.chip:hover{background:#18233d;color:#c7d2ea}
input[type=checkbox]{accent-color:#4f8cff}
.kw{width:220px}
#resmeta{font-size:12px;color:#8fa3c8;margin:8px 2px}
#resmeta b{color:#4f8cff}
table{border-collapse:collapse;width:100%;background:#101623;border:1px solid #1c2740;border-radius:10px;
  overflow:hidden}
th,td{padding:4px 9px;border-bottom:1px solid #18233d;text-align:left;font-size:12px;vertical-align:top}
th{color:#8fa3c8;background:#141d33;position:sticky;top:0}
td{font-family:Consolas,'Cascadia Code',monospace}
td.t{white-space:nowrap;color:#8fa3c8}
td.r{color:#c7d2ea;font-family:inherit}
td.dv{color:#7ee0a1}
td.vr{color:#e0b07e}
td.x{color:#c7d2ea}
.ty{display:inline-block;font-size:11px;padding:0 7px;border-radius:9px;font-family:inherit}
.ty0{background:#173d63;color:#8fc2ff}
.ty1{background:#1e4429;color:#7ee0a1}
.ty2{background:#4d1f24;color:#f2a3a3}
.ty3{background:#4a3a17;color:#e0b07e}
.pg{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:12px;color:#8fa3c8}
.pg b{color:#e8eefb}
#pgo{width:76px}
.empty{padding:40px;text-align:center;color:#5d6b8f}
</style></head>
<body><div class="wrap">
<h1>米家极客版 · 日志浏览器</h1>
<div class="meta" id="srcmeta"></div>

<div class="bar">
  <label>从 <input id="from" type="datetime-local"></label>
  <label>到 <input id="to" type="datetime-local"></label>
  <span class="chip" data-p="all">全部</span>
  <span class="chip" data-p="1d">最近24小时</span>
  <span class="chip" data-p="7d">最近7天</span>
  <span class="chip" data-p="today">今天</span>
  <span style="flex:1"></span>
  <button id="reset">重置</button>
  <button id="csv">导出筛选 CSV</button>
</div>

<div class="bar">
  <span style="font-size:12px;color:#8fa3c8">类型</span>
  <label><input type="checkbox" class="ty" data-t="0" checked> 链路(l)</label>
  <label><input type="checkbox" class="ty" data-t="1" checked> 节点(i)</label>
  <label><input type="checkbox" class="ty" data-t="2" checked> 错误(e)</label>
  <label><input type="checkbox" class="ty" data-t="3" checked> 规则事件(r)</label>
  <label>策略 <select id="rule"></select></label>
  <label>设备 <select id="dev"></select></label>
  <label>变量 <select id="var"></select></label>
  <input id="kw" class="kw" placeholder="关键字（内容/策略/设备名）">
</div>

<div id="resmeta"></div>
<div style="overflow-x:auto;border-radius:10px">
<table><thead><tr><th style="width:150px">时间</th><th style="width:60px">类型</th>
<th style="width:210px">策略</th><th style="width:170px">设备</th><th style="width:140px">变量</th>
<th>内容</th></tr></thead>
<tbody id="rows"></tbody></table>
</div>

<div class="pg">
  第 <b id="cur">1</b> / <span id="tot">1</span> 页
  <button id="prev">‹</button><button id="first">«</button><button id="last">»</button><button id="next">›</button>
  每页 <select id="ps"><option>100</option><option selected>500</option><option>1000</option><option>5000</option></select>
  <label>跳至 <input id="pgo" type="number" min="1"><button id="pgoBtn">Go</button></label>
</div>
</div>

<script>
const D = __DATA__;
const RULES = D.rules, DEVS = D.devs, VARS = D.vars, TXT = D.texts, L = D.L;
const minTs = L.length ? L[0][0] : 0, maxTs = L.length ? L[L.length-1][0] : 0;
const TNAME = ["链路","节点","错误","规则事件"];
document.getElementById('srcmeta').textContent =
  '数据：' + D.meta.total.toLocaleString() + ' 行（' + fmt(minTs) + ' ~ ' + fmt(maxTs) + '）· ' + D.meta.src;

// ---- 下拉框
function fillSel(id, arr, allName){
  const s = document.getElementById(id);
  s.innerHTML = '<option value="-1">' + allName + '</option>' +
    arr.map((v,i) => '<option value="'+i+'">'+esc(v)+'</option>').join('');
}
fillSel('rule', RULES.slice(1), '全部策略');
fillSel('dev', DEVS, '全部设备');
fillSel('var', VARS, '全部变量');

// ---- 工具
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function p2(n){return String(n).padStart(2,'0')}
function fmt(ms){
  const d = new Date(ms);
  return d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate())+' '+
    p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds())+'.'+p2(d.getMilliseconds()).slice(0,2);
}
function toLocalInput(ms){
  const d = new Date(ms);
  return d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate())+'T'+p2(d.getHours())+':'+p2(d.getMinutes());
}

// ---- 筛选状态
let from = null, to = null, curPage = 1, filtered = L.map((_,i)=>i), kwTimer = null;
const size = () => parseInt(document.getElementById('ps').value, 10);

function apply(){
  const tsel = new Set();
  document.querySelectorAll('.ty').forEach(c => { if(c.checked) tsel.add(+c.dataset.t); });
  const rule = +document.getElementById('rule').value;
  const dev = +document.getElementById('dev').value;
  const vr = +document.getElementById('var').value;
  const kw = document.getElementById('kw').value.trim().toLowerCase();
  filtered = [];
  for(let i=0;i<L.length;i++){
    const r = L[i];
    if(from!=null && r[0]<from) continue;
    if(to!=null && r[0]>to) continue;
    if(!tsel.has(r[1])) continue;
    if(rule>=0 && r[2]!==rule) continue;
    if(dev>=0 && r[3]!==dev) continue;
    if(vr>=0 && r[4]!==vr) continue;
    if(kw){
      const hay = TXT[r[5]] + ' ' + RULES[r[2]] + ' ' + (r[3]>=0?DEVS[r[3]]:'');
      if(hay.toLowerCase().indexOf(kw)<0) continue;
    }
    filtered.push(i);
  }
  curPage = 1;
  render();
}

function render(){
  const total = filtered.length, ps = size();
  const pages = Math.max(1, Math.ceil(total/ps));
  if(curPage>pages) curPage = pages;
  document.getElementById('cur').textContent = curPage;
  document.getElementById('tot').textContent = pages;
  const start = (curPage-1)*ps;
  let html = '';
  const end = Math.min(start+ps, total);
  for(let i=start;i<end;i++){
    const r = L[filtered[i]];
    const dv = r[3]>=0 ? '<td class="dv">'+esc(DEVS[r[3]])+'</td>' : '<td></td>';
    const vr = r[4]>=0 ? '<td class="vr">'+esc(VARS[r[4]])+'</td>' : '<td></td>';
    html += '<tr><td class="t">'+fmt(r[0])+'</td>'
      + '<td><span class="ty ty'+r[1]+'">'+TNAME[r[1]]+'</span></td>'
      + '<td class="r">'+esc(RULES[r[2]])+'</td>' + dv + vr
      + '<td class="x">'+esc(TXT[r[5]])+'</td></tr>';
  }
  const tb = document.getElementById('rows');
  tb.innerHTML = html || '<tr><td colspan="6" class="empty">无匹配日志</td></tr>';
  document.getElementById('resmeta').innerHTML =
    '筛选结果 <b>' + total.toLocaleString() + '</b> 行' +
    (total ? '，时间 ' + fmt(L[filtered[0]][0]) + ' ~ ' + fmt(L[filtered[filtered.length-1]][0]) : '');
}

// ---- 事件
document.querySelectorAll('.ty,select#rule,select#dev,select#var,select#ps').forEach(el =>
  el.addEventListener('change', () => { apply(); }));
document.getElementById('ps').addEventListener('change', () => { render(); });
['from','to'].forEach(id => document.getElementById(id).addEventListener('change', () => {
  from = document.getElementById('from').value ? new Date(document.getElementById('from').value).getTime() : null;
  to = document.getElementById('to').value ? new Date(document.getElementById('to').value).getTime() : null;
  apply();
}));
document.getElementById('kw').addEventListener('input', () => {
  clearTimeout(kwTimer); kwTimer = setTimeout(apply, 150);
});
document.querySelectorAll('.chip').forEach(c => c.addEventListener('click', () => {
  const f = document.getElementById('from'), t = document.getElementById('to');
  const now = new Date();
  const mid0 = now.getFullYear()+'-'+p2(now.getMonth()+1)+'-'+p2(now.getDate())+'T00:00';
  if(c.dataset.p === 'all'){ f.value=''; t.value=''; from=to=null; }
  else if(c.dataset.p === '1d'){ to = maxTs; from = maxTs - 86400e3; f.value = toLocalInput(from); t.value = toLocalInput(to); }
  else if(c.dataset.p === '7d'){ to = maxTs; from = maxTs - 7*86400e3; f.value = toLocalInput(from); t.value = toLocalInput(to); }
  else { to = null; from = new Date(mid0).getTime(); t.value=''; f.value = mid0; }
  apply();
}));
document.getElementById('reset').addEventListener('click', () => {
  document.getElementById('from').value=''; document.getElementById('to').value='';
  document.getElementById('rule').value='-1'; document.getElementById('dev').value='-1';
  document.getElementById('var').value='-1'; document.getElementById('kw').value='';
  document.querySelectorAll('.ty').forEach(c=>c.checked=true);
  from=to=null; apply();
});
document.getElementById('prev').addEventListener('click', ()=>{ if(curPage>1){curPage--; render();} });
document.getElementById('next').addEventListener('click', ()=>{ curPage++; if(curPage>parseInt(document.getElementById('tot').textContent,10)) curPage=1; render(); });
document.getElementById('first').addEventListener('click', ()=>{ curPage=1; render(); });
document.getElementById('last').addEventListener('click', ()=>{ curPage=parseInt(document.getElementById('tot').textContent,10); render(); });
document.getElementById('pgoBtn').addEventListener('click', ()=>{
  const v = parseInt(document.getElementById('pgo').value,10);
  if(v>0){ curPage=v; render(); }
});

// ---- CSV 导出（筛选结果，最多 50 万行）
document.getElementById('csv').addEventListener('click', () => {
  const cap = Math.min(filtered.length, 500000);
  let out = '\\uFEFF时间,类型,策略,设备,变量,内容\\n';
  for(let i=0;i<cap;i++){
    const r = L[filtered[i]];
    const row = [fmt(r[0]), TNAME[r[1]], RULES[r[2]], r[3]>=0?DEVS[r[3]]:'', r[4]>=0?VARS[r[4]]:'', TXT[r[5]]]
      .map(x => '"'+String(x).replace(/"/g,'""')+'"').join(',');
    out += row + '\\n';
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([out], {type:'text/csv'}));
  a.download = 'mijia_logs_filtered.csv';
  a.click();
});

// ---- 初始：时间框预填数据范围
document.getElementById('from').value = toLocalInput(minTs);
document.getElementById('to').value = toLocalInput(maxTs);
from = minTs; to = maxTs;
apply();
</script>
</body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="米家日志 → 可筛选 HTML 浏览器")
    ap.add_argument("--gw-out", default=None, help="在线输出目录（默认 <脚本目录>/mijia_gw_out）")
    ap.add_argument("--out", default=None, help="HTML 输出路径（默认 <gw-out>/mijia_log_viewer.html）")
    args = ap.parse_args()

    gw = Path(args.gw_out) if args.gw_out else _HERE / "mijia_gw_out"
    out = Path(args.out) if args.out else gw / "mijia_log_viewer.html"
    if not (gw / "mijia_logs_raw.json").exists():
        print(f"缺少 {gw / 'mijia_logs_raw.json'}，请先运行 mijia_geek_client.py 在线抓取", file=sys.stderr)
        sys.exit(1)

    raw, doc, dev, var, rules, src = load_inputs(gw, _HERE / "mijia_bak_out")
    global _DEV, _VAR
    _DEV, _VAR = dev, var
    labels, ndev, nvar = build_node_index(doc, dev, var)
    rules_arr, devs, vars_, texts, recs = build_records(raw, labels, ndev, nvar, rules)

    tss = [r[0] for r in recs]
    t0, t1 = (min(tss), max(tss)) if tss else (0, 0)
    html = build_html(raw, recs, rules_arr, devs, vars_, texts, src, t0, t1)
    out.write_text(html, encoding="utf-8")

    days = (t1 - t0) / 86400000 if t1 > t0 else 0
    print(f"已生成 {out}（{out.stat().st_size / 1024 / 1024:.1f} MB）")
    print(f"日志 {len(recs):,} 行（{days:.1f} 天）· 策略 {len(rules_arr)-1} · 设备 {len(devs)} · 变量 {len(vars_)}")
    print(f"节点翻译来源：{src if src else '无（未找到 strategies.json 或 mijia_bak_out/*.json，显示原始节点 ID）'}")


if __name__ == "__main__":
    main()
