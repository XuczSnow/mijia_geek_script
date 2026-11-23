#!/usr/bin/env python3
"""mijia_flow.py — 由策略 JSON（在线 mijia_strategies.json / 离线 .bak 解析结果）
生成 Mermaid 策略框图（每条规则一个 .md + 一个索引 .md）。

被 mijia_geek_client.py（在线）与 mijia_bak2json.py（离线）共用，
节点标签使用各自 sources 的设备/变量实际名字（dev_name / var_name 映射表）。

输出目录结构：
  <out_dir>/mijia_flows/
    01_<规则名>.md ...        # 每条规则一个 Mermaid 图 + 节点说明
    index.md                 # 索引（规则列表 + 文件链接）
"""

import json
import os
import re
from pathlib import Path

# 节点类型 → 框图关键词
_TYPE_WORD = {
    "deviceInput": "检测",
    "deviceInputSetVar": "检测并记变量",
    "deviceOutput": "控制",
    "deviceGet": "读取",
    "deviceGetSetVar": "读入变量",
    "varGet": "读变量",
    "varSetNumber": "写变量",
    "varSetString": "写字符串变量",
    "varChange": "改变量",
    "alarmClock": "定时",
    "delay": "延时",
    "timeRange": "时段",
    "condition": "条件",
    "signalOr": "或",
    "signalAnd": "与",
    "logicAnd": "与",
    "logicNot": "非",
    "loop": "循环",
    "counter": "计数",
    "eventSequence": "事件序列",
    "nop": "注释",
}

# 边标签：只在有语义时显示（主输出流 output 不贴标签，减少噪音）
_PORT_LABEL = {
    "met": "满足", "unmet": "不满足", "output2": "其他",
    "zero": "归零", "start": "开始", "stop": "停止",
}
_DEFAULT_INPUT_PORTS = {"input", "input0", "input1", "input2", "input3",
                        "input4", "input5", "input6", "output", "trigger", "condition"}


def _esc(s) -> str:
    """Mermaid 节点文本转义：去掉引号/换行，竖线替换为斜杠。"""
    return str(s).replace('"', "'").replace("\n", " ").replace("|", "/").strip()


def _edge_label(port: str, tport: str) -> str:
    """边标签：源端口 met/unmet/output2/zero/start/stop 有固定中文名；
    目标端口非常规时追加；主输出流（output→常规输入）不贴标签。"""
    lab = _PORT_LABEL.get(port, "")
    if tport and tport not in _DEFAULT_INPUT_PORTS:
        lab = f"{lab}·{tport}" if lab else tport
    return lab.replace("|", "/")


def _expr_text(elements, var_name) -> str:
    """varSetNumber 的 elements 表达式 → 可读文本（变量翻为名字）。"""
    parts = []
    for e in elements or []:
        if isinstance(e, dict):
            et = e.get("type")
            if et == "var":
                parts.append((var_name or {}).get(str(e.get("id")), str(e.get("id"))))
            else:
                parts.append(str(e.get("value", "")))
        else:
            parts.append(str(e))
    return " ".join(p for p in parts if p != "")


def node_label(nd, dev_name, var_name) -> str:
    """节点 → 框图标签（实际名字 + 关键参数），一行内。"""
    t = nd.get("type") or ""
    p = nd.get("props") or {}
    cfg = nd.get("cfg") or {}
    word = _TYPE_WORD.get(t, t)

    did = p.get("did")
    if did is not None:
        base = (dev_name or {}).get(str(did)) or f"设备{did}"
    else:
        base = word

    if t in ("deviceInput", "deviceInputSetVar"):
        evs = [str(x.get("value")) for x in (p.get("ins") or []) if isinstance(x, dict) and x.get("value") is not None]
        s = f"{word} {base}"
        if evs:
            s += " " + "/".join(evs)
        op, v1 = p.get("operator"), p.get("v1")
        if op:
            s += f" {op}{'' if v1 is None else ' '}{v1 if v1 is not None else ''}".rstrip()
            s = s.rstrip()
        return s

    if t in ("deviceOutput", "deviceGetSetVar"):
        s = f"{word} {base}"
        if p.get("value") is not None:
            s += f" = {p.get('value')}"
        return s

    if t == "deviceGet":
        s = f"{word} {base}"
        if p.get("operator"):
            s += f" {p['operator']}{'' if p.get('v1') is None else ' '}{p.get('v1')}"
        return s.rstrip()

    if t in ("varGet", "varChange", "varSetNumber", "varSetString"):
        vid = p.get("id")
        vname = (var_name or {}).get(str(vid), str(vid))
        if t == "varSetNumber":
            expr = _expr_text(p.get("elements"), var_name)
            return f"写变量 {vname}{' = ' + expr if expr else ''}".strip()
        s = f"{word} {vname}"
        if p.get("operator"):
            s += f" {p['operator']}{'' if p.get('v1') is None else ' '}{p.get('v1')}"
        return s.rstrip()

    if t == "alarmClock":
        s = "定时"
        atype = p.get("type") or cfg.get("happenType")
        off = p.get("offset", cfg.get("tempOffset"))
        if atype:
            s += f" {atype}"
        if off not in (None, ""):
            s += f" {'后' if cfg.get('happenType') == 'after' else ''}{off}分".strip()
        return s

    if t == "delay":
        return f"延时 {cfg.get('value', p.get('timeout', ''))}{cfg.get('unit', '')}"

    if t == "timeRange":
        s, e2 = p.get("start") or {}, p.get("end") or {}
        return f"时段 {s.get('hour', 0):02d}:{s.get('minute', 0):02d}~{e2.get('hour', 0):02d}:{e2.get('minute', 0):02d}"

    if t == "loop":
        return f"循环 间隔 {cfg.get('value', 1)}{cfg.get('unit', 's')}"

    if t == "counter":
        return f"计数 {p.get('n', '')} 次"

    if t == "eventSequence":
        return f"事件序列 {int(p.get('timeout', 0)) / 1000:.0f}s"

    if t == "nop":
        text = " ".join(c.get("insert", "") for c in (cfg.get("contents") or []) if isinstance(c, dict))
        text = " ".join(text.split())
        return (f"注释 {text[:48]}" if text else "注释").strip()

    # 逻辑门等
    return f"{word} {base}" if t in ("signalOr", "signalAnd", "logicAnd", "logicNot") and base != word else word


def _mermaid_node_id(nid: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", str(nid))


def render_rule_mermaid(rule, dev_name, var_name) -> str:
    """单条规则 → Mermaid graph LR 源码（含节点与连边）。"""
    nodes = rule.get("nodes", [])
    labels = {n.get("id"): node_label(n, dev_name, var_name) for n in nodes}
    out = ["graph LR"]
    out.extend(f"    {_mermaid_node_id(nid)}[\"{_esc(labels.get(nid, nid))}\"]" for nid in labels)
    node_ids = set(labels)
    for n in nodes:
        nid = n.get("id")
        if nid is None:
            continue
        for port, targets in (n.get("outputs") or {}).items():
            for ref in targets or []:
                ref = str(ref)
                tid = ref.split(".")[0]
                tport = ref.split(".")[1] if "." in ref else ""
                lab = _edge_label(port, tport)
                src, dst = _mermaid_node_id(nid), _mermaid_node_id(tid)
                # Mermaid 边标签必须贴在箭头中间：A -->|标签| B
                out.append(f"    {src} -->{('|' + lab + '|') if lab else ''} {dst}")
    return "\n".join(out)


def _safe_name(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|\s]+', "_", (name or "").strip())[:40] or "unnamed"


def write_flows(strategy_doc, out_dir: str, source_label: str = "") -> list:
    """给 strategy_doc（含 rules/devices/variables 或 names）生成框图文件。

    输出 <out_dir>/mijia_flows/ 下每规则一个 .md + index.md。
    返回生成的 .md 路径列表（不含 index）。
    """
    rules = strategy_doc.get("rules", [])
    names = strategy_doc.get("names") or {}
    dev_name = names.get("设备") or {}
    var_name = names.get("变量") or {}

    flow_dir = Path(out_dir) / "mijia_flows"
    flow_dir.mkdir(parents=True, exist_ok=True)

    index = ["# 策略框图索引\n",
             f"共 {len(rules)} 条规则。设备/变量名来源：{_esc(source_label or '未知')}\n",
             "| # | 规则 | 节点数 | 状态 | 框图 |",
             "|---|---|---|---|---|"]
    paths = []
    for i, rule in enumerate(rules, 1):
        cfg = rule.get("cfg") or {}
        rid = str(cfg.get("id"))
        rname = rule.get("name") or (cfg.get("userData") or {}).get("name") or f"规则{rid}"
        enable = cfg.get("enable", cfg.get("enabled", "?"))
        st = "启用" if enable else ("停用" if enable is False else "?")
        fname = f"{i:02d}_{_safe_name(rname)}.md"
        fpath = flow_dir / fname

        mermaid = render_rule_mermaid(rule, dev_name, var_name)
        content = (f"# 策略框图 {i:02d} · {rname}\n\n"
                   f"- 规则 ID: `{rid}`  节点数: {len(rule.get('nodes', []))}  状态: {st}\n"
                   f"- 名字来源: {source_label or '未知'}\n\n"
                   f"```mermaid\n{mermaid}\n```\n\n"
                   f"## 节点说明\n\n")
        # 节点说明表（id → 标签）
        content += "| 节点 ID | 标签 |\n|---|---|\n"
        for n in rule.get("nodes", []):
            nid = n.get("id")
            content += f"| `{nid}` | {_esc(node_label(n, dev_name, var_name))} |\n"
        content += "\n> 框图为 `graph LR`，边标签：满足/不满足=条件分支，其余为非常规端口名。\n"

        fpath.write_text(content, encoding="utf-8")
        paths.append(str(fpath))
        index.append(f"| {i:02d} | {rname} | {len(rule.get('nodes', []))} | {st} | [框图]({fname}) |")

    idx_path = flow_dir / "index.md"
    idx_path.write_text("\n".join(index) + "\n", encoding="utf-8")
    return paths
