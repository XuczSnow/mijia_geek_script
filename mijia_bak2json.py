#!/usr/bin/env python3
"""mijia_bak2json.py — 将米家极客版 .bak 备份文件解析为 JSON。

米家极客版 local-backup 容器格式（由 Web 控制台 generateBackup 生成）：
    [4 字节小端 uint32: 原始 JSON 长度]
    [N 字节 raw DEFLATE 压缩数据]
    [32 字节 SHA-256 摘要（覆盖 前面所有字节，即 data[:-32]）]

本脚本：
  1. 验证 SHA-256 完整性
  2. 解出 raw DEFLATE → 还原原始 JSON
  3. 校验解压后字节数 == 头部声明的原始长度
  4. 写入格式化 JSON 文件（可选）
  5. 打印规则摘要（可选）

用法：
  python mijia_bak2json.py 备份2026_11_22_09_16_26.bak
  python mijia_bak2json.py input.bak -o output.json --summary
  python mijia_bak2json.py input.bak --pretty        # 默认就 pretty
  python mijia_bak2json.py input.bak --compact        # 紧凑输出
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# 核心解析
# ---------------------------------------------------------------------------

def parse_bak(data: bytes) -> dict:
    """解析米家极客版 .bak 二进制容器，返回 dict（含 rules / variables）。

    容器布局：
      offset 0    : 4-byte LE uint32  —— 原始（解压后）JSON 长度
      offset 4    : N-byte  raw DEFLATE
      offset N+4  : 32-byte SHA-256（对 data[:-32] 即 header+deflate 计算）
    """
    if len(data) < 4 + 32:
        raise ValueError(f"文件过小（{len(data)} B），不是有效的 .bak 容器")

    # 1) 头部：原始长度
    declared_len = struct.unpack_from("<I", data, 0)[0]

    # 2) 尾部：SHA-256
    body = data[:-32]       # header + deflated payload
    digest = data[-32:]     # 32-byte sha256
    computed = hashlib.sha256(body).digest()
    if computed != digest:
        raise ValueError(
            "SHA-256 校验失败：文件可能损坏或被篡改\n"
            f"  expected: {digest.hex()}\n"
            f"  actual:   {computed.hex()}"
        )

    # 3) 解压 raw DEFLATE
    deflated = data[4:-32]
    raw = zlib.decompress(deflated, -15)  # wbits=-15 → raw DEFLATE

    if len(raw) != declared_len:
        raise ValueError(
            f"长度不匹配：头部声明 {declared_len} B，实际解压 {len(raw)} B"
        )

    # 4) 解析 JSON
    text = raw.decode("utf-8")
    obj = json.loads(text)
    if "version" not in obj:
        raise ValueError(f"JSON 顶层缺少 'version' 字段，keys={list(obj.keys())}")

    return obj


# ---------------------------------------------------------------------------
# 人类可读版本
# ---------------------------------------------------------------------------

def _node_desc_bak(nd, dev_map, var_names):
    """节点 → 简短描述（设备名由 URN 推导，变量名来自 bak 内 userData.name）。"""
    t = nd.get("type")
    p = nd.get("props") or {}
    extra = ""
    did = p.get("did")
    if did is not None:
        label = dev_map.get(str(did), "")
        extra = f" 设备[{did}]" + (f" {label}" if label else "")
    if t in ("deviceOutput", "deviceInput"):
        ins = [x.get("value") for x in (p.get("ins") or []) if isinstance(x, dict)]
        if ins:
            extra += f" 动作={ins}"
        args = [a.get("v1") for a in (p.get("arguments") or []) if isinstance(a, dict)]
        if args:
            extra += f" 事件={args}"
    if t in ("varGet", "varSetNumber", "varChange", "varSetString"):
        vid = p.get("id")
        extra += f" 变量[{vid}]" + (f" {var_names.get(str(vid), '')}".rstrip())
    if t == "alarmClock":
        extra += " 定时" if p.get("type") == "periodicAlarm" else f" {p.get('type', '')}"
    if t == "timeRange":
        s, e2 = p.get("start", {}), p.get("end", {})
        extra += f" 时段 {s.get('hour', 0):02d}:{s.get('minute', 0):02d}" \
                 f"~{e2.get('hour', 0):02d}:{e2.get('minute', 0):02d}"
    return f"{t}{extra}"


def render_readable(obj: dict, src_name: str) -> str:
    """生成人类可读文本：规则清单 + 各规则节点明细 + 名字映射表 + 类型统计。"""
    from collections import Counter
    rules = obj.get("rules", [])
    names = obj.get("names", {})
    dev_map, var_map = names.get("设备", {}), names.get("变量", {})

    dev_src = names.get("_设备名来源", "URN 推导")
    out = []
    out.append(f"米家极客版备份解析（人类可读版）")
    out.append(f"源文件: {src_name}   version={obj.get('version')}")
    out.append(f"规则 {len(rules)} 条 / 设备 {len(dev_map)} 台（{dev_src}）/ 变量 {len(var_map)} 个")
    out.append("=" * 70)

    out.append("\n== 规则列表 ==")
    for i, r in enumerate(rules, 1):
        cfg = r.get("cfg", {})
        en = cfg.get("enable", cfg.get("enabled", "?"))
        out.append(f"  {i:02d}  {'ON ' if en else 'OFF'}  {r.get('name') or '(无名)'}  (nodes={len(r.get('nodes', []))})")

    out.append("\n== 各规则节点明细 ==")
    for i, r in enumerate(rules, 1):
        out.append(f"\n[{i:02d}] {r.get('name') or r.get('cfg', {}).get('id')}")
        for nd in r.get("nodes", []):
            out.append(f"    {_node_desc_bak(nd, dev_map, var_map)}")

    dev_src2 = names.get("_设备名来源", "URN 推导")
    out.append(f"\n== 设备映射（did → {dev_src2}） ==")
    for did, label in dev_map.items():
        out.append(f"  {did:>12s}  {label}")

    out.append("\n== 变量映射（vid → 名字，来自 bak userData.name） ==")
    for vid, nm in var_map.items():
        out.append(f"  {vid:>14s}  {nm}")

    out.append("\n== 设备类型统计（节点引用次数） ==")
    counter = Counter()
    for r in rules:
        for nd in r.get("nodes", []):
            urn = (nd.get("cfg") or {}).get("urn", "")
            parts = urn.split(":")
            dt = parts[3] if len(parts) >= 4 and parts[2] == "device" else (urn or "(无urn)")
            counter[dt] += 1
    for dt, cnt in counter.most_common():
        out.append(f"  {cnt:4d}  {dt}")

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 摘要
# ---------------------------------------------------------------------------

def print_summary(obj: dict, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}version: {obj.get('version')}")
    rules = obj.get("rules", [])
    print(f"{pad}rules:   {len(rules)}")
    vars_ = obj.get("variables", {})
    for scope, group in vars_.items():
        print(f"{pad}variables[{scope}]: {len(group)}")

    print(f"\n{pad}=== 规则列表 ===")
    for i, r in enumerate(rules, 1):
        cfg = r.get("cfg", {})
        name = (cfg.get("userData") or {}).get("name", "(unnamed)")
        enable = cfg.get("enable", cfg.get("enabled", "?"))
        n_nodes = len(r.get("nodes", []))
        print(f"{pad}  {i:02d}  {'ON ' if enable else 'OFF'}  {name}  (nodes={n_nodes})")

    # 设备类型统计
    from collections import Counter
    urn_counter: Counter = Counter()
    for r in rules:
        for nd in r.get("nodes", []):
            urn = (nd.get("cfg") or {}).get("urn", "")
            if not urn:
                continue
            parts = urn.split(":")
            # urn:miot-spec-v2:device:<type>:<spec>:<model>:<ver>[:<pid>]
            dt = parts[3] if len(parts) >= 4 and parts[2] == "device" else urn
            urn_counter[dt] += 1
    print(f"\n{pad}=== 设备类型（节点引用次数）===")
    for dt, cnt in urn_counter.most_common():
        print(f"{pad}  {cnt:4d}  {dt}")


def _urn_label(urn: str) -> str:
    """从 URN 推设备标签：urn:miot-spec-v2:device:<type>:<spec>:<model>:<ver>[:<pid>]
    -> '<type>(<model>)'。bak 内没有设备中文名，只能给到类型+型号。"""
    if not urn:
        return ""
    p = urn.split(":")
    # urn:miot-spec-v2:device:occupancy-sensor:0000A0BF:zywjw-c01:1
    if len(p) >= 4 and p[2] == "device":
        typ = p[3]
        model = p[5] if len(p) >= 6 else ""
        return f"{typ}({model})" if model else typ
    return ""


def _load_online_id_map() -> dict:
    """若 <脚本目录>/mijia_gw_out/mijia_id_map.json 存在，加载在线抓取的 ID→实际名字映射。

    该文件由 mijia_geek_client.py 生成（getDevList/getVar*/getGraph），含设备真实中文名。
    找不到或解析失败时返回 {}（不影响离线解析，仅退回 URN 推导）。
    """
    p = Path(__file__).resolve().parent / "mijia_gw_out" / "mijia_id_map.json"
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        print(f"已加载在线 ID 映射 {p}（用于设备真实中文名）")
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"警告：加载 {p} 失败（{e}），退回 URN 推导设备标签")
        return {}


def attach_names(obj: dict) -> dict:
    """基于 .bak 自身信息，给每条规则加 name、顶层加 names 映射表。

    - 规则名：rules[i].cfg.userData.name
    - 变量名：variables[scope][vid].userData.name
    - 设备：bak 无设备中文名字段，默认由 URN 推 type/model；
      若存在 <脚本目录>/mijia_gw_out/mijia_id_map.json，则用其中真实中文名覆盖。
    返回 (规则数, 设备 did 数, 变量数) 统计。
    """
    # 规则名
    for r in obj.get("rules", []):
        r.setdefault("name", (r.get("cfg", {}).get("userData") or {}).get("name"))

    # 变量名（扁平合并各作用域）
    var_names = {}
    for scope, grp in (obj.get("variables") or {}).items():
        for vid, vv in (grp or {}).items():
            ud = vv.get("userData") if isinstance(vv, dict) else None
            if isinstance(ud, dict) and ud.get("name"):
                var_names[str(vid)] = ud["name"]

    # 设备 did（收集去重）+ 由 URN 推标签
    dev_map = {}
    for r in obj.get("rules", []):
        for nd in r.get("nodes", []):
            pr = nd.get("props") or {}
            did = pr.get("did")
            if not did:
                continue
            did = str(did)
            label = _urn_label((nd.get("cfg") or {}).get("urn", ""))
            if did not in dev_map:
                dev_map[did] = label
            elif label and not dev_map[did]:
                dev_map[did] = label

    # 若在线 id_map 可用，用真实中文名覆盖 URN 推导标签
    id_map = _load_online_id_map()
    dev_src = "URN 推导"
    online_dev = (id_map.get("设备") or {}) if id_map else {}
    if online_dev:
        for did, real_name in online_dev.items():
            key = str(did)
            if key in dev_map and real_name:
                dev_map[key] = real_name
        # 同时用在线变量名覆盖（若存在同名 key 且 bak 未提供名字）
        online_var = (id_map.get("变量") or {})
        if online_var:
            for vid, real_name in online_var.items():
                key = str(vid)
                if key in var_names and not var_names.get(key) and real_name:
                    var_names[key] = real_name
        dev_src = "在线 mijia_id_map.json"

    obj["names"] = {
        "规则": {str((r.get("cfg") or {}).get("id")):
                 (r.get("cfg", {}).get("userData") or {}).get("name")
                 for r in obj.get("rules", [])},
        "设备": dict(sorted(dev_map.items())),
        "变量": dict(sorted(var_names.items())),
        "_设备名来源": dev_src,
        "_说明": ("离线解析：规则名/变量名来自 userData.name；设备名来源=" + dev_src + "。"
                  + ("" if online_dev else "完整中文名需在线 getDevList 生成 mijia_gw_out/mijia_id_map.json（见 mijia_geek_client.py）。")),
    }
    return len(obj.get("rules", [])), len(dev_map), len(var_names)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="将米家极客版 .bak 备份解析为 JSON（并输出人类可读版）"
    )
    parser.add_argument("input", help=".bak 备份文件路径")
    parser.add_argument(
        "-o", "--output",
        help="输出 JSON 文件路径（默认进 out 文件夹）",
    )
    parser.add_argument(
        "--out-dir",
        help="输出目录（默认 <脚本目录>/mijia_bak_out）",
    )
    parser.add_argument(
        "--no-txt", action="store_true",
        help="不输出人类可读 .txt（默认输出）",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="解析成功后打印规则摘要",
    )
    parser.add_argument(
        "--compact", action="store_true",
        help="输出紧凑 JSON（默认缩进 2 格）",
    )
    parser.add_argument(
        "--no-flow", action="store_true",
        help="不输出 Mermaid 策略框图（默认输出到 <输出目录>/mijia_flows/）",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        sys.exit(f"错误：找不到文件 {in_path}")

    data = in_path.read_bytes()
    print(f"读取 {in_path}  ({len(data)} B)")

    obj = parse_bak(data)
    print(f"解析成功：version={obj['version']}, rules={len(obj.get('rules', []))}")

    # 用 bak 自身信息解析 ID -> 实际名字（规则/变量名来自 userData.name，设备名优先在线 id_map，否则 URN 推导）
    nrules, ndev, nvar = attach_names(obj)
    dev_src = obj.get("names", {}).get("_设备名来源", "URN 推导")
    print(f"已附加名字映射：规则 {nrules}、设备 {ndev}（{dev_src}）、变量 {nvar}")

    # 确定输出路径：默认进 out 文件夹（<脚本目录>/mijia_bak_out），可用 --out-dir/-o 覆盖
    if args.output:
        out_path = Path(args.output)
    else:
        out_dir = Path(args.out_dir) if args.out_dir else \
            Path(__file__).resolve().parent / "mijia_bak_out"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / (in_path.stem + ".json")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    indent = None if args.compact else 2
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=indent)
    print(f"已写入 {out_path}  ({os.path.getsize(out_path)} B)")

    # 回读校验
    with open(out_path, "r", encoding="utf-8") as f:
        json.load(f)
    print("回读校验通过")

    # 人类可读版（同目录同名 .txt）
    if not args.no_txt:
        txt_path = out_path.with_suffix(".txt")
        txt = render_readable(obj, in_path.name)
        with open(txt_path, "w", encoding="utf-8-sig") as f:
            f.write(txt)
        print(f"已写入人类可读版 {txt_path}  ({os.path.getsize(txt_path)} B)")

    # Mermaid 策略框图（每规则一个 .md + index.md，输出到 <输出目录>/mijia_flows/）
    if not args.no_flow:
        import mijia_flow
        flow_paths = mijia_flow.write_flows(
            obj, str(out_path.parent),
            source_label=f"离线 .bak 解析（设备名来源={dev_src}，变量名=userData.name）")
        print(f"已生成策略框图 {len(flow_paths)} 张 -> {out_path.parent / 'mijia_flows'}")

    if args.summary:
        print()
        print_summary(obj)


if __name__ == "__main__":
    main()
