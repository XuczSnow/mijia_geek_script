# 米家极客版网关 策略/日志抓取工具

纯 Python 3 标准库实现（**零第三方依赖**）的米家自动化极客版（中枢网关）数据客户端。
通过加密 WebSocket 反向协议，从中枢网关拉取**全部自动化策略（规则图）**、设备表、变量表与**执行日志**。

> 协议逆向自 2026 版中枢网关 Web 控制台（`prod/ai-config` 系列 JS 包 `gateway.6cbc85.js`）。
> 网关不开放 REST/HTTP API，所有数据都走 `ws://<网关IP>:8086/centrallinkws/` 的二进制协议。

## 文件结构

```
mijia_geek_script/
├── mijia_geek_client.py      # 在线客户端（约 1100 行，纯标准库）
├── mijia_bak2json.py         # 离线 .bak 解析器（纯标准库）
├── mijia_flow.py             # Mermaid 策略框图共用生成模块
├── mijia_log_analyze.py      # 策略/节点执行频率分析 → 自包含 HTML（折线图 + 可点击框图 + 缩放）
├── README.md
├── mijia_gw_out/             # 在线抓取输出目录（相对脚本所在路径）
│   ├── mijia_strategies.json   # 策略（cfg + 图节点）+ 设备/变量表 + names 映射
│   ├── mijia_logs.txt          # 人类可读执行日志（单行简洁形式，设备/变量已翻译为实际名字）
│   ├── mijia_logs_raw.json     # 原始日志行（JSON 数组，每行一个网关日志事件）
│   ├── mijia_id_map.json       # ID→实际名字对照表（规则 / 设备 / 变量）
│   ├── mijia_log_analysis.html # 执行频率分析报告（自包含，浏览器直接打开）
│   └── mijia_flows/            # Mermaid 策略框图（每规则一个 .md + index.md）
└── mijia_bak_out/            # 离线 .bak 解析输出目录（相对脚本所在路径）
    ├── <输入名>.json          # 解析后的 JSON（含 names 映射）
    ├── <输入名>.txt          # 人类可读版（规则清单 + 节点明细 + 映射表 + 类型统计）
    └── mijia_flows/          # Mermaid 策略框图（每规则一个 .md + index.md）
```

### 策略框图（Mermaid）

两个脚本都生成 Mermaid 策略框图（共用 `mijia_flow.py`）：每条规则一个 `.md`
（`graph LR` 框图 + 节点说明表），外加 `index.md` 总览。节点标签用实际设备/变量名，
边带端口标签（满足/不满足=条件分支，其余为非常规端口名）。

- `mijia_geek_client.py`：在线抓取时自动生成到 `<out-dir>/mijia_flows/`；
  也可不连网关用 `--flows` 基于已有 `mijia_strategies.json` 离线生成。
- `mijia_bak2json.py`：离线解析 `.bak` 时自动生成到 `<输出目录>/mijia_flows/`，
  可用 `--no-flow` 关闭。设备名来源与 JSON 一致（在线 `id_map` 或 URN 推导）。

生成的 `.md` 含 ` ```mermaid ` 代码块，可在支持 Mermaid 的 Markdown 渲染器
（GitHub / Typora / Obsidian / VS Code Markdown 预览等）中查看流程图。

### 执行频率分析（mijia_log_analyze.py）

`mijia_log_analyze.py` 读取 `mijia_gw_out/` 下在线抓取的
`mijia_strategies.json` + `mijia_logs_raw.json` + `mijia_id_map.json`，统计**每条策略**与
**每个图节点**在日志区间内的执行次数，生成**自包含 HTML 报告**
（`mijia_gw_out/mijia_log_analysis.html`，浏览器直接打开即可，框图走 mermaid CDN，
其余折线图/表格/交互全部内联、无额外依赖）：

```bash
# 基于已抓取的在线数据生成执行频率报告
python mijia_log_analyze.py            # 默认读 <脚本目录>/mijia_gw_out，输出 mijia_log_analysis.html
python mijia_log_analyze.py --gw-out D:\gw --out D:\gw\report.html
```

报告内容：
- **策略执行频率总表**：按触发次数排序 + 相对频率条，点击跳转对应策略卡片；
- **每条策略卡片**：Mermaid 框图（节点按执行频次着色 灰0/蓝1-99/黄100-999/红≥1000），
  点击图中节点或右侧节点表行 → 右下角弹出该节点执行次数、success 回执占比、下发值 Top、
  按天折线 + 单日 24 小时折线（可点日期切换）；
- **可缩放框图**：每个框图带 －/＋/重置 按钮与 `Ctrl+滚轮` 缩放，框图区可滚动，
  布局与图表高度随 16:9 / 4K 视口自适应；
- 「策略执行频率」按钮 → 展开该策略**按天折线** + **单日 24 小时折线**。

## 两个脚本如何解析"实际名字"

两个脚本都把 ID 解析为可读名字，但数据源不同：

| 脚本 | 名字来源 | 设备 did | 变量 Vid | 规则 |
|---|---|---|---|---|
| `mijia_geek_client.py`（**在线**） | 网关在线 API `getDevList`/`getVarList`/`getGraphList` | ✅ 中文设备名+房间（如 `Yeelight 主卧窗帘（主卧）`） | ✅ `userData.name` | ✅ `cfg.userData.name` |
| `mijia_bak2json.py`（**离线**） | `.bak` 自带信息 **+** 可选的在线 `mijia_gw_out/mijia_id_map.json` | ✅ 若存在 `mijia_id_map.json` 则用真实中文名，否则 URN 推 `<type>(<model>)` | ✅ `userData.name` | ✅ `cfg.userData.name` |

> **设备名来源自动选择**：`mijia_bak2json.py` 运行时会自动检测 `<脚本目录>/mijia_gw_out/mijia_id_map.json`
> （由 `mijia_geek_client.py` 在线抓取生成）。若该文件存在，则用其中的设备真实中文名（含房间）覆盖
> URN 推导标签；若不存在，则退回 URN 推导 `<type>(<model>)` 并如实标注来源。
> 因此**先在线抓取一次**（生成 `mijia_id_map.json`），再离线解析 `.bak` 即可让设备名也显示为
> 「Yeelight 主卧窗帘（主卧）」这类完整中文名。

两个脚本输出的 JSON 都在**每条规则加 `name` 字段**、**顶层加 `names` 映射表**
（`{"规则":{...},"设备":{...},"变量":{...},"_设备名来源"/"_说明"/"_source":...}`），日志/对照表据此翻译。
离线解析 JSON 额外含 `_设备名来源` 字段（值为 `URN 推导` 或 `在线 mijia_id_map.json`），便于追溯设备名来源。

## 环境要求

- Python 3.8+（本机已验证 3.14）
- 与中枢网关同网段，且知道网关**登录码**（米家 App → 网关 → 极客版 → 登录码）
- 无任何第三方库：secp256k1、ECJPAKE、AES-128-GCM、WebSocket 帧均为内置纯 Python 实现

## 快速开始

```bash
# 1) 离线自检（校验内置 AES-128 / AES-GCM / ECJPAKE 密码学实现）
python mijia_geek_client.py --selftest

# 2) 抓取策略 + 日志（默认 192.168.31.1:8086）
python mijia_geek_client.py --passcode 916527

# 3) 指定网关与输出目录
python mijia_geek_client.py --host 192.168.31.1 --port 8086 --passcode 916527 --out-dir D:\gw
```

登录码也可通过环境变量 `MIJIA_PASSCODE` 提供：`set MIJIA_PASSCODE=916527` 后省略 `--passcode`。

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--host` | `192.168.31.1` | 中枢网关 IP |
| `--port` | `8086` | 网关端口 |
| `--passcode` | 环境变量 `MIJIA_PASSCODE` | 网关登录码 |
| `--out-dir` | `<脚本目录>\mijia_gw_out` | 输出目录 |
| `--max-log-blocks N` | `6` | 执行日志最大翻页数（日志按块返回，越大拉得越多） |
| `--no-prompt` | 关 | 非交互模式：失败后不提示输入登录码，自动读 `MIJIA_PASSCODE` 或沿用原值 |
| `--reparse` | — | 不连网关：用 `out-dir` 下已有 `mijia_logs_raw.json` + `mijia_strategies.json` 重新渲染 `mijia_logs.txt` |
| `--flows` | — | 不连网关：基于 `out-dir` 下已有 `mijia_strategies.json` 生成 Mermaid 策略框图到 `mijia_flows/` |
| `--enrich` | — | 不连网关：给 `out-dir` 下已有 `mijia_strategies.json` 就地补全 `name` 字段与顶层 `names` 映射表 |
| `--selftest` | — | 只跑内置密码学自检，不联网 |

### 离线 .bak 解析（mijia_bak2json.py）

```bash
# 把 .bak 备份解析为 JSON（SHA-256 校验 + DEFLATE 解压），输出进 mijia_bak_out/，
# 同时生成人类可读 .txt（规则清单 + 各规则节点明细 + 设备/变量映射表 + 类型统计）
python mijia_bak2json.py 备份2026_11_22_09_16_26.bak

# 自定义输出目录 / 仅 JSON（不输出 txt）/ 打印摘要
python mijia_bak2json.py input.bak --out-dir D:\bak_out --no-txt --summary
python mijia_bak2json.py input.bak -o D:\custom.json   # 指定 JSON 输出路径
python mijia_bak2json.py input.bak --no-flow            # 不生成 Mermaid 框图
```
- 默认输出到 `<脚本目录>/mijia_bak_out/`，可用 `--out-dir` 改目录、`-o` 指定完整 JSON 路径。
- 同时输出同名 `.txt`（UTF-8 BOM），可用 `--no-txt` 关闭。
- 输出 JSON 中每条规则含 `name`，顶层含 `names` 映射表（规则名/变量名来自备份内
  `userData.name`）。**设备名自动选择来源**：若存在 `<脚本目录>/mijia_gw_out/mijia_id_map.json`
  （在线抓取生成），则用其中真实中文名（含房间）覆盖；否则由 URN 推 `<type>(<model>)` 并标注来源。
  JSON 顶层 `_设备名来源` 字段标明当前用的是 `在线 mijia_id_map.json` 还是 `URN 推导`。

## 协议原理（简述）

```
ws://<host>:8086/centrallinkws/
帧 = [1 字节帧类型] + 载荷

  0x01 PROTOCOL_LIST         客户端发送 ["passcode"]
  0x02 SELECTED_PROTOCOL    服务端选定协议
  0x32 ECJPAKE_ROUND_ONE    口令双向认证（secp256k1 + ZKP，口令=登录码）
  0x33 ECJPAKE_ROUND_TWO    完成认证并派生 32 字节会话密钥 E
  0x03 SESSION_KEY_EXCHANGE AES-GCM 交换双向加密通道密钥
  0x05 DATA                 后续全部通信：
                            AES-GCM( [4B LE 原始长度] + raw-DEFLATE(JSON-RPC 2.0) )
                            method = /api/<name>

常用 API：getGraphList / getGraph / getLog / getDevList /
          getVarScopeList / getVarList / createBackup ...
```

- **ECJPAKE**：类 TLS-PSK 的口令认证，登录码经 16 轮 SHA-256 展开为 secp256k1 群上的标量，
  双方交换 2 把公钥并各带一个 Schnorr ZKP（验证知道私钥），最后用共享群点派生会话密钥。
  脚本内置 client/server 双端模拟自检。
- **AES-GCM 通道**：会话密钥 E 前 16B/后 16B 分别为两条 GCM 通道（加密 16B key + 8B salt，
  IV = salt ‖ uint32 LE 计数器），收发各一条，带防重放计数器。
- **JSON-RPC**：请求/响应经 raw-DEFLATE 压缩 + `[4B LE 原长度]` 头，包进 GCM DATA 帧。

## 已知限制与注意事项

1. **网关握手限流**：短时间内重复 ECJPAKE 握手会触发网关 `ERROR` 帧拒绝（保护机制）。
   脚本捕获认证/连接类失败后**重新获取登录码**（交互式终端会提示输入，
   非交互读 `MIJIA_PASSCODE` 或沿用原值），冷却 30s 后最多重试 3 次；
   仍失败时等待数分钟或先在米家 App 登录一次极客版页面，再重跑。
2. **执行日志为增量缓存**：网关的 `getLog` 返回分页块（最新在前），翻页至首块重复即止。
   `--max-log-blocks` 越大拉得越多，但每页请求约数秒。
3. 日志行格式为**管道符分隔字符串**（非 JSON）：`版本|时间戳(ms)|类型(l/i/e/r)|规则ID|...`：
   - `l` 链路：`src节点.端口|dst节点.端口|值`；`i` 节点：`nodeId|信息`（信息常为 JSON 数组字符串，
     脚本会自动拆开，如 `["次卧无人执行"]` → `次卧无人执行`）；`e` 错误、`r` 规则事件。
   解析结果渲染为**简洁单行**形式写入 `mijia_logs.txt`（UTF-8 BOM，记事本/Excel 不乱码）：
   `[时间] [规则名] <源标签> -> <目标签> 值`、`[时间] [规则名] <节点标签> 信息`，
   其中节点标签自动用实际名字（设备中文名 / 变量名 / 定时、条件、或、延时等控制词），不再显示裸 ID 与缩进明细行。
   原始行保留在 `mijia_logs_raw.json`；若渲染逻辑有更新，可用 `--reparse` 离线重渲染，无需重连网关。
4. 策略 JSON 与 `.bak` 备份 JSON 结构一致（`version/rules/nodes/cfg`），可配合
   同目录 `mijia_bak2json.py` 交叉核对。离线解析 `.bak` 时，设备名默认只能到 类型/型号，
   但若已有在线抓取的 `mijia_gw_out/mijia_id_map.json`，则 `mijia_bak2json.py` 会自动
   采用其中的真实中文名，使离线/在线输出的设备名保持一致。

## 输出示例（mijia_strategies.json 顶层）

```json
{
  "fetched_at": "2026-11-23 21:21:05",
  "rules": [
    { "cfg": { "id": "1748878011512", "enable": true,
               "userData": { "name": "全屋-日常状态" } },
      "name": "全屋-日常状态",
      "nodes": [ ... 62 个图节点 ... ] }
  ],
  "devices": { "devList": { "556946080": { "name": "餐厅灯", "roomName": "餐厅", "...": "..." } } },
  "variables": { "global": { "VOyKCbGMep4": { "type": "number", "userData": { "name": "living_lux" } }, "...": "..." } },
  "names": {
    "规则": { "1748878011512": "全屋-日常状态", "...": "..." },
    "设备": { "1110908201": "Yeelight 主卧窗帘（主卧）", "...": "..." },
    "变量": { "VOyKCbGMep4": "living_lux", "...": "..." },
    "_source": "在线 API：getDevList(devList.name/roomName)、getVarList(userData.name)、getGraphList(cfg.userData.name)"
  }
}
```

## 自检说明（--selftest）

| 项 | 参照 |
|---|---|
| AES-128 | FIPS-197 A.1 / A.2 官方向量 |
| AES-GCM | NIST GCM TC1/TC2 + OpenSSL 45 组随机向量全量对拍 |
| GCM 双通道 | 加解密往返 + 重放计数器 |
| ECJPAKE | client/server 双端模拟，两端会话密钥一致 |
