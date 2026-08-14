# PortScan — 内网 TCP/UDP 端口扫描工具

基于 Rust 编写的高性能内网端口扫描工具，支持 **CLI 与图形界面（GUI）** 双入口，支持 TCP / UDP / 双协议同时扫描。

> ⚠️ **仅限授权测试**：请勿对未授权的目标进行扫描，使用本工具产生的一切后果由使用者自行承担。

## 功能特性

- 🔍 默认扫描全部端口（1-65535），支持自定义端口范围与**常用端口快速扫描**（约 120 个）
- 🎯 多目标输入：IP 地址、域名、CIDR 网段（支持 `192.168.1.1/24` 主机地址形式），逗号分隔批量扫描
- 🌐 三种扫描模式：**TCP**（connect）/ **UDP**（探测+响应判定）/ **TCP+UDP 同时**
- 🕵️ 可疑劫持检测：25/110/143 邮件端口发送协议探测，连接成功但静默/立即关闭的端口标记为「可疑」（tcpwrapped/网关劫持特征）
- ⏱️ 延迟三测：仅对确认开放端口测量 3 次延迟（如 `2/15/0ms`，失败位置显示 `-`），排序按平均值
- ⚡ 高并发：信号量限流 + 分批任务调度（GUI 默认并发 64，可安全扫描 /16 网段 × 全端口）
- 🏷️ 280+ 端口服务名识别（基础网络/数据库/中间件/容器/监控/游戏服务器，TCP/UDP 分表）
- 📄 结果导出四种格式：**CSV / JSON / TXT / HTML**，头部均含本次扫描总情况（目标/端口/协议/探测点/耗时/各状态计数）
- 🖥️ 图形界面：五段彩色进度条（open 绿/可疑橙/开放过滤黄/其他红/未扫描灰）、实时结果推送、全列排序、状态过滤、域名 IP 多选弹窗、扫描速度显示、中文字体

## 构建

需要 Rust 工具链（stable）：

```bash
cargo build --release
```

产物位于 `target/release/`：

| 文件 | 说明 |
|---|---|
| `portscan.exe` | 命令行工具 |
| `portscan-gui.exe` | 图形界面（egui） |

## 使用

### 图形界面（GUI）

```bash
./target/release/portscan-gui.exe
```

- 输入目标（如 `192.168.1.0/24, 192.168.1.10, router.local`），默认勾选「仅常用端口」、并发 64
- 目标含域名时自动解析，**弹窗多选要扫描的 IP**（可全选/全不选）
- 扫描中实时显示结果与速度；完成后可一键导出 CSV / JSON / TXT / HTML

### 命令行（CLI）

```bash
# 全端口扫描单个 IP
portscan 192.168.1.10

# 扫描网段 + 指定端口（支持主机地址形式 CIDR）
portscan 192.168.1.1/24 -p 80,443,8000-9000

# 只扫描常用端口
portscan 192.168.1.0/24 --common

# UDP 扫描（无响应端口显示为 open|filtered）
portscan 192.168.1.10 -p 53,123,161,500 -u -t 2000

# TCP 与 UDP 同时扫描
portscan 192.168.1.10 -p 80,443,53 -b -t 2000

# 多目标混合输入
portscan "192.168.1.0/24, 10.0.0.5, router.local"

# 导出四种格式报告（头部含扫描总情况）
portscan 192.168.1.0/24 --csv result.csv --json result.json --txt report.txt --html report.html

# 调整并发与超时（毫秒）
portscan 192.168.1.0/24 -c 2048 -t 500

# 静默模式 + 导出结果
portscan 192.168.1.0/24 --quiet --csv result.csv --json result.json
```

### CLI 参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `<TARGETS>` | 目标：IP / 域名 / CIDR，逗号分隔 | 必填 |
| `-p, --ports` | 端口范围，如 `80` / `80,443` / `8000-9000` / `1-65535` | `1-65535` |
| `--common` | 只扫描常用端口（约 120 个） | `false` |
| `-u, --udp` | UDP 扫描模式（无响应端口显示为 open\|filtered） | `false` |
| `-b, --both` | TCP 与 UDP 同时扫描（与 `-u` 互斥） | `false` |
| `-c, --concurrency` | 最大并发连接数（1-65535） | `1024` |
| `-t, --timeout` | 单连接超时（毫秒）；UDP 扫描建议调大（如 2000） | `1000` |
| `--quiet` | 不显示进度（避免污染导出文件） | `false` |
| `--csv <PATH>` | 导出 CSV（头部注释含总情况；列：ip, port, proto, service, latency_ms, state） | 无 |
| `--json <PATH>` | 导出 JSON（含 targets/ports/proto/计数与 open_ports） | 无 |
| `--txt <PATH>` | 导出 TXT 文本报告 | 无 |
| `--html <PATH>` | 导出 HTML 网页报告（白底） | 无 |

### 输出示例

```
127.0.0.1 开放端口 (2):
  80/tcp   (http) 2/0/14ms
  445/tcp  (microsoft-ds) 2/15/0ms
扫描完成: 65535 个探测点, 耗时 10.03s, 共发现 46 个开放端口
```

端口行格式：`端口/协议 (服务) 延迟1/延迟2/延迟3ms [状态]`——延迟为 3 次测量（失败显示 `-`，如 `101/-/105`）；可疑端口带 `[可疑]` 标记，UDP 无响应带 `[open|filtered]`。

### 导出报告

四种格式头部均含本次扫描总情况（目标/端口/协议/探测点/耗时/开放·可疑·开放|过滤计数）：

```
# portscan 扫描报告          （CSV 为 # 注释行；TXT/HTML 为头部区块）
# 目标: 192.168.1.0/24
# 端口: 1-65535
# 协议: tcp
# 探测点: 65535
# 耗时: 12.34s
# 结果: 开放 46 · 可疑 1 · 开放|过滤 0
```

- **CSV**：表头 `ip,port,proto,service,latency_ms,state` + 数据行
- **JSON**：`targets/ports/proto/total_probes/duration_ms/三计数/open_ports`
- **TXT**：文本报告，按 IP 分组列出端口、服务、延迟与状态
- **HTML**：白底网页报告，含结果分布条（绿=open/橙=可疑/黄=open|filtered/红=其他），可直接浏览器打开

## 测试

```bash
cargo test --release
```

34 个单元测试覆盖：扫描核心（并发/串行/超时/进度/UDP 探测/劫持检测/延迟三测）、目标解析（IP/域名/CIDR/主机地址形式/上限）、端口解析（范围/服务名/UDP 分表/常用端口）、报告生成（TXT/HTML/JSON/CSV 头部/HTML 转义/延迟占位显示）。

## 技术栈

- [tokio](https://tokio.rs) — 异步运行时、JoinSet 任务调度、Semaphore 限流
- [clap](https://clap.rs) — CLI 参数解析
- [egui / eframe](https://github.com/emilk/egui) — 即时模式 GUI
- [cidr](https://crates.io/crates/cidr) — CIDR 网段解析
- [rfd](https://crates.io/crates/rfd) — 原生文件对话框

## 许可

MIT
