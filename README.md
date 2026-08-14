# PortScan — 内网 TCP 端口扫描工具

基于 Rust 编写的高性能内网端口扫描工具，支持 **CLI 与图形界面（GUI）** 双入口，默认扫描全部 65535 个端口。

> ⚠️ **仅限授权测试**：请勿对未授权的目标进行扫描，使用本工具产生的一切后果由使用者自行承担。

## 功能特性

- 🔍 默认扫描全部端口（1-65535），也支持自定义端口范围（如 `80,443,8000-9000`）
- 🎯 多目标输入：IP 地址、域名、CIDR 网段，逗号分隔批量扫描
- ⚡ 高并发：信号量限流 + 分批任务调度，兼顾速度与资源占用（可安全扫描 /16 网段 × 全端口）
- ⏱️ 可配置连接超时
- 🏷️ 常见端口服务名识别（HTTP、HTTPS、SSH、SMB 等 60+ 服务）
- 📄 结果导出：CSV / JSON 格式
- 🖥️ 图形界面：实时进度条、结果表格、一键取消、原生导出对话框、中文界面

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

- 输入目标（如 `192.168.1.0/24, 192.168.1.10`）与端口范围，点击「开始扫描」
- 扫描中可随时取消；完成后可一键导出 CSV / JSON

### 命令行（CLI）

```bash
# 全端口扫描单个 IP
portscan 192.168.1.10

# 扫描网段 + 指定端口
portscan 192.168.1.0/24 -p 80,443,8000-9000

# UDP 扫描（无响应端口显示为 open|filtered）
portscan 192.168.1.10 -p 53,123,161,500 -u -t 2000

# TCP 与 UDP 同时扫描
portscan 192.168.1.10 -p 80,443,53 -b -t 2000

# 多目标混合输入
portscan "192.168.1.0/24, 10.0.0.5, router.local"

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
| `-u, --udp` | UDP 扫描模式（无响应端口显示为 open\|filtered） | `false` |
| `-b, --both` | TCP 与 UDP 同时扫描（与 `-u` 互斥） | `false` |
| `-c, --concurrency` | 最大并发连接数（1-65535） | `1024` |
| `-t, --timeout` | 单连接超时（毫秒）；UDP 扫描建议调大（如 2000） | `1000` |
| `--quiet` | 不显示进度（避免污染导出文件） | `false` |
| `--csv <PATH>` | 导出 CSV（列：ip, port, proto, service, state） | 无 |
| `--json <PATH>` | 导出 JSON | 无 |

### 输出示例

```
127.0.0.1 开放端口 (2):
  80/tcp   (http)
  445/tcp  (microsoft-ds)
扫描完成: 65535 个探测点, 耗时 10.03s, 共发现 46 个开放端口
```

## 测试

```bash
cargo test --release
```

17 个单元测试覆盖：扫描核心（并发/串行/超时/进度）、目标解析（IP/域名/CIDR/上限）、端口解析（范围/服务名/非法输入）。

## 技术栈

- [tokio](https://tokio.rs) — 异步运行时、JoinSet 任务调度、Semaphore 限流
- [clap](https://clap.rs) — CLI 参数解析
- [egui / eframe](https://github.com/emilk/egui) — 即时模式 GUI
- [cidr](https://crates.io/crates/cidr) — CIDR 网段解析
- [rfd](https://crates.io/crates/rfd) — 原生文件对话框

## 许可

MIT
