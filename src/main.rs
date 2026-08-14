mod cli;

use anyhow::Context;
use clap::Parser;
use cli::Cli;
use portscan::scanner::OpenPort;
use portscan::{ports, scanner, target};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 1. 展开扫描目标（IP / 域名 / CIDR）
    let ips = target::expand_targets(&cli.targets).context("解析扫描目标失败")?;
    if ips.is_empty() {
        anyhow::bail!("没有有效的扫描目标");
    }

    // 2. 解析端口范围（默认全端口 1-65535；--common 时用常用端口表）
    let ports = if cli.common {
        ports::COMMON_PORTS.to_vec()
    } else {
        ports::parse_ports(&cli.ports).context("解析端口范围失败")?
    };
    if ports.is_empty() {
        anyhow::bail!("没有有效的端口");
    }

    let total = ips.len() as u64 * ports.len() as u64;
    if cli.timeout == 0 {
        anyhow::bail!("超时必须为 1 以上的整数（毫秒）");
    }
    if !cli.quiet {
        if total > 50_000_000 {
            eprintln!(
                "警告: 探测点数量巨大（{total}），预计耗时很长，建议缩小目标网段或端口范围"
            );
        }
        eprintln!(
            "开始扫描: {} 个目标 × {} 个端口 = {} 个探测点 | 并发 {} | 超时 {}ms",
            ips.len(),
            ports.len(),
            total,
            cli.concurrency,
            cli.timeout
        );
    }

    // 3. 执行扫描
    let proto = if cli.udp {
        scanner::Proto::Udp
    } else if cli.both {
        scanner::Proto::Both
    } else {
        scanner::Proto::Tcp
    };
    let started = Instant::now();
    let cfg = scanner::ScanConfig {
        concurrency: cli.concurrency,
        timeout_ms: cli.timeout,
    };
    let results = scanner::scan(&ips, &ports, &cfg, cli.quiet, None, None, proto).await?;
    let elapsed = started.elapsed();

    // 4. 按 IP 分组输出开放端口（结果始终打印，quiet 仅隐藏进度与统计）
    let mut by_ip: BTreeMap<IpAddr, Vec<&OpenPort>> = BTreeMap::new();
    for r in &results {
        by_ip.entry(r.ip).or_default().push(r);
    }
    for (ip, port_list) in &mut by_ip {
        port_list.sort_by_key(|r| r.port);
        println!("\n{} 开放端口 ({}):", ip, port_list.len());
        for r in port_list.iter() {
            let state = if r.suspicious {
                " [可疑]"
            } else if r.filtered {
                " [open|filtered]"
            } else {
                ""
            };
            let latency = if r.latency_ms.is_empty() {
                String::new()
            } else {
                format!(" {}ms", portscan::report::latency_display(&r.latency_ms))
            };
            match r.service {
                Some(svc) => println!("  {}/{}  ({svc}){latency}{state}", r.port, r.proto),
                None => println!("  {}/{}{latency}{state}", r.port, r.proto),
            }
        }
    }
    if !cli.quiet {
        let filtered = results.iter().filter(|r| r.filtered).count();
        let suspicious = results.iter().filter(|r| r.suspicious).count();
        let mut notes = Vec::new();
        if filtered > 0 {
            notes.push(format!("{filtered} 个 open|filtered"));
        }
        if suspicious > 0 {
            notes.push(format!("{suspicious} 个可疑（疑似劫持）"));
        }
        let state_note = if notes.is_empty() {
            String::new()
        } else {
            format!("（其中 {}）", notes.join("，"))
        };
        eprintln!(
            "\n扫描完成: {} 个探测点, 耗时 {:.2}s, 共发现 {} 个开放端口{state_note}",
            total,
            elapsed.as_secs_f64(),
            results.len()
        );
    }

    // 5. 导出（CSV / JSON / TXT / HTML，头部均含本次扫描总情况）
    let meta = portscan::report::ReportMeta {
        targets: cli.targets.join(","),
        ports: if cli.common {
            format!("常用端口({})", ports::COMMON_PORTS.len())
        } else {
            cli.ports.clone()
        },
        proto: proto.name().to_string(),
        total_probes: total,
        elapsed_ms: elapsed.as_millis(),
        open: results.iter().filter(|r| !r.suspicious && !r.filtered).count(),
        suspicious: results.iter().filter(|r| r.suspicious).count(),
        filtered: results.iter().filter(|r| r.filtered).count(),
    };

    if let Some(path) = &cli.csv {
        let mut wtr = csv::WriterBuilder::new()
            .flexible(true)
            .from_path(path)
            .with_context(|| format!("无法创建 CSV 文件: {}", path.display()))?;
        for line in portscan::report::csv_meta_lines(&meta) {
            wtr.write_record([line.as_str()])
                .with_context(|| format!("写入 CSV 失败: {}", path.display()))?;
        }
        wtr.write_record(["ip", "port", "proto", "service", "latency_ms", "state"])?;
        for r in &results {
            let state = if r.suspicious {
                "suspicious"
            } else if r.filtered {
                "open|filtered"
            } else {
                "open"
            };
            wtr.write_record([
                r.ip.to_string(),
                r.port.to_string(),
                r.proto.to_string(),
                r.service.unwrap_or("").to_string(),
                portscan::report::latency_display(&r.latency_ms),
                state.to_string(),
            ])
            .with_context(|| format!("写入 CSV 失败: {}", path.display()))?;
        }
        wtr.flush()
            .with_context(|| format!("写入 CSV 失败: {}", path.display()))?;
        if !cli.quiet {
            eprintln!("已导出 CSV: {}", path.display());
        }
    }

    if let Some(path) = &cli.json {
        let json = portscan::report::to_json(&meta, &results);
        std::fs::write(path, json)
            .with_context(|| format!("无法写入 JSON 文件: {}", path.display()))?;
        if !cli.quiet {
            eprintln!("已导出 JSON: {}", path.display());
        }
    }

    if let Some(path) = &cli.txt {
        let txt = portscan::report::to_txt(&meta, &results);
        std::fs::write(path, txt)
            .with_context(|| format!("无法写入 TXT 文件: {}", path.display()))?;
        if !cli.quiet {
            eprintln!("已导出 TXT: {}", path.display());
        }
    }

    if let Some(path) = &cli.html {
        let html = portscan::report::to_html(&meta, &results);
        std::fs::write(path, html)
            .with_context(|| format!("无法写入 HTML 文件: {}", path.display()))?;
        if !cli.quiet {
            eprintln!("已导出 HTML: {}", path.display());
        }
    }

    Ok(())
}
