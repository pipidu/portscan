//! 扫描报告生成：TXT / HTML / JSON / CSV 头部注释

use crate::scanner::OpenPort;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

/// 本次扫描的总情况（导出文件头部信息）
#[derive(Debug, Clone)]
pub struct ReportMeta {
    pub targets: String,
    /// 端口范围描述（如 "1-65535" / "常用端口(120)"）
    pub ports: String,
    pub proto: String,
    pub total_probes: u64,
    pub elapsed_ms: u128,
    pub open: usize,
    pub suspicious: usize,
    pub filtered: usize,
}

impl ReportMeta {
    /// 头部信息行（"键: 值"）
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!("目标: {}", self.targets),
            format!("端口: {}", self.ports),
            format!("协议: {}", self.proto),
            format!("探测点: {}", self.total_probes),
            format!("耗时: {:.2}s", self.elapsed_ms as f64 / 1000.0),
            format!(
                "结果: 开放 {} · 可疑 {} · 开放|过滤 {}",
                self.open, self.suspicious, self.filtered
            ),
        ]
    }
}

/// 按 IP 分组排序的 (ip, port, proto, service, latency, state) 行
fn group_rows(results: &[OpenPort]) -> Vec<(&OpenPort, &'static str)> {
    let mut by_ip: BTreeMap<IpAddr, Vec<&OpenPort>> = BTreeMap::new();
    for r in results {
        by_ip.entry(r.ip).or_default().push(r);
    }
    let mut rows = Vec::new();
    for list in by_ip.values_mut() {
        list.sort_by_key(|r| r.port);
        for r in list.iter() {
            let state = if r.suspicious {
                "可疑"
            } else if r.filtered {
                "open|filtered"
            } else {
                "open"
            };
            rows.push((*r, state));
        }
    }
    rows
}

/// TXT 文本报告
pub fn to_txt(meta: &ReportMeta, results: &[OpenPort]) -> String {
    let mut s = String::new();
    s.push_str("====== portscan 扫描报告 ======\n");
    for line in meta.summary_lines() {
        let _ = writeln!(s, "  {line}");
    }
    s.push_str("--------------------------------\n");
    if results.is_empty() {
        s.push_str("（无开放端口）\n");
        return s;
    }
    for (r, state) in group_rows(results) {
        let latency = if r.latency_ms.is_empty() {
            String::new()
        } else {
            format!(
                " {}ms",
                r.latency_ms
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join("/")
            )
        };
        let svc = r.service.unwrap_or("");
        let _ = writeln!(
            s,
            "{:<20} {}/{}  ({svc}){latency} [{state}]",
            r.ip,
            r.port,
            r.proto
        );
    }
    s
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// HTML 网页报告（内嵌样式，可直接浏览器打开）
pub fn to_html(meta: &ReportMeta, results: &[OpenPort]) -> String {
    let mut s = String::new();
    s.push_str("<!DOCTYPE html>\n<html lang=\"zh\"><head><meta charset=\"utf-8\">\n");
    s.push_str("<title>portscan 扫描报告</title>\n");
    s.push_str("<style>body{font-family:'Microsoft YaHei',sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}\n");
    s.push_str("h1{color:#38bdf8} table{border-collapse:collapse;width:100%;margin-top:12px}\n");
    s.push_str("th,td{border:1px solid #334155;padding:6px 10px;text-align:left}\n");
    s.push_str("th{background:#1e293b} tr:nth-child(even){background:#16213a}\n");
    s.push_str(".open{color:#22c55e;font-weight:bold}.susp{color:#f97316;font-weight:bold}.filt{color:#eab308;font-weight:bold}</style></head><body>\n");
    s.push_str("<h1>portscan 扫描报告</h1>\n");
    s.push_str("<table>\n");
    for line in meta.summary_lines() {
        let (k, v) = line.split_once(':').unwrap_or((line.as_str(), ""));
        let _ = writeln!(s, "<tr><th>{}</th><td>{}</td></tr>", html_escape(k.trim()), html_escape(v.trim()));
    }
    s.push_str("</table>\n");
    if results.is_empty() {
        s.push_str("<p>（无开放端口）</p>\n");
    } else {
        s.push_str("<table><tr><th>IP</th><th>端口</th><th>服务</th><th>延迟</th><th>状态</th></tr>\n");
        for (r, state) in group_rows(results) {
            let latency = if r.latency_ms.is_empty() {
                String::new()
            } else {
                r.latency_ms
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join("/")
                    + "ms"
            };
            let cls = if r.suspicious {
                "susp"
            } else if r.filtered {
                "filt"
            } else {
                "open"
            };
            let _ = writeln!(
                s,
                "<tr><td>{}</td><td>{}/{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td></tr>",
                html_escape(&r.ip.to_string()),
                r.port,
                r.proto,
                html_escape(r.service.unwrap_or("")),
                html_escape(&latency),
                cls,
                state
            );
        }
        s.push_str("</table>\n");
    }
    s.push_str("</body></html>\n");
    s
}

/// JSON 报告（含总情况与结果列表）
pub fn to_json(meta: &ReportMeta, results: &[OpenPort]) -> String {
    #[derive(serde::Serialize)]
    struct Report<'a> {
        targets: &'a str,
        ports: &'a str,
        proto: &'a str,
        total_probes: u64,
        duration_ms: u128,
        open_count: usize,
        suspicious_count: usize,
        filtered_count: usize,
        open_ports: &'a [OpenPort],
    }
    let report = Report {
        targets: &meta.targets,
        ports: &meta.ports,
        proto: &meta.proto,
        total_probes: meta.total_probes,
        duration_ms: meta.elapsed_ms,
        open_count: meta.open,
        suspicious_count: meta.suspicious,
        filtered_count: meta.filtered,
        open_ports: results,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// CSV 头部注释行（写入数据前的总情况，以 # 开头）
pub fn csv_meta_lines(meta: &ReportMeta) -> Vec<String> {
    let mut lines = vec!["# portscan 扫描报告".to_string()];
    lines.extend(meta.summary_lines().into_iter().map(|l| format!("# {l}")));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn sample_meta() -> ReportMeta {
        ReportMeta {
            targets: "192.168.1.0/30".into(),
            ports: "1-65535".into(),
            proto: "tcp".into(),
            total_probes: 4,
            elapsed_ms: 1234,
            open: 1,
            suspicious: 1,
            filtered: 0,
        }
    }

    fn sample_results() -> Vec<OpenPort> {
        vec![
            OpenPort {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port: 80,
                proto: "tcp",
                service: Some("http"),
                latency_ms: vec![2, 3, 2],
                filtered: false,
                suspicious: false,
            },
            OpenPort {
                ip: "192.168.1.2".parse::<IpAddr>().unwrap(),
                port: 25,
                proto: "tcp",
                service: Some("smtp"),
                latency_ms: vec![],
                filtered: false,
                suspicious: true,
            },
        ]
    }

    #[test]
    fn txt_report_contains_meta_and_rows() {
        let txt = to_txt(&sample_meta(), &sample_results());
        assert!(txt.contains("目标: 192.168.1.0/30"));
        assert!(txt.contains("开放 1 · 可疑 1"));
        assert!(txt.contains("80/tcp"));
        assert!(txt.contains("[可疑]"));
        assert!(txt.contains("2/3/2ms"));
    }

    #[test]
    fn html_report_escapes_and_lists() {
        let html = to_html(&sample_meta(), &sample_results());
        assert!(html.contains("<title>portscan 扫描报告</title>"));
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("class=\"open\""));
        assert!(html.contains("class=\"susp\""));
        // 转义验证
        let esc = html_escape("<a href=\"x\">&");
        assert_eq!(esc, "&lt;a href=&quot;x&quot;&gt;&amp;");
    }

    #[test]
    fn json_report_has_counts() {
        let json = to_json(&sample_meta(), &sample_results());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["total_probes"], 4);
        assert_eq!(v["open_count"], 1);
        assert_eq!(v["suspicious_count"], 1);
        assert_eq!(v["open_ports"].as_array().unwrap().len(), 2);
        assert_eq!(v["open_ports"][0]["port"], 80);
    }

    #[test]
    fn csv_meta_lines_prefixed() {
        let lines = csv_meta_lines(&sample_meta());
        assert!(lines[0].starts_with("# "));
        assert!(lines.iter().any(|l| l.contains("探测点: 4")));
    }

    #[test]
    fn empty_results_report() {
        let txt = to_txt(&sample_meta(), &[]);
        assert!(txt.contains("无开放端口"));
        let html = to_html(&sample_meta(), &[]);
        assert!(html.contains("无开放端口"));
    }
}
