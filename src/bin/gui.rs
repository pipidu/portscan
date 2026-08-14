#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use portscan::scanner::{self, OpenPort, Progress};
use portscan::{ports, target};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// 后台扫描事件
enum ScanEvent {
    Finished(Result<Vec<OpenPort>, String>),
}

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().expect("创建 tokio runtime 失败"))
}

/// 后台扫描任务：直接执行扫描，通过 channel 回报进度与结果
/// （目标 IP 由 GUI 解析：含域名时先弹窗让用户选择 IP）
async fn run_scan(
    ips: Vec<IpAddr>,
    ports_list: Vec<u16>,
    cfg: scanner::ScanConfig,
    proto: scanner::Proto,
    progress_tx: watch::Sender<Progress>,
    open_tx: mpsc::UnboundedSender<OpenPort>,
    event_tx: mpsc::UnboundedSender<ScanEvent>,
) {
    let res = scanner::scan(&ips, &ports_list, &cfg, true, Some(progress_tx), Some(open_tx), proto).await;
    let _ = event_tx.send(ScanEvent::Finished(res.map_err(|e| format!("{e:#}"))));
}

fn write_csv(results: &[OpenPort], path: &PathBuf) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(["ip", "port", "proto", "service", "latency_ms", "state"])
        .map_err(|e| e.to_string())?;
    for r in results {
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
            r.latency_ms
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join("/"),
            state.to_string(),
        ])
        .map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn write_json(results: &[OpenPort], path: &PathBuf) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Report<'a> {
        open_count: usize,
        open_ports: &'a [OpenPort],
    }
    let report = Report {
        open_count: results.len(),
        open_ports: results,
    };
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())?;
    Ok(())
}

/// 结果表格行：(IP, 端口, 协议, 服务, 延迟ms, filtered, suspicious)
type ResultRow = (IpAddr, u16, &'static str, Option<&'static str>, Vec<u64>, bool, bool);

/// 表格排序列
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Ip,
    Port,
    Service,
    Latency,
    State,
}

struct ScanApp {
    // 输入
    targets_text: String,
    ports_text: String,
    concurrency_text: String,
    timeout_text: String,
    proto: scanner::Proto,
    common_ports: bool,
    // 扫描状态
    running: bool,
    canceled: bool,
    progress: Option<Progress>,
    elapsed: Duration,
    started_at: Option<Instant>,
    error: Option<String>,
    // 结果
    results: Vec<OpenPort>,
    // 状态过滤（表格显示）
    show_open: bool,
    show_suspicious: bool,
    show_filtered: bool,
    // 表格排序
    sort_col: SortCol,
    sort_asc: bool,
    // 目标数量（异步解析，用于显示探测点总数）
    target_count: Option<usize>,
    target_count_for: String,
    target_count_rx: Option<mpsc::UnboundedReceiver<usize>>,
    // 域名 IP 选择弹窗
    picker_rx: Option<mpsc::UnboundedReceiver<Vec<IpAddr>>>,
    pending_ips: Vec<IpAddr>,
    selected_ips: Vec<bool>,
    show_picker: bool,
    // 后台任务
    progress_rx: Option<watch::Receiver<Progress>>,
    open_rx: Option<mpsc::UnboundedReceiver<OpenPort>>,
    event_rx: Option<mpsc::UnboundedReceiver<ScanEvent>>,
    handle: Option<JoinHandle<()>>,
}

impl Default for ScanApp {
    fn default() -> Self {
        Self {
            targets_text: String::new(),
            ports_text: "1-65535".into(),
            concurrency_text: "1024".into(),
            timeout_text: "1000".into(),
            proto: scanner::Proto::Tcp,
            common_ports: false,
            running: false,
            canceled: false,
            progress: None,
            elapsed: Duration::ZERO,
            started_at: None,
            error: None,
            results: Vec::new(),
            show_open: true,
            show_suspicious: false,
            show_filtered: false,
            sort_col: SortCol::Port,
            sort_asc: true,
            target_count: None,
            target_count_for: String::new(),
            target_count_rx: None,
            picker_rx: None,
            pending_ips: Vec::new(),
            selected_ips: Vec::new(),
            show_picker: false,
            progress_rx: None,
            open_rx: None,
            event_rx: None,
            handle: None,
        }
    }
}

impl ScanApp {
    fn start_scan(&mut self) {
        // 目标含域名时异步解析（DNS 可能慢），解析后弹窗让用户选择要扫描的 IP
        if has_hostname(&self.targets_text) {
            let (tx, rx) = mpsc::unbounded_channel();
            self.picker_rx = Some(rx);
            let text = self.targets_text.clone();
            runtime().spawn_blocking(move || {
                let ips = target::expand_targets(&[text]).unwrap_or_default();
                let _ = tx.send(ips);
            });
            return;
        }
        // 纯 IP / CIDR：同步解析（快速，无 DNS），直接扫描
        match target::expand_targets(std::slice::from_ref(&self.targets_text)) {
            Ok(ips) if !ips.is_empty() => self.launch_scan(ips),
            Ok(_) => self.error = Some("没有有效的扫描目标".into()),
            Err(e) => self.error = Some(format!("目标解析失败: {e:#}")),
        }
    }

    /// 以给定 IP 列表启动扫描（含输入校验与后台任务创建）
    fn launch_scan(&mut self, ips: Vec<IpAddr>) {
        // 解析端口范围（同步、快速）
        let ports_list = if self.common_ports {
            ports::COMMON_PORTS.to_vec()
        } else {
            match ports::parse_ports(&self.ports_text) {
                Ok(v) if !v.is_empty() => v,
                Ok(_) => {
                    self.error = Some("没有有效的端口".into());
                    return;
                }
                Err(e) => {
                    self.error = Some(format!("端口解析失败: {e:#}"));
                    return;
                }
            }
        };
        let concurrency: usize = match self.concurrency_text.trim().parse() {
            Ok(v) if (1..=65_535).contains(&v) => v,
            _ => {
                self.error = Some("并发数必须是 1-65535 之间的整数".into());
                return;
            }
        };
        let timeout_ms: u64 = match self.timeout_text.trim().parse() {
            Ok(v) if v >= 1 => v,
            _ => {
                self.error = Some("超时必须是 1 以上的整数（毫秒）".into());
                return;
            }
        };

        let cfg = scanner::ScanConfig {
            concurrency,
            timeout_ms,
        };
        // 进度 watch channel（只保留最新值，UI 读取不积压）与结果 channel 分离
        let (progress_tx, progress_rx) = watch::channel(Progress { done: 0, total: 0 });
        let (open_tx, open_rx) = mpsc::unbounded_channel::<OpenPort>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<ScanEvent>();
        let handle = runtime().spawn(run_scan(
            ips,
            ports_list,
            cfg,
            self.proto,
            progress_tx,
            open_tx,
            event_tx,
        ));
        self.progress_rx = Some(progress_rx);
        self.open_rx = Some(open_rx);
        self.event_rx = Some(event_rx);
        self.handle = Some(handle);
        self.running = true;
        self.canceled = false;
        self.error = None;
        self.results.clear();
        self.progress = None;
        self.started_at = Some(Instant::now());
        self.elapsed = Duration::ZERO;
    }

    fn cancel_scan(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        self.running = false;
        self.canceled = true;
        self.event_rx = None;
        self.progress_rx = None;
        self.open_rx = None;
        self.progress = None;
        self.started_at = None;
    }

    fn poll_events(&mut self) {
        // 目标数量异步解析：输入变化时在阻塞线程解析（DNS 可能慢），完成后经 channel 回传
        if self.target_count_for != self.targets_text {
            self.target_count_for = self.targets_text.clone();
            self.target_count = None;
            if !self.targets_text.trim().is_empty() {
                let (tx, rx) = mpsc::unbounded_channel();
                self.target_count_rx = Some(rx);
                let text = self.targets_text.clone();
                runtime().spawn_blocking(move || {
                    let n = target::expand_targets(&[text])
                        .map(|v| v.len())
                        .unwrap_or(0);
                    let _ = tx.send(n);
                });
            }
        }
        if let Some(rx) = &mut self.target_count_rx {
            if let Ok(n) = rx.try_recv() {
                self.target_count = Some(n);
                self.target_count_rx = None;
            }
        }
        // 域名目标解析完成：>1 个 IP 弹窗选择，1 个直接扫描，0 个报错
        if let Some(rx) = &mut self.picker_rx {
            if let Ok(ips) = rx.try_recv() {
                self.picker_rx = None;
                if ips.is_empty() {
                    self.error = Some("没有有效的扫描目标".into());
                } else if ips.len() == 1 {
                    self.launch_scan(ips);
                } else {
                    self.pending_ips = ips;
                    self.selected_ips = vec![true; self.pending_ips.len()];
                    self.show_picker = true;
                }
            }
        }
        // 进度（watch 只保留最新值）
        if let Some(rx) = &mut self.progress_rx {
            if rx.has_changed().unwrap_or(false) {
                self.progress = Some(*rx.borrow_and_update());
            }
        }
        // 实时开放端口：扫描过程中边发现边追加到结果表格
        if let Some(rx) = &mut self.open_rx {
            while let Ok(op) = rx.try_recv() {
                self.results.push(op);
            }
        }
        // 完成/失败消息（至多一条，收到即结束）
        let Some(rx) = &mut self.event_rx else {
            return;
        };
        if let Ok(ScanEvent::Finished(res)) = rx.try_recv() {
            match res {
                Ok(v) => self.results = v,
                Err(e) => self.error = Some(e),
            }
            self.running = false;
            self.handle = None;
            self.event_rx = None;
            self.progress_rx = None;
            self.open_rx = None;
            self.started_at = None;
        }
    }

    /// 底栏开放端口数（仅统计确认 open 状态，不含可疑/过滤）
    fn open_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| !r.suspicious && !r.filtered)
            .count()
    }

    fn toggle_sort(&mut self, col: SortCol) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = true;
        }
    }

    fn export_dialog(&mut self, kind: &str) {
        let filter = if kind == "csv" { "CSV 文件" } else { "JSON 文件" };
        let ext = kind;
        let Some(path) = rfd::FileDialog::new()
            .add_filter(filter, &[ext])
            .set_file_name(format!("scan-result.{ext}"))
            .save_file()
        else {
            return;
        };
        let res = if kind == "csv" {
            write_csv(&self.results, &path)
        } else {
            write_json(&self.results, &path)
        };
        if let Err(e) = res {
            self.error = Some(format!("导出 {kind} 失败: {e}"));
        }
    }
}

impl eframe::App for ScanApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        if self.running {
            self.elapsed = self.started_at.map_or(Duration::ZERO, |t| t.elapsed());
            // 扫描中持续刷新进度
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // ---- 顶部输入区 ----
        egui::Panel::top("input").show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("端口扫描工具");
                ui.weak("— 内网 TCP/UDP 端口扫描");
            });
            ui.add_space(4.0);
            // 目标输入（整行，回车即开始扫描）
            let target_edit = ui
                .horizontal(|ui| {
                    ui.label("目标:");
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.targets_text)
                            .hint_text("例如 192.168.1.0/24, 192.168.1.10, router.local")
                            .desired_width(480.0),
                    );
                    // 解析出的 IP 数量（域名多 IP 时提示）
                    if let Some(n) = self.target_count {
                        if n > 1 {
                            ui.weak(format!("→ {n} 个 IP"));
                        }
                    }
                    edit
                })
                .inner;
            if target_edit.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                && !self.running
                && !self.targets_text.trim().is_empty()
            {
                self.start_scan();
            }
            // 参数单行：端口 / 仅常用 / 协议 / 并发 / 超时
            ui.horizontal(|ui| {
                ui.label("端口:");
                ui.add_enabled(
                    !self.common_ports,
                    egui::TextEdit::singleline(&mut self.ports_text).desired_width(150.0),
                );
                ui.checkbox(&mut self.common_ports, "仅常用端口");
                ui.separator();
                ui.label("协议:");
                egui::ComboBox::from_id_salt("proto_combo")
                    .selected_text(match self.proto {
                        scanner::Proto::Tcp => "TCP",
                        scanner::Proto::Udp => "UDP",
                        scanner::Proto::Both => "TCP+UDP",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.proto, scanner::Proto::Tcp, "TCP");
                        ui.selectable_value(&mut self.proto, scanner::Proto::Udp, "UDP");
                        ui.selectable_value(&mut self.proto, scanner::Proto::Both, "TCP+UDP");
                    });
                ui.separator();
                ui.label("并发:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.concurrency_text).desired_width(70.0),
                );
                ui.label("超时(ms):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.timeout_text).desired_width(70.0),
                );
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let can_start = !self.running && !self.targets_text.trim().is_empty();
                // 开始按钮：主色填充
                let start_btn = egui::Button::new(egui::RichText::new("▶ 开始扫描").strong())
                    .fill(egui::Color32::from_rgb(22, 163, 74))
                    .stroke(egui::Stroke::NONE);
                if ui.add_enabled(can_start, start_btn).clicked() {
                    self.start_scan();
                }
                // 取消按钮：红色描边
                let cancel_btn = egui::Button::new(egui::RichText::new("■ 取消").strong())
                    .stroke(egui::Stroke::new(1.5, egui::Color32::from_rgb(220, 60, 60)));
                if ui.add_enabled(self.running, cancel_btn).clicked() {
                    self.cancel_scan();
                }
                ui.separator();
                let has_results = !self.results.is_empty();
                if ui
                    .add_enabled(has_results, egui::Button::new("导出 CSV"))
                    .clicked()
                {
                    self.export_dialog("csv");
                }
                if ui
                    .add_enabled(has_results, egui::Button::new("导出 JSON"))
                    .clicked()
                {
                    self.export_dialog("json");
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // 探测点总数：IP 数 × 端口数（目标数异步解析，含域名时稍候）
                    let port_count = if self.common_ports {
                        Some(ports::COMMON_PORTS.len())
                    } else {
                        ports::parse_ports(&self.ports_text).ok().map(|p| p.len())
                    };
                    match (self.target_count, port_count) {
                        (Some(ips), Some(ps)) if ips > 0 => {
                            ui.weak(format!(
                                "探测点: {ips}×{ps}={}",
                                ips as u64 * ps as u64
                            ));
                        }
                        _ => {
                            ui.weak("探测点: —");
                        }
                    }
                });
            });
            ui.add_space(8.0);
        });

        // ---- 底部状态区 ----
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(4.0);
            if self.running {
                let (done, total) = match self.progress {
                    Some(p) if p.total > 0 => (p.done, p.total),
                    _ => (0, 0),
                };
                let open_n = self.open_count();
                // 分段进度条：绿=已扫描开放端口，红=已扫描非开放，灰=未扫描
                let total_w = ui.available_width();
                let (green_w, red_w) = if total > 0 {
                    (
                        total_w * (open_n as f32 / total as f32),
                        total_w * (done.saturating_sub(open_n) as f32 / total as f32),
                    )
                } else {
                    (0.0, 0.0)
                };
                let gray_w = (total_w - green_w - red_w).max(0.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    if green_w > 0.0 {
                        ui.add(
                            egui::ProgressBar::new(1.0)
                                .fill(egui::Color32::from_rgb(34, 197, 94))
                                .desired_width(green_w),
                        );
                    }
                    if red_w > 0.0 {
                        ui.add(
                            egui::ProgressBar::new(1.0)
                                .fill(egui::Color32::from_rgb(239, 68, 68))
                                .desired_width(red_w),
                        );
                    }
                    if gray_w > 0.0 {
                        ui.add(
                            egui::ProgressBar::new(1.0)
                                .fill(egui::Color32::from_rgb(75, 85, 99))
                                .desired_width(gray_w),
                        );
                    }
                });
                if total > 0 {
                    ui.weak(format!(
                        "{done}/{total} ({:.1}%) · 开放 {open_n} 个",
                        done as f32 * 100.0 / total as f32
                    ));
                } else {
                    ui.weak("准备中...");
                }
                stroked_text(
                    ui,
                    format!(
                        "● 已耗时 {:.1}s",
                        self.elapsed.as_secs_f64()
                    ),
                    egui::Color32::from_rgb(59, 130, 246),
                );
            } else if self.canceled {
                stroked_text(ui, "■ 已取消", egui::Color32::from_rgb(249, 115, 22));
            } else if let Some(err) = &self.error {
                stroked_text(
                    ui,
                    format!("✗ 错误: {err}"),
                    egui::Color32::from_rgb(239, 68, 68),
                );
            } else if !self.results.is_empty() {
                stroked_text(
                    ui,
                    format!(
                        "✓ 扫描完成，共发现 {} 个开放端口（耗时 {:.1}s）",
                        self.open_count(),
                        self.elapsed.as_secs_f64()
                    ),
                    egui::Color32::from_rgb(34, 197, 94),
                );
            } else {
                stroked_text(
                    ui,
                    "○ 就绪 — 输入目标后点击「开始扫描」",
                    egui::Color32::from_rgb(148, 163, 184),
                );
            }
            ui.add_space(4.0);
        });

        // ---- 中央结果表格 ----
        egui::CentralPanel::default().show(ui, |ui| {
            if self.results.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.weak("扫描结果将显示在这里");
                });
                return;
            }
            // 状态过滤控件
            ui.horizontal(|ui| {
                ui.label("状态过滤:");
                ui.checkbox(&mut self.show_open, "open");
                ui.checkbox(&mut self.show_suspicious, "可疑");
                ui.checkbox(&mut self.show_filtered, "open|filtered");
            });
            ui.add_space(4.0);
            let mut rows: Vec<ResultRow> = self
                .results
                .iter()
                .filter(|r| {
                    if r.suspicious {
                        self.show_suspicious
                    } else if r.filtered {
                        self.show_filtered
                    } else {
                        self.show_open
                    }
                })
                .map(|r| {
                    (
                        r.ip,
                        r.port,
                        r.proto,
                        r.service,
                        r.latency_ms.clone(),
                        r.filtered,
                        r.suspicious,
                    )
                })
                .collect();
            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.weak("没有匹配当前过滤条件的端口");
                });
                return;
            }
            // 按当前排序列与方向排序
            let (sort_col, sort_asc) = (self.sort_col, self.sort_asc);
            rows.sort_by(|a, b| {
                let ord = match sort_col {
                    SortCol::Ip => a.0.cmp(&b.0),
                    SortCol::Port => a.1.cmp(&b.1),
                    SortCol::Service => a.3.unwrap_or("").cmp(b.3.unwrap_or("")),
                    SortCol::Latency => avg_latency(&a.4).cmp(&avg_latency(&b.4)),
                    SortCol::State => state_rank(a).cmp(&state_rank(b)),
                };
                if sort_asc {
                    ord
                } else {
                    ord.reverse()
                }
            });
            // 表头排序按钮：箭头表示当前列与方向
            let header_btn = |ui: &mut egui::Ui, title: &str, col: SortCol, app: &mut ScanApp| {
                let arrow = if app.sort_col == col {
                    if app.sort_asc {
                        " ↑"
                    } else {
                        " ↓"
                    }
                } else {
                    ""
                };
                if ui.button(format!("{title}{arrow}")).clicked() {
                    app.toggle_sort(col);
                }
            };
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::auto().at_least(150.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::remainder().at_least(120.0))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(90.0))
                .header(22.0, |mut header| {
                    header.col(|ui| header_btn(ui, "IP 地址", SortCol::Ip, self));
                    header.col(|ui| header_btn(ui, "端口", SortCol::Port, self));
                    header.col(|ui| header_btn(ui, "服务", SortCol::Service, self));
                    header.col(|ui| header_btn(ui, "延迟", SortCol::Latency, self));
                    header.col(|ui| header_btn(ui, "状态", SortCol::State, self));
                })
                .body(|mut body| {
                    for (ip, port, proto, svc, latency, filtered, suspicious) in &rows {
                        body.row(18.0, |mut row| {
                            row.col(|ui| {
                                ui.label(ip.to_string());
                            });
                            row.col(|ui| {
                                ui.label(format!("{port}/{proto}"));
                            });
                            row.col(|ui| {
                                ui.label(svc.unwrap_or(""));
                            });
                            row.col(|ui| {
                                let text = if latency.is_empty() {
                                    String::new()
                                } else {
                                    format!(
                                        "{}ms",
                                        latency
                                            .iter()
                                            .map(|l| l.to_string())
                                            .collect::<Vec<_>>()
                                            .join("/")
                                    )
                                };
                                ui.label(text);
                            });
                            row.col(|ui| {
                                if *suspicious {
                                    stroked_text(
                                        ui,
                                        "可疑",
                                        egui::Color32::from_rgb(249, 115, 22),
                                    );
                                } else if *filtered {
                                    stroked_text(
                                        ui,
                                        "open|filtered",
                                        egui::Color32::from_rgb(234, 179, 8),
                                    );
                                } else {
                                    stroked_text(
                                        ui,
                                        "open",
                                        egui::Color32::from_rgb(34, 197, 94),
                                    );
                                }
                            });
                        });
                    }
                });
        });

        // ---- 域名 IP 选择弹窗 ----
        if self.show_picker {
            egui::Window::new("选择要扫描的 IP")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.label(format!(
                        "域名解析出 {} 个 IP，请选择要扫描的目标：",
                        self.pending_ips.len()
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let all_selected = !self.selected_ips.contains(&false);
                        if ui
                            .button(if all_selected { "全不选" } else { "全选" })
                            .clicked()
                        {
                            for s in &mut self.selected_ips {
                                *s = !all_selected;
                            }
                        }
                        ui.weak(format!(
                            "已选 {}/{}",
                            self.selected_ips.iter().filter(|s| **s).count(),
                            self.selected_ips.len()
                        ));
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            for (i, ip) in self.pending_ips.iter().enumerate() {
                                ui.checkbox(&mut self.selected_ips[i], ip.to_string());
                            }
                        });
                    ui.separator();
                    ui.horizontal(|ui| {
                        let selected: Vec<IpAddr> = self
                            .pending_ips
                            .iter()
                            .zip(self.selected_ips.iter())
                            .filter(|(_, &s)| s)
                            .map(|(ip, _)| *ip)
                            .collect();
                        let can_go = !selected.is_empty() && !self.running;
                        let go_btn = egui::Button::new(egui::RichText::new("开始扫描所选").strong())
                            .fill(egui::Color32::from_rgb(22, 163, 74))
                            .stroke(egui::Stroke::NONE);
                        if ui.add_enabled(can_go, go_btn).clicked() {
                            self.show_picker = false;
                            self.pending_ips.clear();
                            self.selected_ips.clear();
                            self.launch_scan(selected);
                        }
                        if ui.button("取消").clicked() {
                            self.show_picker = false;
                            self.pending_ips.clear();
                            self.selected_ips.clear();
                        }
                    });
                });
        }
    }
}

/// 目标文本是否包含域名（非 IP、非 CIDR 的片段）
fn has_hostname(targets: &str) -> bool {
    targets.split(',').any(|t| {
        let t = t.trim();
        !t.is_empty() && t.parse::<IpAddr>().is_err() && !t.contains('/')
    })
}

/// 延迟平均值（空列表按最大值处理，排序时排最后）
fn avg_latency(l: &[u64]) -> u64 {
    if l.is_empty() {
        u64::MAX
    } else {
        l.iter().sum::<u64>() / l.len() as u64
    }
}

/// 状态排序权重：open < suspicious < open|filtered
fn state_rank(r: &ResultRow) -> u8 {
    if r.5 {
        2
    } else if r.6 {
        1
    } else {
        0
    }
}

/// 绘制状态文字（纯色无描边；使用中等深度颜色，深浅主题下均清晰）
fn stroked_text(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>, color: egui::Color32) {
    let font_id = egui::FontId::proportional(14.0);
    let galley = text
        .into()
        .into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, font_id.clone());
    let pos = ui.cursor().min + egui::vec2(0.0, ui.spacing().item_spacing.y);
    ui.painter().galley(pos, galley.clone(), color);
    ui.advance_cursor_after_rect(galley.rect.translate(pos.to_vec2()));
}

/// 加载系统中文字体，解决 egui 默认字体不含 CJK 字符导致的乱码/方块问题
fn setup_cjk_fonts(ctx: &egui::Context) {
    // 按优先级尝试常见中文字体
    const CANDIDATES: [&str; 6] = [
        "C:\\Windows\\Fonts\\msyh.ttc",   // 微软雅黑
        "C:\\Windows\\Fonts\\msyhbd.ttc", // 微软雅黑粗体
        "C:\\Windows\\Fonts\\simhei.ttf", // 黑体
        "C:\\Windows\\Fonts\\simsun.ttc", // 宋体
        "C:\\Windows\\Fonts\\Deng.ttf",   // 等线
        "C:\\Windows\\Fonts\\msjh.ttc",   // 微软正黑（繁体）
    ];
    let Some(data) = CANDIDATES.iter().find_map(|p| std::fs::read(p).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("cjk".to_owned(), egui::FontData::from_owned(data).into());
    // 追加到所有字体族末尾作为回退，保证中英文混合正常显示
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("cjk".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 620.0])
            .with_min_inner_size([720.0, 460.0])
            .with_title("端口扫描工具"),
        ..Default::default()
    };
    eframe::run_native(
        "portscan-gui",
        options,
        Box::new(|cc| {
            setup_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(ScanApp::default()))
        }),
    )
}
