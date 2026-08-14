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

/// 后台扫描任务：先在阻塞线程解析目标（DNS 解析可能阻塞数十秒，不能冻结 UI），
/// 再执行扫描，通过 channel 回报进度与结果
async fn run_scan(
    targets_text: String,
    ports_list: Vec<u16>,
    cfg: scanner::ScanConfig,
    proto: scanner::Proto,
    progress_tx: watch::Sender<Progress>,
    open_tx: mpsc::UnboundedSender<OpenPort>,
    event_tx: mpsc::UnboundedSender<ScanEvent>,
) {
    let parsed = tokio::task::spawn_blocking(move || {
        target::expand_targets(std::slice::from_ref(&targets_text))
    })
    .await;
    let ips = match parsed {
        Ok(Ok(v)) if !v.is_empty() => v,
        Ok(Ok(_)) => {
            let _ = event_tx.send(ScanEvent::Finished(Err("没有有效的扫描目标".into())));
            return;
        }
        Ok(Err(e)) => {
            let _ = event_tx.send(ScanEvent::Finished(Err(format!("目标解析失败: {e:#}"))));
            return;
        }
        Err(e) => {
            let _ = event_tx.send(ScanEvent::Finished(Err(format!("目标解析任务失败: {e}"))));
            return;
        }
    };
    let res = scanner::scan(
        &ips,
        &ports_list,
        &cfg,
        true,
        Some(progress_tx),
        Some(open_tx),
        proto,
    )
    .await;
    let _ = event_tx.send(ScanEvent::Finished(res.map_err(|e| format!("{e:#}"))));
}

fn write_csv(results: &[OpenPort], path: &PathBuf) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(["ip", "port", "proto", "service", "state"])
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

/// 结果表格行：(IP, 端口, 协议, 服务, filtered, suspicious)
type ResultRow = (IpAddr, u16, &'static str, Option<&'static str>, bool, bool);

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
            show_suspicious: true,
            show_filtered: true,
            progress_rx: None,
            open_rx: None,
            event_rx: None,
            handle: None,
        }
    }
}

impl ScanApp {
    fn start_scan(&mut self) {
        // 解析端口范围（同步、快速）；目标解析因涉及阻塞式 DNS，放入后台任务
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
            self.targets_text.clone(),
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
            ui.heading("端口扫描工具");
            ui.add_space(4.0);
            egui::Grid::new("input_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("目标 (IP/域名/CIDR，逗号分隔):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.targets_text)
                            .hint_text("例如 192.168.1.0/24, 192.168.1.10")
                            .desired_width(440.0),
                    );
                    ui.end_row();

                    ui.label("端口范围:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(
                            !self.common_ports,
                            egui::TextEdit::singleline(&mut self.ports_text).desired_width(200.0),
                        );
                        ui.checkbox(&mut self.common_ports, "仅常用端口");
                    });
                    ui.end_row();

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
                    ui.end_row();

                    ui.label("并发数:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.concurrency_text)
                            .desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label("超时 (毫秒):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.timeout_text).desired_width(120.0),
                    );
                    ui.end_row();
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let can_start = !self.running && !self.targets_text.trim().is_empty();
                if ui
                    .add_enabled(can_start, egui::Button::new("▶ 开始扫描"))
                    .clicked()
                {
                    self.start_scan();
                }
                if ui
                    .add_enabled(self.running, egui::Button::new("■ 取消"))
                    .clicked()
                {
                    self.cancel_scan();
                }
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
                let frac = if total > 0 {
                    done as f32 / total as f32
                } else {
                    0.0
                };
                let text = if total > 0 {
                    format!("{done}/{total} ({:.1}%)", frac * 100.0)
                } else {
                    "准备中...".into()
                };
                ui.add(
                    egui::ProgressBar::new(frac)
                        .text(text)
                        .desired_width(f32::INFINITY),
                );
                ui.colored_label(
                    egui::Color32::from_rgb(56, 189, 248),
                    format!(
                        "已耗时 {:.1}s，已发现 {} 个开放端口",
                        self.elapsed.as_secs_f64(),
                        self.results.len()
                    ),
                );
            } else if self.canceled {
                ui.colored_label(
                    egui::Color32::from_rgb(251, 146, 60),
                    egui::RichText::new("已取消").strong(),
                );
            } else if let Some(err) = &self.error {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 85, 85),
                    egui::RichText::new(format!("错误: {err}")).strong(),
                );
            } else if !self.results.is_empty() {
                ui.colored_label(
                    egui::Color32::from_rgb(80, 250, 123),
                    egui::RichText::new(format!(
                        "扫描完成，共发现 {} 个开放端口（耗时 {:.1}s）",
                        self.results.len(),
                        self.elapsed.as_secs_f64()
                    ))
                    .strong(),
                );
            } else {
                ui.weak("就绪 — 输入目标后点击「开始扫描」");
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
                .map(|r| (r.ip, r.port, r.proto, r.service, r.filtered, r.suspicious))
                .collect();
            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.weak("没有匹配当前过滤条件的端口");
                });
                return;
            }
            rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::auto().at_least(150.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::remainder().at_least(120.0))
                .column(Column::auto().at_least(90.0))
                .header(22.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("IP 地址");
                    });
                    header.col(|ui| {
                        ui.strong("端口");
                    });
                    header.col(|ui| {
                        ui.strong("服务");
                    });
                    header.col(|ui| {
                        ui.strong("状态");
                    });
                })
                .body(|mut body| {
                    for (ip, port, proto, svc, filtered, suspicious) in &rows {
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
                                if *suspicious {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(251, 146, 60),
                                        egui::RichText::new("可疑").strong(),
                                    );
                                } else if *filtered {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(250, 204, 21),
                                        egui::RichText::new("open|filtered").strong(),
                                    );
                                } else {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(80, 250, 123),
                                        egui::RichText::new("open").strong(),
                                    );
                                }
                            });
                        });
                    }
                });
        });
    }
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
