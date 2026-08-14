use crate::ports::service_name;
use anyhow::Result;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

/// 扫描协议
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    /// TCP 与 UDP 同时扫描
    Both,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Both => "tcp+udp",
        }
    }
}

/// 单个探测点的结果状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    /// 确认开放（TCP 连接成功 / UDP 收到响应）
    Open,
    /// 无响应（UDP 超时，可能是开放或被防火墙过滤）
    Filtered,
    /// 确认关闭（TCP 拒绝 / UDP 收到 ICMP 不可达）
    Closed,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
    /// 协议："tcp" 或 "udp"
    pub proto: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<&'static str>,
    /// true = UDP 无响应，状态为 open|filtered
    #[serde(default, skip_serializing_if = "is_false")]
    pub filtered: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

pub struct ScanConfig {
    /// 最大并发连接数
    pub concurrency: usize,
    /// 单个连接超时（毫秒）
    pub timeout_ms: u64,
}

/// 扫描进度（通过 watch channel 提供给 GUI 等调用方，只保留最新值）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub done: usize,
    pub total: usize,
}

/// 扫描任务被外部 abort（future 被 drop）时置位取消标志，
/// 让 CLI 的 stderr 进度任务及时退出，避免永久残留
struct CancelGuard(Arc<AtomicBool>);

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// 对全部 (ip, port) 组合执行端口扫描（TCP connect 或 UDP 探测）。
/// 任务分批 spawn（每批至多 `batch_size` 个），内存占用与并发数成正比而非与总探测点数成正比；
/// 信号量限制同时进行的探测数。空输入直接返回空结果。
///
/// UDP 探测：发送探测包后等待响应或 ICMP 不可达——有响应判 open，
/// 收到 ICMP 不可达判 closed，超时无响应判 open|filtered（OpenPort.filtered = true）。
///
/// `quiet` 为 true 时不向 stderr 输出进度；
/// `progress` 提供时，进度通过 watch channel 实时更新；
/// `open_tx` 提供时，每个新发现的开放端口都会立即通过 mpsc channel 推送
/// （CLI 两者均传 None 保持原行为）。
pub async fn scan(
    ips: &[IpAddr],
    ports: &[u16],
    cfg: &ScanConfig,
    quiet: bool,
    progress: Option<watch::Sender<Progress>>,
    open_tx: Option<mpsc::UnboundedSender<OpenPort>>,
    proto: Proto,
) -> Result<Vec<OpenPort>> {
    if ips.is_empty() || ports.is_empty() {
        return Ok(Vec::new());
    }
    let total = ips.len().saturating_mul(ports.len());
    let done = Arc::new(AtomicUsize::new(0));
    let canceled = Arc::new(AtomicBool::new(false));
    // abort 时由 Drop guard 置位取消标志
    let _cancel_guard = CancelGuard(Arc::clone(&canceled));
    let open: Arc<Mutex<Vec<OpenPort>>> = Arc::new(Mutex::new(Vec::new()));
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));

    // CLI 的 stderr 进度显示任务（仅在未提供进度 channel 且非 quiet 时启用）；
    // 由它自己负责收尾换行，扫描结束（成功或异常取消）时先等它退出，避免进度残留到后续输出
    let mut progress_task = if !quiet && progress.is_none() && total > 0 {
        let done = Arc::clone(&done);
        let canceled = Arc::clone(&canceled);
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if canceled.load(Ordering::Relaxed) {
                    eprintln!();
                    break;
                }
                let d = done.load(Ordering::Relaxed);
                eprint!("\r进度: {d}/{total} ({:.1}%)  ", d as f64 * 100.0 / total as f64);
                if d >= total {
                    eprintln!();
                    break;
                }
            }
        }))
    } else {
        None
    };

    let timeout_ms = cfg.timeout_ms;
    // 每批任务数上限：与并发数成正比但封顶，避免一次性生成全部任务导致内存耗尽
    // （如 /16 网段 × 全端口 ≈ 43 亿个组合）。用显式索引遍历笛卡尔积。
    let batch_size = cfg.concurrency.max(1).saturating_mul(2).min(65_536);
    let mut i = 0usize; // 当前主机索引
    let mut j = 0usize; // 当前端口索引
    loop {
        let mut set = JoinSet::new();
        let mut spawned = 0usize;
        while spawned < batch_size && i < ips.len() {
            let ip = ips[i];
            let port = ports[j];
            j += 1;
            if j >= ports.len() {
                j = 0;
                i += 1;
            }
            let sem = Arc::clone(&sem);
            let done = Arc::clone(&done);
            let open = Arc::clone(&open);
            let progress_tx = progress.clone();
            let open_tx = open_tx.clone();
            set.spawn(async move {
                // 信号量限流：控制同时进行的探测数
                let _permit = sem.acquire().await.expect("信号量未关闭");
                let probes: Vec<(&'static str, ProbeState)> = match proto {
                    Proto::Tcp => vec![("tcp", tcp_probe(ip, port, timeout_ms).await)],
                    Proto::Udp => vec![("udp", udp_probe(ip, port, timeout_ms).await)],
                    Proto::Both => vec![
                        ("tcp", tcp_probe(ip, port, timeout_ms).await),
                        ("udp", udp_probe(ip, port, timeout_ms).await),
                    ],
                };
                for &(proto_name, state) in &probes {
                    if state != ProbeState::Closed {
                        let found = OpenPort {
                            ip,
                            port,
                            proto: proto_name,
                            // UDP 端口用 UDP 专属服务表，其余用通用表
                            service: if proto_name == "udp" {
                                crate::ports::service_name_udp(port)
                            } else {
                                service_name(port)
                            },
                            filtered: state == ProbeState::Filtered,
                        };
                        open.lock().unwrap().push(found.clone());
                        // 实时推送：GUI 等调用方收到后立即显示，无需等待扫描结束
                        if let Some(tx) = &open_tx {
                            let _ = tx.send(found);
                        }
                    }
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(tx) = &progress_tx {
                    let _ = tx.send_replace(Progress { done: d, total });
                }
            });
            spawned += 1;
        }
        if spawned == 0 {
            break;
        }
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                canceled.store(true, Ordering::Relaxed);
                if let Some(h) = progress_task.take() {
                    let _ = h.await;
                }
                return Err(e.into());
            }
        }
    }
    if let Some(h) = progress_task.take() {
        let _ = h.await;
    }

    let open = match Arc::try_unwrap(open) {
        Ok(m) => m.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };
    Ok(open)
}

/// TCP 探测：connect 成功即开放，否则关闭
async fn tcp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> ProbeState {
    let addr = SocketAddr::new(ip, port);
    let connected = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await;
    if connected.is_ok_and(|r| r.is_ok()) {
        ProbeState::Open
    } else {
        ProbeState::Closed
    }
}

/// UDP 探测：发送探测包后等待响应或 ICMP 不可达。
/// - 收到响应 => Open
/// - Windows 上 ICMP Port Unreachable 表现为 ConnectionReset/ConnectionRefused 错误 => Closed
/// - 超时无响应 => Filtered（可能开放，也可能被防火墙丢弃）
async fn udp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> ProbeState {
    let Ok(socket) = UdpSocket::bind((ip, 0)).await else {
        return ProbeState::Filtered;
    };
    if socket.connect((ip, port)).await.is_err() {
        return ProbeState::Filtered;
    }
    // 发送 1 字节探测包；多数 UDP 服务收到空/短包后会响应或回 ICMP 不可达
    if socket.send(&[0u8]).await.is_err() {
        return ProbeState::Filtered;
    }
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(_)) => ProbeState::Open,
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused) => ProbeState::Closed,
        // 其他错误或超时：无法确认，按 open|filtered 处理
        _ => ProbeState::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 起一个监听端口并找一个未被占用的端口，返回 (open, closed)
    async fn probe_ports() -> (u16, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        // closed 端口从低端口段选取（避开动态端口 49152+）：其他测试用 bind(":0")
        // 分配的端口都落在动态段，不会与这里释放的 closed 端口撞号
        let mut closed_port = 2000u16;
        loop {
            if TcpListener::bind(("127.0.0.1", closed_port)).await.is_ok() {
                break;
            }
            closed_port += 1;
            if closed_port >= 40_000 {
                panic!("在 2000-39999 段找不到可用端口");
            }
        }
        (open_port, closed_port)
    }

    #[tokio::test]
    async fn detects_open_and_closed_ports() {
        let (open_port, closed_port) = probe_ports().await;
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port, closed_port];
        let cfg = ScanConfig {
            concurrency: 16,
            timeout_ms: 1000,
        };
        let res = scan(&ips, &ports, &cfg, true, None, None, Proto::Tcp).await.unwrap();
        assert!(res.iter().any(|o| o.port == open_port), "应检出监听中的端口");
        assert!(
            !res.iter().any(|o| o.port == closed_port),
            "不应检出未监听的端口"
        );
    }

    #[tokio::test]
    async fn serial_concurrency_works() {
        // concurrency=1 时串行执行，全部端口仍应被扫描到
        let (open_port, closed_port) = probe_ports().await;
        // open2 必须与 closed_port 不同，否则同一端口会被探测两次导致计数重复
        let listener2 = loop {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            if l.local_addr().unwrap().port() != closed_port {
                break l;
            }
        };
        let open2 = listener2.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener2.accept().await.is_err() {
                    break;
                }
            }
        });
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port, open2, closed_port];
        let cfg = ScanConfig {
            concurrency: 1,
            timeout_ms: 1000,
        };
        let res = scan(&ips, &ports, &cfg, true, None, None, Proto::Tcp).await.unwrap();
        assert_eq!(res.len(), 2, "应恰好检出两个监听端口");
        assert!(res.iter().any(|o| o.port == open_port));
        assert!(res.iter().any(|o| o.port == open2));
    }

    #[tokio::test]
    async fn progress_output_does_not_break_results() {
        // 进度显示路径（quiet=false）：应正常完成并输出结果
        let (open_port, _closed_port) = probe_ports().await;
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port];
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 1000,
        };
        let res = scan(&ips, &ports, &cfg, false, None, None, Proto::Tcp).await.unwrap();
        assert_eq!(res.len(), 1);
    }

    #[tokio::test]
    async fn empty_inputs_return_empty() {
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 200,
        };
        assert!(scan(&[], &[1, 2], &cfg, true, None, None, Proto::Tcp)
            .await
            .unwrap()
            .is_empty());
        assert!(scan(
            &[IpAddr::from([127, 0, 0, 1])],
            &[],
            &cfg,
            true,
            None,
            None,
            Proto::Tcp
        )
        .await
        .unwrap()
        .is_empty());
    }

    #[tokio::test]
    async fn progress_channel_receives_updates() {
        let (open_port, closed_port) = probe_ports().await;
        let (tx, mut rx) = watch::channel(Progress { done: 0, total: 0 });
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port, closed_port];
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 500,
        };
        let res = scan(&ips, &ports, &cfg, true, Some(tx), None, Proto::Tcp).await.unwrap();
        assert_eq!(res.len(), 1, "应检出监听中的端口");
        // 扫描完成后 watch 最新值应为 done == total
        assert_eq!(
            *rx.borrow_and_update(),
            Progress {
                done: ports.len(),
                total: ports.len()
            }
        );
    }

    #[tokio::test]
    async fn timeout_honored() {
        // 并发/超时配置应能正常驱动一次扫描（无开放端口也不应报错）
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![1, 2, 3];
        let cfg = ScanConfig {
            concurrency: 2,
            timeout_ms: 200,
        };
        let res = scan(&ips, &ports, &cfg, true, None, None, Proto::Tcp).await.unwrap();
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn open_ports_pushed_in_realtime() {
        // 通过 open_tx 推送：扫描过程中（未结束时）即可收到开放端口，而非等全部完成
        let (open_port, _closed_port) = probe_ports().await;
        let (open_tx, mut open_rx) = mpsc::unbounded_channel::<OpenPort>();
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port];
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 500,
        };
        let scan_task = tokio::spawn(async move {
            let ips = ips;
            let ports = ports;
            let cfg = cfg;
            scan(&ips, &ports, &cfg, true, None, Some(open_tx), Proto::Tcp).await
        });
        // 扫描任务未结束时，channel 就应已收到开放端口（说明是实时推送）
        let received = open_rx
            .recv()
            .await
            .expect("扫描结束前应实时收到开放端口");
        assert_eq!(received.port, open_port);
        let res = scan_task.await.unwrap().unwrap();
        assert_eq!(res.len(), 1);
    }

    #[tokio::test]
    async fn udp_detects_open_and_closed() {
        // 本机起一个 UDP echo 服务：收到包即回包 => 应检出 open
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let open_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                    break;
                };
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });
        // 找一个已释放的 UDP 端口（bind 后 drop）=> 应判 closed（Windows 回环会回 ICMP 不可达）
        let closed_port = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let p = s.local_addr().unwrap().port();
            drop(s);
            p
        };
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![open_port, closed_port];
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 500,
        };
        let res = scan(&ips, &ports, &cfg, true, None, None, Proto::Udp)
            .await
            .unwrap();
        // 开放端口必须被检出且不是 filtered
        assert!(
            res.iter().any(|o| o.port == open_port && !o.filtered),
            "应检出 UDP 开放端口"
        );
        // 关闭端口不应被误报为开放
        assert!(
            !res.iter().any(|o| o.port == closed_port && !o.filtered),
            "关闭的 UDP 端口不应被误报为开放"
        );
    }

    #[tokio::test]
    async fn both_proto_scans_tcp_and_udp() {
        // TCP 监听服务
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if tcp_listener.accept().await.is_err() {
                    break;
                }
            }
        });
        // UDP echo 服务
        let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await else {
                    break;
                };
                let _ = udp_echo.send_to(&buf[..n], peer).await;
            }
        });
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        let ports = vec![tcp_port, udp_port];
        let cfg = ScanConfig {
            concurrency: 4,
            timeout_ms: 500,
        };
        let res = scan(&ips, &ports, &cfg, true, None, None, Proto::Both)
            .await
            .unwrap();
        assert!(
            res.iter().any(|o| o.port == tcp_port && o.proto == "tcp"),
            "TCP 端口应以 tcp 协议检出"
        );
        assert!(
            res.iter().any(|o| o.port == udp_port && o.proto == "udp"),
            "UDP 端口应以 udp 协议检出"
        );
    }
}
