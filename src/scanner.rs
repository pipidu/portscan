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

/// 探测结果：状态 + 延迟列表（毫秒；仅 open 状态测量，空表示未测量）
type ProbeResult = (ProbeState, Vec<u64>);

/// 单个探测点的结果状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    /// 确认开放（TCP 连接成功 / UDP 收到响应）
    Open,
    /// 无响应（UDP 超时，可能是开放或被防火墙过滤）
    Filtered,
    /// 确认关闭（TCP 拒绝 / UDP 收到 ICMP 不可达）
    Closed,
    /// TCP 连接成功但连接建立后立即收到 RST/FIN（tcpwrapped 特征，疑似网关劫持）
    Suspicious,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
    /// 协议："tcp" 或 "udp"
    pub proto: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<&'static str>,
    /// 探测延迟（毫秒，仅 open 状态测量 3 次）：TCP 为连接握手耗时，UDP 为发送到收到响应耗时
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub latency_ms: Vec<u64>,
    /// true = UDP 无响应，状态为 open|filtered
    #[serde(default, skip_serializing_if = "is_false")]
    pub filtered: bool,
    /// true = TCP 连接后立即被对端关闭（疑似劫持/tcpwrapped）
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspicious: bool,
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
                let probes: Vec<(&'static str, ProbeResult)> = match proto {
                    Proto::Tcp => vec![("tcp", tcp_probe(ip, port, timeout_ms).await)],
                    Proto::Udp => vec![("udp", udp_probe(ip, port, timeout_ms).await)],
                    Proto::Both => vec![
                        ("tcp", tcp_probe(ip, port, timeout_ms).await),
                        ("udp", udp_probe(ip, port, timeout_ms).await),
                    ],
                };
                for (proto_name, (state, latency)) in &probes {
                    if *state != ProbeState::Closed {
                        let found = OpenPort {
                            ip,
                            port,
                            proto: proto_name,
                            // UDP 端口用 UDP 专属服务表，其余用通用表
                            service: if *proto_name == "udp" {
                                crate::ports::service_name_udp(port)
                            } else {
                                service_name(port)
                            },
                            latency_ms: latency.clone(),
                            filtered: *state == ProbeState::Filtered,
                            suspicious: *state == ProbeState::Suspicious,
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

/// 邮件端口（25/110/143）的协议探测 payload：用于识别「连接成功但静默」的劫持/tcpwrapped。
/// 真实邮件服务器必然响应这些协议命令，劫持方（代答 SYN-ACK 后不转发）不会响应。
fn tcp_probe_payload(port: u16) -> Option<&'static [u8]> {
    Some(match port {
        25 => b"EHLO probe\r\n",    // SMTP
        110 => b"CAPA\r\n",         // POP3
        143 => b"CAPABILITY\r\n",   // IMAP
        _ => return None,
    })
}

/// TCP 探测：connect 成功即开放，否则关闭。
/// 连接成功后：
/// - 对 25/110/143 发送协议探测并等待响应——收到数据 => Open；
///   立即 RST/FIN 或超时无响应 => Suspicious（劫持/tcpwrapped 特征）
/// - 其他端口：收到数据（banner）=> Open；立即 RST/FIN => Suspicious；
///   超时无响应 => Open（真实服务可能静默等待客户端先发言，不能误伤）
///
/// 单次 TCP 探测，返回状态与连接握手耗时（连接失败为 None）
async fn tcp_probe_once(ip: IpAddr, port: u16, timeout_ms: u64) -> (ProbeState, Option<u64>) {
    let addr = SocketAddr::new(ip, port);
    let t0 = std::time::Instant::now();
    // timeout 外层返回 Result<Result<TcpStream>, Elapsed>，需双层解包
    let Ok(connect_result) = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await
    else {
        return (ProbeState::Closed, None);
    };
    let Ok(stream) = connect_result else {
        return (ProbeState::Closed, None);
    };
    // 连接握手耗时即 RTT 近似
    let latency = t0.elapsed().as_millis() as u64;
    let dur = Duration::from_millis(timeout_ms);
    let payload = tcp_probe_payload(port);
    // 发送协议探测（仅 25/110/143）
    if let Some(p) = payload {
        if timeout(dur, stream.writable()).await.is_ok() {
            let _ = stream.try_write(p);
        }
    }
    let mut buf = [0u8; 256];
    let state = match timeout(dur, stream.readable()).await {
        Ok(Ok(())) => match stream.try_read(&mut buf) {
            Ok(0) => ProbeState::Suspicious, // EOF：对端建立连接后立即关闭
            Ok(_) => ProbeState::Open,       // 收到 banner 或对探测的响应
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                ProbeState::Suspicious // 连接后立即 RST：疑似劫持
            }
            // 其他错误（含 WouldBlock 竞态）：无法证明劫持，保守判 Open
            Err(_) => ProbeState::Open,
        },
        // 超时无响应：发过 probe 仍无响应 => 疑似劫持；未发 probe => 保持 Open
        _ => {
            if payload.is_some() {
                ProbeState::Suspicious
            } else {
                ProbeState::Open
            }
        }
    };
    (state, Some(latency))
}

/// 仅测量连接握手耗时（不判定状态），用于 open 端口的重复延迟采样
async fn tcp_connect_latency(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<u64> {
    let addr = SocketAddr::new(ip, port);
    let t0 = std::time::Instant::now();
    let Ok(Ok(_)) = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await
    else {
        return None;
    };
    Some(t0.elapsed().as_millis() as u64)
}

/// TCP 探测：connect 成功即开放，否则关闭；open 状态补测延迟共 3 次。
async fn tcp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> ProbeResult {
    let (state, first_lat) = tcp_probe_once(ip, port, timeout_ms).await;
    // 仅 open 状态检测延迟（suspicious/filtered/closed 不测）
    if state != ProbeState::Open {
        return (state, Vec::new());
    }
    let mut lats = Vec::with_capacity(3);
    if let Some(l) = first_lat {
        lats.push(l);
    }
    for _ in 0..2 {
        if let Some(l) = tcp_connect_latency(ip, port, timeout_ms).await {
            lats.push(l);
        }
    }
    (state, lats)
}

/// UDP 探测：发送探测包后等待响应或 ICMP 不可达；open 状态补测延迟共 3 次。
/// - 收到响应 => Open（延迟 = 发送到响应耗时）
/// - Windows 上 ICMP Port Unreachable 表现为 ConnectionReset/ConnectionRefused 错误 => Closed
/// - 超时无响应 => Filtered（可能开放，也可能被防火墙丢弃）
async fn udp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> ProbeResult {
    let (state, first_lat) = udp_probe_once(ip, port, timeout_ms).await;
    // 仅 open 状态检测延迟
    if state != ProbeState::Open {
        return (state, Vec::new());
    }
    let mut lats = Vec::with_capacity(3);
    if let Some(l) = first_lat {
        lats.push(l);
    }
    for _ in 0..2 {
        if let Some(l) = udp_roundtrip_latency(ip, port, timeout_ms).await {
            lats.push(l);
        }
    }
    (state, lats)
}

/// 单次 UDP 探测：返回状态与响应耗时（无响应为 None）
async fn udp_probe_once(ip: IpAddr, port: u16, timeout_ms: u64) -> (ProbeState, Option<u64>) {
    let Ok(socket) = UdpSocket::bind((ip, 0)).await else {
        return (ProbeState::Filtered, None);
    };
    if socket.connect((ip, port)).await.is_err() {
        return (ProbeState::Filtered, None);
    }
    // 发送 1 字节探测包；多数 UDP 服务收到空/短包后会响应或回 ICMP 不可达
    if socket.send(&[0u8]).await.is_err() {
        return (ProbeState::Filtered, None);
    }
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(_)) => (ProbeState::Open, Some(t0.elapsed().as_millis() as u64)),
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused) => (ProbeState::Closed, None),
        // 其他错误或超时：无法确认，按 open|filtered 处理
        _ => (ProbeState::Filtered, None),
    }
}

/// 仅测量 UDP 发送到响应耗时，用于 open 端口的重复延迟采样
async fn udp_roundtrip_latency(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<u64> {
    let Ok(socket) = UdpSocket::bind((ip, 0)).await else {
        return None;
    };
    if socket.connect((ip, port)).await.is_err() {
        return None;
    }
    if socket.send(&[0u8]).await.is_err() {
        return None;
    }
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(_)) => Some(t0.elapsed().as_millis() as u64),
        _ => None,
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
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                // 保持连接打开（等待可读并消费数据），模拟真实监听服务
                let _ = sock.readable().await;
                let mut buf = [0u8; 64];
                let _ = sock.try_read(&mut buf);
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
        // open 端口应测得 3 次延迟
        let open = res.iter().find(|o| o.port == open_port).unwrap();
        assert_eq!(open.latency_ms.len(), 3, "open 端口应测得 3 次延迟");
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
    async fn tcp_probe_detects_immediate_close() {
        // listener accept 后立即关闭连接：客户端应判定为 Suspicious（EOF/RST 特征）
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                drop(sock); // 连接建立后立即关闭
            }
        });
        let (state, latency) = tcp_probe(IpAddr::from([127, 0, 0, 1]), port, 500).await;
        assert_eq!(state, ProbeState::Suspicious);
        // 非 open 状态不测延迟
        assert!(latency.is_empty(), "可疑状态不应测量延迟");
    }

    #[test]
    fn mail_ports_have_probe_payloads() {
        // 邮件端口应有协议探测 payload；其他端口不应有（避免误伤 TLS/SSH 等）
        assert!(tcp_probe_payload(25).is_some());
        assert!(tcp_probe_payload(110).is_some());
        assert!(tcp_probe_payload(143).is_some());
        assert!(tcp_probe_payload(22).is_none());
        assert!(tcp_probe_payload(443).is_none());
        assert!(tcp_probe_payload(3389).is_none());
    }

    #[tokio::test]
    async fn smtp_silent_service_marked_suspicious() {
        // 25 端口 accept 后读取数据但不响应（模拟网关劫持/静默 tcpwrapped）
        let Ok(listener) = TcpListener::bind("127.0.0.1:25").await else {
            eprintln!("跳过：本机 25 端口不可用");
            return;
        };
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                // 等待读取探测数据但静默不响应
                let _ = sock.readable().await;
                let mut buf = [0u8; 64];
                let _ = sock.try_read(&mut buf);
            }
        });
        // 客户端仍持有连接（服务端未关闭）=> readable 超时 => 发过 probe => Suspicious
        let (state, _latency) = tcp_probe(IpAddr::from([127, 0, 0, 1]), 25, 400).await;
        assert_eq!(state, ProbeState::Suspicious);
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
