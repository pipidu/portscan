use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "portscan",
    version,
    about = "内网 TCP 端口扫描工具（默认扫描全部端口 1-65535）"
)]
pub struct Cli {
    /// 扫描目标：IP 地址、主机名或 CIDR 网段（如 192.168.1.0/24）。
    /// 多个目标用逗号分隔，或重复指定本参数。
    #[arg(required = true, value_name = "TARGET")]
    pub targets: Vec<String>,

    /// 端口范围，如 "80,443,8000-9000"；默认 1-65535 全部端口
    #[arg(short, long, default_value = "1-65535", value_name = "PORTS")]
    pub ports: String,

    /// 最大并发连接数（1-65535）
    #[arg(
        short,
        long,
        default_value_t = 1024,
        value_name = "N",
        value_parser = clap::builder::RangedI64ValueParser::<usize>::new().range(1..=65_535)
    )]
    pub concurrency: usize,

    /// 单个连接超时（毫秒）
    #[arg(short, long, default_value_t = 1000, value_name = "MS")]
    pub timeout: u64,

    /// 导出结果为 CSV 文件
    #[arg(long, value_name = "FILE")]
    pub csv: Option<PathBuf>,

    /// 导出结果为 JSON 文件
    #[arg(long, value_name = "FILE")]
    pub json: Option<PathBuf>,

    /// 不显示进度与统计信息
    #[arg(short, long)]
    pub quiet: bool,
}
