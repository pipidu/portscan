use anyhow::{bail, Context};
use cidr::IpCidr;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// 单次展开的目标地址数上限，防止误扫超大网段（如 10.0.0.0/8）耗尽内存
pub const MAX_TARGETS: usize = 1_000_000;

/// 展开目标列表：支持 IP 地址、主机名（DNS 解析）、CIDR 网段（如 192.168.1.0/24）。
/// 多个目标用逗号分隔或重复指定。结果去重并按地址排序。
/// 展开后的地址数超过 [`MAX_TARGETS`] 时报错，请缩小网段范围。
pub fn expand_targets(raw: &[String]) -> anyhow::Result<Vec<IpAddr>> {
    let mut set = BTreeSet::new();
    for item in raw {
        for part in item.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.contains('/') {
                // 手动拆分地址与前缀：cidr crate 的 FromStr 不接受 host bits 非零
                // 的地址（如 192.168.1.1/24），这里计算网络地址后构造
                let (addr_s, prefix_s) = part
                    .split_once('/')
                    .with_context(|| format!("无效的 CIDR 网段: {part}"))?;
                let addr: IpAddr = addr_s
                    .trim()
                    .parse()
                    .with_context(|| format!("无效的 CIDR 地址: {part}"))?;
                let prefix: u8 = prefix_s
                    .trim()
                    .parse()
                    .with_context(|| format!("无效的 CIDR 前缀: {part}"))?;
                let cidr: IpCidr = match addr {
                    IpAddr::V4(v4) => {
                        if prefix > 32 {
                            bail!("CIDR 前缀长度无效: {part}");
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u32::MAX << (32 - prefix as u32)
                        };
                        let network = Ipv4Addr::from(u32::from(v4) & mask);
                        IpCidr::V4(cidr::Ipv4Cidr::new(network, prefix).expect("网络地址 host part 为 0"))
                    }
                    IpAddr::V6(v6) => {
                        if prefix > 128 {
                            bail!("CIDR 前缀长度无效: {part}");
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix as u32)
                        };
                        let network = Ipv6Addr::from(u128::from(v6) & mask);
                        IpCidr::V6(cidr::Ipv6Cidr::new(network, prefix).expect("网络地址 host part 为 0"))
                    }
                };
                for ip in cidr.iter() {
                    set.insert(ip.address());
                    if set.len() > MAX_TARGETS {
                        bail!(
                            "目标数量超过上限 {MAX_TARGETS}（网段 {part} 过大），请缩小网段范围"
                        );
                    }
                }
            } else if let Ok(ip) = part.parse::<IpAddr>() {
                set.insert(ip);
            } else {
                let addrs = (part, 0u16)
                    .to_socket_addrs()
                    .with_context(|| format!("无法解析主机名: {part}"))?;
                for addr in addrs {
                    set.insert(addr.ip());
                    if set.len() > MAX_TARGETS {
                        bail!("目标数量超过上限 {MAX_TARGETS}，请缩小目标范围");
                    }
                }
            }
        }
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ip() {
        let ips = expand_targets(&["192.168.1.10".into()]).unwrap();
        assert_eq!(ips, vec!["192.168.1.10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn expands_cidr() {
        // /30 网段包含 4 个地址（含网络与广播地址，扫描无妨）
        let ips = expand_targets(&["192.168.1.0/30".into()]).unwrap();
        assert_eq!(ips.len(), 4);
        assert_eq!(ips[0], "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(ips[3], "192.168.1.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn expands_cidr_host_address() {
        // 主机地址 + 前缀（192.168.1.1/24）应忽略 host bits 按网络展开
        let ips = expand_targets(&["192.168.1.1/24".into()]).unwrap();
        assert_eq!(ips.len(), 256);
        assert_eq!(ips[0], "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(ips[255], "192.168.1.255".parse::<IpAddr>().unwrap());
        // IPv6 主机地址 + 前缀
        let ips = expand_targets(&["2001:db8::1/120".into()]).unwrap();
        assert_eq!(ips.len(), 256);
        assert_eq!(ips[0], "2001:db8::".parse::<IpAddr>().unwrap());
        // 前缀超范围应报错
        assert!(expand_targets(&["192.168.1.1/33".into()]).is_err());
        assert!(expand_targets(&["2001:db8::1/129".into()]).is_err());
    }

    #[test]
    fn dedups_and_sorts() {
        let ips = expand_targets(&["10.0.0.2,10.0.0.1,10.0.0.1".into()]).unwrap();
        assert_eq!(
            ips,
            vec![
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(expand_targets(&["192.168.1.0/99".into()]).is_err());
    }

    #[test]
    fn rejects_huge_network() {
        // 10.0.0.0/8 有 1677 万个地址，超过上限应报错而不是耗尽内存
        let err = expand_targets(&["10.0.0.0/8".into()]).unwrap_err();
        assert!(err.to_string().contains("上限"));
    }

    #[test]
    fn resolves_hostname() {
        // localhost 由 hosts 文件保证解析，不依赖外部 DNS
        let ips = expand_targets(&["localhost".into()]).unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }
}
