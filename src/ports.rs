use anyhow::{bail, Context};

/// 解析端口规格字符串，如 "1-65535"、"80,443,8000-9000"。
/// 返回去重、升序排列的端口列表。
pub fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .with_context(|| format!("无效端口: {part}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .with_context(|| format!("无效端口: {part}"))?;
            if lo == 0 || hi == 0 {
                bail!("端口必须为 1-65535: {part}");
            }
            if lo > hi {
                bail!("端口范围起始大于结束: {part}");
            }
            ports.extend(lo..=hi);
        } else {
            let p: u16 = part
                .parse()
                .with_context(|| format!("无效端口: {part}"))?;
            if p == 0 {
                bail!("端口必须为 1-65535: {part}");
            }
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// 常见端口 -> 服务名（仅用于展示提示，非精确指纹）
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "smtp-submission",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 => "docker",
        2376 => "docker-tls",
        3000 => "http-alt",
        3128 => "squid",
        3306 => "mysql",
        3389 => "rdp",
        4369 => "erlang-port-mapper",
        5000 => "upnp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        5985 => "winrm",
        5986 => "winrm-https",
        6379 => "redis",
        7001 => "weblogic",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "ajp",
        8080 => "http-proxy",
        8081 => "http-alt",
        8088 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "php-fpm",
        9092 => "kafka",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        9418 => "git",
        9999 => "http-alt",
        10000 => "webmin",
        11211 => "memcached",
        27017 => "mongodb",
        27018 => "mongodb",
        50000 => "sap",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_range() {
        let ports = parse_ports("1-65535").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(*ports.last().unwrap(), 65535);
    }

    #[test]
    fn parses_single_and_mixed() {
        let ports = parse_ports("80,443,8000-8002,22").unwrap();
        assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn dedups_and_sorts() {
        let ports = parse_ports("8080,80,80,1-3").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 80, 8080]);
    }

    #[test]
    fn rejects_invalid() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("").unwrap().is_empty());
    }

    #[test]
    fn known_services() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(3389), Some("rdp"));
        assert_eq!(service_name(12345), None);
    }
}
