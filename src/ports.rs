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
        // ---- 基础网络服务 ----
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        37 => "time",
        42 => "nameserver",
        49 => "tacacs",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        70 => "gopher",
        79 => "finger",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        194 => "irc",
        389 => "ldap",
        411 => "directconnect",
        427 => "afp-over-tcp",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd",
        465 => "smtps",
        500 => "isakmp",
        512 => "exec",
        513 => "login",
        514 => "syslog",
        515 => "printer",
        517 => "talk",
        518 => "ntalk",
        540 => "uucp",
        543 => "klogin",
        544 => "kshell",
        546 => "dhcpv6-client",
        547 => "dhcpv6-server",
        548 => "afp",
        554 => "rtsp",
        563 => "nntps",
        587 => "smtp-submission",
        631 => "ipp",
        635 => "mountd",
        636 => "ldaps",
        749 => "kerberos-adm",
        873 => "rsync",
        953 => "rndc",
        989 => "ftps-data",
        990 => "ftps",
        992 => "telnets",
        993 => "imaps",
        994 => "ircs",
        995 => "pop3s",
        // ---- 常用软件/中间件 ----
        1080 => "socks",
        1099 => "java-rmi",
        1194 => "openvpn",
        1352 => "lotusnotes",
        1433 => "mssql",
        1434 => "mssql-browser",
        1494 => "citrix-ica",
        1512 => "wins",
        1521 => "oracle",
        1701 => "l2tp",
        1718 => "h323-discover",
        1719 => "h323-gatekeeper",
        1720 => "h323",
        1723 => "pptp",
        1801 => "msmq",
        1812 => "radius",
        1813 => "radius-acct",
        1863 => "msnp",
        1883 => "mqtt",
        1900 => "ssdp",
        1935 => "rtmp",
        2049 => "nfs",
        2082 => "cpanel",
        2083 => "cpanel-ssl",
        2086 => "whm",
        2087 => "whm-ssl",
        2095 => "webmail",
        2096 => "webmail-ssl",
        2181 => "zookeeper",
        2222 => "ssh-alt",
        2323 => "telnet-alt",
        2375 => "docker",
        2376 => "docker-tls",
        2379 => "etcd",
        2380 => "etcd-peer",
        2401 => "cvspserver",
        2525 => "smtp-alt",
        2628 => "dict",
        2869 => "upnp-discovery",
        3000 => "http-alt",
        3050 => "firebird",
        3074 => "xbox",
        3128 => "squid",
        3130 => "icp",
        3260 => "iscsi",
        3268 => "global-catalog-ldap",
        3269 => "global-catalog-ldaps",
        3306 => "mysql",
        3307 => "mysql-alt",
        3389 => "rdp",
        3478 => "stun",
        3632 => "distcc",
        3689 => "daap",
        3690 => "svn",
        4369 => "erlang-port-mapper",
        4380 => "steam-p2p",
        4500 => "ipsec-nat",
        4848 => "glassfish",
        4899 => "radmin",
        4949 => "munin",
        5000 => "upnp",
        5038 => "asterisk",
        5060 => "sip",
        5061 => "sips",
        5190 => "icq",
        5222 => "xmpp-client",
        5269 => "xmpp-server",
        5353 => "mdns",
        5355 => "llmnr",
        5432 => "postgresql",
        5555 => "adb",
        5631 => "pcanywhere",
        5632 => "pcanywhere-data",
        5666 => "nagios",
        5667 => "nagios-trap",
        5671 => "amqps",
        5672 => "amqp",
        5683 => "coap",
        5800 => "vnc-http",
        5900 => "vnc",
        5901 => "vnc-1",
        5984 => "couchdb",
        5985 => "winrm",
        5986 => "winrm-https",
        6000 => "x11",
        61613 => "stomp",
        61616 => "activemq",
        6346 => "gnutella",
        6347 => "gnutella-alt",
        6379 => "redis",
        6443 => "kubernetes",
        6566 => "sane",
        6666 => "irc",
        6667 => "irc",
        6668 => "irc",
        6669 => "irc",
        6679 => "irc-ssl",
        6697 => "ircs",
        6881 => "bittorrent",
        7000 => "cassandra",
        7001 => "weblogic",
        7002 => "weblogic-ssl",
        7199 => "cassandra-jmx",
        7474 => "neo4j",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "ajp",
        8069 => "odoo",
        8080 => "http-proxy",
        8081 => "http-alt",
        8083 => "influxdb-admin",
        8086 => "influxdb",
        8088 => "http-alt",
        8091 => "couchbase",
        8096 => "emby",
        8112 => "deluge-web",
        8118 => "privoxy",
        8123 => "home-assistant",
        8161 => "activemq-web",
        8200 => "vault",
        8291 => "mikrotik-winbox",
        8332 => "bitcoin-rpc",
        8333 => "bitcoin",
        8384 => "syncthing",
        8443 => "https-alt",
        8448 => "matrix",
        8500 => "consul",
        8545 => "ethereum-rpc",
        8554 => "rtsp-alt",
        8766 => "steam",
        8767 => "steam",
        8883 => "mqtts",
        8888 => "http-alt",
        8920 => "jellyfin-https",
        8983 => "solr",
        9000 => "php-fpm",
        9001 => "supervisord",
        9042 => "cassandra-cql",
        9050 => "tor-socks",
        9060 => "websphere-admin",
        9080 => "websphere",
        9090 => "prometheus",
        9092 => "kafka",
        9093 => "alertmanager",
        9100 => "node-exporter",
        9119 => "mrtg",
        9160 => "cassandra-thrift",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        9306 => "mysql-proxy",
        9312 => "sphinx",
        9323 => "docker-metrics",
        9339 => "supercell",
        9389 => "adws",
        9418 => "git",
        9990 => "wildfly",
        9993 => "zerotier",
        9999 => "http-alt",
        10000 => "webmin",
        10050 => "zabbix-agent",
        10051 => "zabbix-server",
        10250 => "kubelet",
        10255 => "kubelet-readonly",
        11211 => "memcached",
        11311 => "ros",
        15672 => "rabbitmq",
        17500 => "dropbox-lan",
        17501 => "dropbox-sync",
        // ---- 游戏服务器 ----
        2302 => "arma",
        2456 => "valheim",
        2457 => "valheim",
        3724 => "wow",
        7777 => "terraria",
        7778 => "terraria",
        8211 => "palworld",
        10999 => "don't-starve",
        16261 => "project-zomboid",
        19132 => "minecraft-bedrock",
        19133 => "minecraft-bedrock",
        25565 => "minecraft",
        25575 => "minecraft-rcon",
        26900 => "7-days-to-die",
        27000 => "valve",
        27015 => "valve",
        27016 => "valve",
        27017 => "mongodb",
        27018 => "mongodb",
        27036 => "steam",
        27900 => "quake",
        27910 => "quake2",
        27960 => "quake-arena",
        28015 => "rust",
        28960 => "cod",
        31337 => "elite",
        34197 => "factorio",
        50000 => "sap",
        50030 => "hdfs-namenode",
        50070 => "hdfs-namenode-web",
        50075 => "hdfs-datanode",
        50090 => "hdfs-secondary",
        51413 => "transmission",
        60010 => "hbase-master",
        60020 => "hbase-region",
        _ => return None,
    })
}

/// UDP 端口服务名：UDP 专属/常用服务优先，未命中回退通用表（[`service_name`]）
pub fn service_name_udp(port: u16) -> Option<&'static str> {
    let udp_only = match port {
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        37 => "time",
        42 => "nameserver",
        49 => "tacacs",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        123 => "ntp",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        161 => "snmp",
        162 => "snmptrap",
        500 => "isakmp",
        514 => "syslog",
        520 => "rip",
        1194 => "openvpn",
        1701 => "l2tp",
        1812 => "radius",
        1813 => "radius-acct",
        1900 => "ssdp",
        2427 => "mgcp",
        2869 => "upnp-discovery",
        3074 => "xbox",
        3478 => "stun",
        3702 => "ws-discovery",
        4500 => "ipsec-nat",
        5060 => "sip",
        5061 => "sips",
        5353 => "mdns",
        5355 => "llmnr",
        5683 => "coap",
        6881 => "bittorrent",
        // ---- 游戏服务器（UDP）----
        2302 => "arma",
        2456 => "valheim",
        2457 => "valheim",
        7777 => "terraria",
        7778 => "terraria",
        8211 => "palworld",
        8766 => "steam",
        8767 => "steam",
        10999 => "don't-starve",
        16261 => "project-zomboid",
        19132 => "minecraft-bedrock",
        19133 => "minecraft-bedrock",
        27015 => "valve",
        27016 => "valve",
        27036 => "steam",
        27900 => "quake",
        27910 => "quake2",
        27960 => "quake-arena",
        34197 => "factorio",
        _ => return service_name(port), // 回退通用映射
    };
    Some(udp_only)
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

    #[test]
    fn software_and_game_services() {
        // 常用软件：数据库/中间件/容器/监控/工具
        assert_eq!(service_name(5555), Some("adb"));
        assert_eq!(service_name(6443), Some("kubernetes"));
        assert_eq!(service_name(9042), Some("cassandra-cql"));
        assert_eq!(service_name(15672), Some("rabbitmq"));
        assert_eq!(service_name(9090), Some("prometheus"));
        assert_eq!(service_name(2379), Some("etcd"));
        assert_eq!(service_name(8500), Some("consul"));
        assert_eq!(service_name(1883), Some("mqtt"));
        assert_eq!(service_name(25575), Some("minecraft-rcon"));
        // 游戏服务器
        assert_eq!(service_name(25565), Some("minecraft"));
        assert_eq!(service_name(19132), Some("minecraft-bedrock"));
        assert_eq!(service_name(27015), Some("valve"));
        assert_eq!(service_name(7777), Some("terraria"));
        assert_eq!(service_name(2456), Some("valheim"));
        assert_eq!(service_name(28015), Some("rust"));
        assert_eq!(service_name(34197), Some("factorio"));
        assert_eq!(service_name(2302), Some("arma"));
        assert_eq!(service_name(3724), Some("wow"));
        assert_eq!(service_name(8211), Some("palworld"));
        assert_eq!(service_name(26900), Some("7-days-to-die"));
        assert_eq!(service_name(16261), Some("project-zomboid"));
        assert_eq!(service_name(10999), Some("don't-starve"));
    }

    #[test]
    fn extended_services() {
        // 基础网络服务
        assert_eq!(service_name(7), Some("echo"));
        assert_eq!(service_name(79), Some("finger"));
        assert_eq!(service_name(119), Some("nntp"));
        assert_eq!(service_name(179), Some("bgp"));
        assert_eq!(service_name(631), Some("ipp"));
        assert_eq!(service_name(990), Some("ftps"));
        // 常用软件
        assert_eq!(service_name(1194), Some("openvpn"));
        assert_eq!(service_name(1701), Some("l2tp"));
        assert_eq!(service_name(3690), Some("svn"));
        assert_eq!(service_name(5060), Some("sip"));
        assert_eq!(service_name(5353), Some("mdns"));
        assert_eq!(service_name(5984), Some("couchdb"));
        assert_eq!(service_name(6667), Some("irc"));
        assert_eq!(service_name(8086), Some("influxdb"));
        assert_eq!(service_name(8123), Some("home-assistant"));
        assert_eq!(service_name(8333), Some("bitcoin"));
        assert_eq!(service_name(9001), Some("supervisord"));
        assert_eq!(service_name(10050), Some("zabbix-agent"));
        assert_eq!(service_name(17500), Some("dropbox-lan"));
        // 游戏服务器补充
        assert_eq!(service_name(27000), Some("valve"));
        assert_eq!(service_name(27036), Some("steam"));
        assert_eq!(service_name(27960), Some("quake-arena"));
        assert_eq!(service_name(31337), Some("elite"));
        // 大数据组件
        assert_eq!(service_name(50070), Some("hdfs-namenode-web"));
        assert_eq!(service_name(60010), Some("hbase-master"));
    }

    #[test]
    fn udp_services() {
        // UDP 专属服务
        assert_eq!(service_name_udp(53), Some("dns"));
        assert_eq!(service_name_udp(67), Some("dhcp"));
        assert_eq!(service_name_udp(123), Some("ntp"));
        assert_eq!(service_name_udp(161), Some("snmp"));
        assert_eq!(service_name_udp(500), Some("isakmp"));
        assert_eq!(service_name_udp(1194), Some("openvpn"));
        assert_eq!(service_name_udp(1701), Some("l2tp"));
        assert_eq!(service_name_udp(3478), Some("stun"));
        assert_eq!(service_name_udp(5353), Some("mdns"));
        assert_eq!(service_name_udp(5355), Some("llmnr"));
        assert_eq!(service_name_udp(5683), Some("coap"));
        // UDP 游戏服务
        assert_eq!(service_name_udp(19132), Some("minecraft-bedrock"));
        assert_eq!(service_name_udp(7777), Some("terraria"));
        assert_eq!(service_name_udp(27015), Some("valve"));
        // 未命中 UDP 表时回退通用映射
        assert_eq!(service_name_udp(22), Some("ssh"));
        assert_eq!(service_name_udp(443), Some("https"));
    }
}
