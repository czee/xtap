use std::net::IpAddr;

use netdev::{Interface, get_interfaces};

use crate::debug_log;
use crate::log::{log_and_none, log_and_some};

fn log_interface_addrs(interface: &Interface) {
    debug_log!(
        "Interface: {:<10} | Addr(v4): {:?}",
        interface.name,
        interface.ipv4_addrs()
    );
    debug_log!(
        "Interface: {:<10} | Addr(v6): {:?}",
        interface.name,
        interface.ipv6_addrs()
    );
}

pub(crate) fn first_interface_ip(interface: &Interface) -> Option<IpAddr> {
    log_interface_addrs(interface);

    interface
        .ipv4_addrs()
        .first()
        .map(|ip| IpAddr::V4(*ip))
        .or_else(|| interface.ipv6_addrs().first().map(|ip| IpAddr::V6(*ip)))
        .or_else(|| {
            log_and_none(&format!(
                "Interface '{}' has no IP addresses",
                interface.name
            ))
        })
}

pub(crate) fn interface_by_ip(ip: IpAddr) -> Option<Interface> {
    for interface in get_interfaces() {
        log_interface_addrs(&interface);

        if interface.ip_addrs().contains(&ip) {
            return log_and_some(
                &format!("Found interface '{}' for address '{}'", interface.name, ip),
                interface,
            );
        }
    }

    log_and_none(&format!("No interface found for address '{ip}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdev::{
        Interface,
        ipnet::{Ipv4Net, Ipv6Net},
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_interface(name: &str, v4_addrs: Vec<Ipv4Net>, v6_addrs: Vec<Ipv6Net>) -> Interface {
        Interface {
            name: name.to_string(),
            ipv4: v4_addrs,
            ipv6: v6_addrs,
            ..Interface::dummy()
        }
    }

    #[test]
    fn test_first_interface_ip_with_ipv4() {
        let iface = make_interface(
            "eth0",
            vec![Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap()],
            vec![],
        );
        let ip = first_interface_ip(&iface);

        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_first_interface_ip_with_ipv6_only() {
        let iface = make_interface(
            "eth1",
            vec![],
            vec![Ipv6Net::new(Ipv6Addr::LOCALHOST, 128).unwrap()],
        );
        let ip = first_interface_ip(&iface);

        assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_first_interface_ip_with_no_addrs() {
        let iface = make_interface("lo", vec![], vec![]);
        let ip = first_interface_ip(&iface);

        assert_eq!(ip, None);
    }

    #[test]
    fn test_interface_by_ip_found() {
        fn mock_get_interfaces() -> Vec<Interface> {
            vec![
                make_interface(
                    "eth0",
                    vec![Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap()],
                    vec![],
                ),
                make_interface(
                    "eth1",
                    vec![Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()],
                    vec![],
                ),
            ]
        }

        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = mock_get_interfaces()
            .into_iter()
            .find(|iface| iface.ipv4.iter().any(|net| net.addr() == target_ip))
            .map(|iface| iface.name);

        assert_eq!(result, Some("eth1".to_string()));
    }

    #[test]
    fn test_interface_by_ip_not_found() {
        let iface = make_interface(
            "eth0",
            vec![Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap()],
            vec![],
        );
        let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let matches = iface.ipv4.iter().any(|net| net.addr() == target_ip);

        assert!(!matches);
    }
}
