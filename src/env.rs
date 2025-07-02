use std::net::IpAddr;

use netdev::{interface, Interface};

use crate::debug_log;
use crate::net;

const XTAP_INTERFACE_ENVS: [&str; 2] = ["XTAP_IFACE", "XTAP_INTERFACE"];
const XTAP_IP_ENVS: [&str; 6] = [
    "XTAP_IP",
    "BIND_IP",
    "BIND_SRC",
    "XTAP_ADDR",
    "XTAP_BIND",
    "XTAP_BIND_ADDR",
];

/// Return an interface specified by an environment variable or `None`
fn interface_by_env(key: &str) -> Option<Interface> {
    if let Ok(name) = std::env::var(key) {
        debug_log!("{} selects interface: {}", key, name);
        let interfaces = interface::get_interfaces();

        return interfaces.iter().find(|iface| iface.name == name).cloned();
    } else {
        debug_log!("Environment variable '{}' not set", key);
    }

    None
}

/// Return an IP specified by an environment variable or `None`
fn ip_by_env(key: &str) -> Option<IpAddr> {
    if let Ok(ip_str) = std::env::var(key) {
        debug_log!("{} selects address: {}", key, ip_str);

        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            return Some(ip);
        } else {
            debug_log!("Invalid IP address format in '{}': {}", key, ip_str);
        }
    } else {
        debug_log!("Environment variable '{}' not set", key);
    }

    None
}

/// Returns the first valid IP from an environment variable in XTAP_IP_ENVS
fn parse_ip_envs() -> Option<IpAddr> {
    for env in XTAP_IP_ENVS.iter() {
        if let Some(ip) = ip_by_env(env) {
            return Some(ip);
        }
    }

    None
}

/// Returns the first matching interface from an environment variable in
/// XTAP_INTERFACE_ENVS
pub(crate) fn parse_interface_envs() -> Option<Interface> {
    for env in XTAP_INTERFACE_ENVS.iter() {
        if let Some(iface) = interface_by_env(env) {
            return Some(iface);
        }
    }

    None
}

/// Get the first IP for a specified interface or the first available IP
/// address specified in the environment variables.
pub(crate) fn parse(interface: &Option<Interface>) -> Option<IpAddr> {
    if let Some(interface) = interface {
        net::first_interface_ip(interface)
    } else {
        debug_log!(
            "Interface unspecified or not found, checking IP address environment variables..."
        );

        parse_ip_envs().or_else(|| {
            debug_log!("No specific IP address found in environment variables, using passthrough");
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdev::interface;
    use std::env;

    fn clear_xtap_envs() {
        for key in XTAP_INTERFACE_ENVS.iter().chain(XTAP_IP_ENVS.iter()) {
            unsafe { env::remove_var(key) };
        }
    }

    #[test]
    fn test_interface_by_env_returns_interface_when_set() {
        clear_xtap_envs();

        let interfaces = interface::get_interfaces();
        assert!(
            !interfaces.is_empty(),
            "No network interfaces available for test"
        );

        let iface_name = &interfaces[0].name;

        unsafe { env::set_var(XTAP_INTERFACE_ENVS[0], iface_name) };

        let iface = interface_by_env(XTAP_INTERFACE_ENVS[0]);
        assert!(iface.is_some(), "Expected interface found by env var");
        assert_eq!(iface.unwrap().name, *iface_name);

        clear_xtap_envs();
    }

    #[test]
    fn test_interface_by_env_returns_none_when_not_set() {
        clear_xtap_envs();

        let iface = interface_by_env("NONEXISTENT");
        assert!(iface.is_none());
    }

    #[test]
    fn test_ip_by_env_returns_ip_when_set_and_valid() {
        clear_xtap_envs();

        unsafe { env::set_var(XTAP_IP_ENVS[0], "127.0.0.1") };

        let ip = ip_by_env(XTAP_IP_ENVS[0]);
        assert_eq!(ip, Some("127.0.0.1".parse().unwrap()));

        clear_xtap_envs();
    }

    #[test]
    fn test_ip_by_env_returns_none_when_not_set() {
        clear_xtap_envs();

        let ip = ip_by_env("NONEXISTENT");
        assert!(ip.is_none());
    }

    #[test]
    fn test_ip_by_env_returns_none_on_invalid_ip() {
        clear_xtap_envs();

        unsafe { env::set_var(XTAP_IP_ENVS[0], "nonexistent") };

        let ip = ip_by_env(XTAP_IP_ENVS[0]);
        assert!(ip.is_none());

        clear_xtap_envs();
    }

    #[test]
    fn test_parse_ip_envs_returns_first_valid_ip() {
        clear_xtap_envs();

        unsafe { env::set_var(XTAP_IP_ENVS[0], "invalid.ip") };
        unsafe { env::set_var(XTAP_IP_ENVS[1], "192.168.1.1") };

        let ip = parse_ip_envs();
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));

        clear_xtap_envs();
    }

    #[test]
    fn test_parse_interface_envs_returns_first_found_interface() {
        clear_xtap_envs();

        let interfaces = interface::get_interfaces();
        assert!(!interfaces.is_empty());

        unsafe { env::set_var(XTAP_INTERFACE_ENVS[1], &interfaces[0].name) };

        let iface = parse_interface_envs();
        assert!(iface.is_some());
        assert_eq!(iface.unwrap().name, interfaces[0].name);

        clear_xtap_envs();
    }

    #[test]
    fn test_parse_returns_ip_from_interface_if_present() {
        clear_xtap_envs();

        let interfaces = interface::get_interfaces();
        assert!(!interfaces.is_empty());

        let iface = Some(interfaces[0].clone());
        let ip = parse(&iface);

        assert!(ip.is_some());
    }

    #[test]
    fn test_parse_returns_ip_from_env_if_interface_none() {
        clear_xtap_envs();

        unsafe { env::set_var(XTAP_IP_ENVS[0], "8.8.8.8") };

        let ip = parse(&None);

        assert_eq!(ip, Some("8.8.8.8".parse().unwrap()));

        clear_xtap_envs();
    }

    #[test]
    fn test_parse_returns_none_if_no_interface_and_no_ip_env() {
        clear_xtap_envs();

        let ip = parse(&None);

        assert!(ip.is_none());
    }
}
