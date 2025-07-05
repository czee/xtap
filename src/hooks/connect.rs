use std::cell::Cell;
use std::ffi::CStr;
use std::sync::OnceLock;

use libc::{AF_INET, AF_INET6, c_int, sockaddr, sockaddr_in, socklen_t};

use super::bind::Bind;
use super::hook::Hook;
use super::{guard, setup};
use crate::debug_log;

type ConnectFn = unsafe extern "C" fn(i32, *const sockaddr, socklen_t) -> i32;

static RAW_CONNECT: OnceLock<ConnectFn> = OnceLock::new();

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

pub struct Connect;

pub(crate) trait ConnectHook: Hook {
    /// Returns the raw `connect` function pointer and internally does setup once
    fn raw() -> ConnectFn;

    /// Internal `connect` hook implementation.
    ///
    /// Uses a recursion guard to avoid infinite loops on multithreaded calls.
    fn _connect(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        let _guard = match guard(&IN_HOOK) {
            None => {
                debug_log!("connect() already inside hook, calling raw");
                return unsafe { Self::raw()(sockfd, addr, addrlen) };
            }
            Some(g) => g,
        };

        debug_log!("connect() called");

        let sa = unsafe { &*(addr as *const sockaddr_in) };
        if sa.sin_family as c_int != AF_INET && sa.sin_family as c_int != AF_INET6 {
            debug_log!("not an AF_INET-type socket, calling raw");
            return unsafe { Self::raw()(sockfd, addr, addrlen) };
        }

        Bind::guarded(sockfd);

        unsafe { Self::raw()(sockfd, addr, addrlen) }
    }
}

impl Hook for Connect {
    const SYMBOL: &'static str = "connect";
    const CSYMBOL: &'static CStr = c"connect";
}

impl ConnectHook for Connect {
    fn raw() -> ConnectFn {
        debug_log!("connect() intercepted");
        unsafe { setup(&RAW_CONNECT, Self::CSYMBOL) }
    }
}

impl Connect {
    /// Entry point wrapper for the internal `_connect` hook.
    pub fn connect(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        Self::_connect(sockfd, addr, addrlen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{AF_INET, AF_INET6, AF_UNIX, sockaddr, sockaddr_in};
    use std::mem::size_of;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::ptr;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    const RC: i32 = 4242;

    static CALLED: AtomicBool = AtomicBool::new(false);
    static MOCK_CONNECT: OnceLock<ConnectFn> = OnceLock::new();

    unsafe extern "C" fn mock_raw(
        _sockfd: i32,
        _addr: *const sockaddr,
        _addrlen: socklen_t,
    ) -> i32 {
        CALLED.store(true, Ordering::SeqCst);
        RC
    }

    struct ConnectTest;

    impl Hook for ConnectTest {
        const SYMBOL: &'static str = "connect";
        const CSYMBOL: &'static CStr = c"connect";
    }

    impl ConnectHook for ConnectTest {
        fn raw() -> ConnectFn {
            *MOCK_CONNECT.get().unwrap_or(&Connect::raw())
        }
    }

    fn setup_mock_connect() {
        let _ = MOCK_CONNECT.set(mock_raw);
    }

    #[test]
    fn test_connect_guard_blocks_recursion() {
        setup_mock_connect();
        IN_HOOK.with(|flag| flag.set(true));

        let result = ConnectTest::_connect(99, ptr::null(), 0);

        IN_HOOK.with(|flag| flag.set(false));
        assert_eq!(
            result, RC,
            "raw call should be called directly on recursion"
        );

        assert!(CALLED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_connect_non_inet_family_falls_back() {
        setup_mock_connect();

        let sa = sockaddr_in {
            sin_family: AF_UNIX as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };

        let result = ConnectTest::_connect(
            55,
            &sa as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as _,
        );

        assert_eq!(
            result, RC,
            "non-inet family should fall back to raw connect"
        );
        assert!(CALLED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_connect_valid_ipv4_calls_try_bind_and_connect() {
        setup_mock_connect();

        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let sa = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };

        let result = ConnectTest::_connect(
            7,
            &sa as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as _,
        );

        assert_eq!(result, RC, "valid AF_INET should call try_bind and raw");
        assert!(CALLED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_connect_valid_ipv6_does_not_panic() {
        setup_mock_connect();

        #[repr(C)]
        struct sockaddr_in6 {
            sin6_family: u16,
            sin6_port: u16,
            sin6_flowinfo: u32,
            sin6_addr: [u8; 16],
            sin6_scope_id: u32,
        }

        let sa = sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        };

        let result = ConnectTest::_connect(
            8,
            &sa as *const _ as *const sockaddr,
            size_of::<sockaddr_in6>() as _,
        );

        assert_eq!(result, RC, "AF_INET6 should bind and connect cleanly");
        assert!(CALLED.load(Ordering::SeqCst));
    }
}
