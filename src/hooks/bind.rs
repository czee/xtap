use core::cell::Cell;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, OnceLock};

use libc::{
    SO_BINDTODEVICE, SOL_SOCKET, setsockopt, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage,
    socklen_t,
};
use netdev::Interface;

use super::hook::Hook;
use super::{guard, setup};
use crate::debug_log;
use crate::env;
use crate::net;

type BindFn = unsafe extern "C" fn(i32, *const sockaddr, socklen_t) -> i32;

static RAW_BIND: OnceLock<BindFn> = OnceLock::new();
static INTERFACE: LazyLock<Option<Interface>> = LazyLock::new(env::parse_interface_envs);
static IP: LazyLock<Option<IpAddr>> = LazyLock::new(|| env::parse(&INTERFACE));

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

pub struct Bind;

pub(crate) trait BindHook: Hook {
    /// Returns the raw `bind` function pointer and internally does setup once
    fn raw() -> BindFn;

    /// Determines whether to intercept and override the bind call without recursion guard.
    ///
    /// Returns `Some(i32)` as a result from bind, otherwise `None` to
    /// allow fallback to original `bind` syscall.
    fn unguarded(sockfd: i32) -> Option<i32>;

    /// Internal `bind` hook implementation.
    ///
    /// Uses a recursion guard to avoid infinite loops on multithreaded calls.
    fn _bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        let _guard = match guard(&IN_HOOK) {
            None => return unsafe { Self::raw()(sockfd, addr, addrlen) },
            Some(g) => g,
        };

        Self::unguarded(sockfd).unwrap_or_else(|| unsafe { Self::raw()(sockfd, addr, addrlen) })
    }
}

impl Hook for Bind {
    const SYMBOL: &'static str = "bind";
    const CSYMBOL: &'static CStr = c"bind";
}

impl BindHook for Bind {
    fn raw() -> BindFn {
        debug_log!("bind() intercepted");
        unsafe { setup(&RAW_BIND, Self::CSYMBOL) }
    }

    fn unguarded(sockfd: i32) -> Option<i32> {
        if let Some(ip) = *IP {
            let (binded, bind_addrlen) = Self::try_ip(ip);
            Self::try_interface(sockfd, ip, &INTERFACE);

            unsafe { Some(Self::raw()(sockfd, binded, bind_addrlen)) }
        } else {
            debug_log!("No interface address specified, proceeding with raw bind");
            None
        }
    }
}

impl Bind {
    /// Returns the name of a specified `Interface` as a `CString`.
    fn name_of(interface: &Interface) -> CString {
        CString::new(interface.name.as_str()).expect("Interface name contains null byte")
    }

    /// Try setting the socket file descriptor, `sockfd`, to bind to an `Interface`
    ///
    /// Calls `setsockopt` with `SO_BINDTODEVICE`.
    fn try_interface(sockfd: i32, ip: IpAddr, interface: &Option<Interface>) {
        let interface = interface
            .as_ref()
            .map(|i| {
                let name = Self::name_of(i);
                debug_log!(
                    "No IP specified, binding to interface: {}",
                    name.to_str().unwrap()
                );
                name
            })
            .or_else(|| net::interface_by(ip).map(|i| Self::name_of(&i)))
            .unwrap_or_else(|| {
                debug_log!("No interface specified, proceeding with connect without binding");
                CString::default()
            });

        let res = unsafe {
            setsockopt(
                sockfd,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes().len() as u32,
            )
        };

        if res != 0 {
            debug_log!(
                "Failed to bind to device: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    /// Converts an IP address to a raw socket address pointer and length for binding.
    ///
    /// Returns a tuple of pointer and length suitable for `bind(2)`.
    fn try_ip(ip: IpAddr) -> (*const sockaddr, u32) {
        let sock_addr = SocketAddr::new(ip, 0);
        let mut storage = MaybeUninit::<sockaddr_storage>::uninit();
        let len = match sock_addr {
            SocketAddr::V4(_) => size_of::<sockaddr_in>(),
            SocketAddr::V6(_) => size_of::<sockaddr_in6>(),
        } as u32;

        debug_log!("Binding to interface IP: {:?}", ip);

        unsafe {
            let dst = storage.as_mut_ptr().cast::<u8>();
            let src = (&sock_addr as *const SocketAddr).cast::<u8>();

            std::ptr::copy_nonoverlapping(src, dst, len as usize);

            (storage.as_ptr().cast::<sockaddr>(), len)
        }
    }

    /// Guarded wrapper for `unguarded()` bind.
    ///
    /// Returns `Some(i32)` as a result from bind, otherwise `None` to
    /// allow fallback to original `bind` syscall.
    pub(crate) fn guarded(sockfd: i32) -> Option<i32> {
        let _guard = guard(&IN_HOOK)?;

        Self::unguarded(sockfd)
    }

    /// Entry point wrapper for the internal `_bind` hook.
    ///
    /// Called instead of the original libc `bind`.
    pub fn bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        Self::_bind(sockfd, addr, addrlen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::ptr;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    type BindFn = unsafe extern "C" fn(i32, *const sockaddr, socklen_t) -> i32;

    const RC: i32 = 1337;

    static CALLED: AtomicBool = AtomicBool::new(false);
    static MOCK_BIND: OnceLock<BindFn> = OnceLock::new();

    unsafe extern "C" fn mock_raw(
        _sockfd: i32,
        _addr: *const sockaddr,
        _addrlen: socklen_t,
    ) -> i32 {
        CALLED.store(true, Ordering::SeqCst);
        RC
    }

    pub struct BindTest;

    impl Hook for BindTest {
        const SYMBOL: &'static str = "bind";
        const CSYMBOL: &'static CStr = c"bind";
    }

    impl BindHook for BindTest {
        fn raw() -> BindFn {
            *MOCK_BIND.get().unwrap_or(&Bind::raw())
        }

        fn unguarded(sockfd: i32) -> Option<i32> {
            Bind::unguarded(sockfd)
        }
    }

    fn setup_mock_bind() {
        let _ = MOCK_BIND.set(mock_raw);
    }

    #[test]
    fn test_bind_guard_blocks_recursion() {
        setup_mock_bind();
        IN_HOOK.with(|flag| flag.set(true));

        let result = BindTest::_bind(42, ptr::null(), 0);

        assert_eq!(
            result, RC,
            "raw call should be called directly on recursion"
        );

        IN_HOOK.with(|flag| flag.set(false));
    }

    #[test]
    fn test_bind_falls_back_to_raw_when_no_env() {
        setup_mock_bind();
        CALLED.store(false, Ordering::SeqCst);

        let result = BindTest::_bind(5, ptr::null(), 0);

        assert!(CALLED.load(Ordering::SeqCst), "raw call should be called");

        assert_eq!(result, RC, "_bind should return mocked raw value");
    }

    #[test]
    fn test_valid_xtap_ip_triggers_bind() {
        setup_mock_bind();
        unsafe { std::env::set_var("XTAP_IP", "127.0.0.1") };

        let result = BindTest::unguarded(7);
        assert!(result.is_some(), "should return Some when XTAP_IP is valid");

        unsafe { std::env::remove_var("XTAP_IP") };
    }

    #[test]
    fn test_invalid_xtap_ip_does_not_bind() {
        unsafe { std::env::set_var("XTAP_IP", "not-an-ip") };

        let result = BindTest::unguarded(7);
        assert!(result.is_none(), "should return None for invalid IP");

        unsafe { std::env::remove_var("XTAP_IP") };
    }

    #[test]
    fn test_try_bind_interface() {
        let interface = Interface {
            name: "lo".to_string(),
            ..Interface::dummy()
        };

        Bind::try_interface(123, IpAddr::V4(Ipv4Addr::LOCALHOST), &Some(interface));
    }

    #[test]
    fn test_try_bind_ip_produces_valid_sockaddr() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (ptr, len) = Bind::try_ip(ip);

        assert!(!ptr.is_null(), "sockaddr pointer should not be null");
        assert!(len > 0, "sockaddr length should be nonzero");
    }
}
