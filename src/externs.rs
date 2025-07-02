use libc::{sockaddr, socklen_t};

use crate::hooks::bind::Bind;
use crate::hooks::connect::Connect;

/// # Safety
///
/// Raw pointers make this unsafe to override the
/// entrypoint for external libc function `bind`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
    Bind::bind(sockfd, addr, addrlen)
}

/// # Safety
///
/// Raw pointers make this unsafe to override the
/// entrypoint for external libc function `connect`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
    Connect::connect(sockfd, addr, addrlen)
}
