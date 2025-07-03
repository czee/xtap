pub mod bind;
pub mod connect;
pub mod hook;

use std::cell::Cell;
use std::ffi::CString;
use std::sync::OnceLock;
use std::thread::LocalKey;

use libc::{RTLD_NEXT, dlsym};
use scopeguard::{self, ScopeGuard};

use crate::debug_log;

/// # Safety
///
/// Raw pointers make this unsafe to setup the OnceLock for the
/// original function symbol.
pub(crate) unsafe fn setup<F>(lock: &OnceLock<F>, symbol: &'static str) -> F
where
    F: Copy,
{
    *lock.get_or_init(|| unsafe {
        let cstr = CString::new(symbol).expect("Symbol had internal null byte");
        debug_log!("Initial setup for {}()", symbol);

        let addr = dlsym(RTLD_NEXT, cstr.as_ptr());
        assert!(!addr.is_null(), "Failed to find original {symbol:?}()");

        debug_log!("Resolved real {}() to: {:?}", symbol, addr);

        std::mem::transmute_copy(&(addr as *const ()))
    })
}

// This function takes a reference to a thread-local boolean flag and returns the guard
// which will automatically Drop() at scope termination - similar to defer!
fn guard(flag: &'static LocalKey<Cell<bool>>) -> Option<ScopeGuard<(), impl FnOnce(())>> {
    if flag.with(|f| f.replace(true)) {
        None
    } else {
        Some(scopeguard::guard((), |_| {
            flag.with(|f| f.set(false));
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type MallocFn = unsafe extern "C" fn(usize) -> *mut libc::c_void;

    const SYMBOL: &str = "malloc";
    const NONEXISTENT: &str = "nonexistent_function";

    #[test]
    fn test_setup_resolves_known_symbol() {
        static RAW_ADDR: OnceLock<MallocFn> = OnceLock::new();

        unsafe {
            let malloc_fn: MallocFn = setup(&RAW_ADDR, &SYMBOL);

            let ptr = malloc_fn(16);
            assert!(!ptr.is_null());

            libc::free(ptr);
        }
    }

    #[test]
    #[should_panic(expected = "Failed to find original")]
    fn test_setup_panics_on_invalid_symbol() {
        static RAW_ADDR: OnceLock<MallocFn> = OnceLock::new();

        unsafe {
            let _: MallocFn = setup(&RAW_ADDR, &NONEXISTENT);
        }
    }
}
