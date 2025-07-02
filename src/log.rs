use std::sync::Mutex;

use libc::write;

const STDERR: libc::c_int = 2;

static LOCK: Mutex<()> = Mutex::new(());

/// Logs a thread-safe prefixed message to stderr using a raw `write()`
/// syscall.
pub fn stderr_log(msg: &str) {
    let msg = format!("[xtap] {msg}\n");
    let _lock = LOCK.lock().unwrap();

    unsafe {
        let _ = write(STDERR, msg.as_ptr().cast(), msg.len());
    }
}

#[macro_export]
macro_rules! debug_log {
    ($msg:expr) => {
        #[cfg(debug_assertions)]
        {
            $crate::log::stderr_log($msg);
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = &$msg;
        }
    };
    ($($arg:tt)+) => {
        #[cfg(debug_assertions)]
        {
            $crate::log::stderr_log(&format!($($arg)+));
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = format!($($arg)+);
        }
    };
}

/// Logs a message and returns `Some(val)`.
///
/// Useful for debugging while returning a wrapped value in an `Option`.
pub(crate) fn log_and_some<T>(msg: &str, val: T) -> Option<T> {
    debug_log!(msg);
    Some(val)
}

/// Logs a message and returns `None`.
///
/// Useful for debugging when an operation results in no value.
pub(crate) fn log_and_none<T>(msg: &str) -> Option<T> {
    debug_log!(msg);
    None
}
