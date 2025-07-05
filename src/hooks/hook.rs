use std::ffi::CStr;

pub trait Hook {
    const SYMBOL: &'static str;
    const CSYMBOL: &'static CStr;
}
