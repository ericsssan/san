use std::ffi::{CStr, CString};

fn main() {
    // Bug: from_ptr — pointer must be non-null, null-terminated, and live long enough.
    let cs = CString::new("hello").unwrap();
    let ptr = cs.as_ptr();
    let _cstr: &CStr = unsafe { CStr::from_ptr(ptr) };

    // Bug: from_bytes_with_nul_unchecked — bytes must have exactly one trailing nul.
    let bytes: &[u8] = b"hello\0";
    let _cstr2: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(bytes) };

    // Bug: from_vec_unchecked — bytes must contain no null bytes.
    let vec: Vec<u8> = b"hello".to_vec();
    let _cs2: CString = unsafe { CString::from_vec_unchecked(vec) };
}
