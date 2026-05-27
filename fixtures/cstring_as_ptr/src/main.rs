use std::ffi::CString;

fn main() {
    // Bug: CString::as_ptr — CString is dropped at the semicolon; ptr is dangling.
    let ptr = CString::new("hello").unwrap().as_ptr();
    let _ = ptr;

    // Bug: CString::into_raw — leaks; must be freed via CString::from_raw.
    let raw = CString::new("world").unwrap().into_raw();
    // re-acquire to avoid leak in the fixture
    let _ = unsafe { CString::from_raw(raw) };

    // Bug: CString::from_vec_unchecked — bytes with interior nuls cause null-byte injection.
    let bytes: Vec<u8> = b"hello\0world".to_vec();
    let _ = unsafe { CString::from_vec_unchecked(bytes) };
}
