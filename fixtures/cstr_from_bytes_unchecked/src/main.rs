use std::ffi::CStr;

fn main() {
    let bytes: &[u8] = b"hello\0";
    // Bug: from_bytes_with_nul_unchecked — must verify trailing \0, no interior nuls.
    let s: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(bytes) };
    println!("{:?}", s);
}
