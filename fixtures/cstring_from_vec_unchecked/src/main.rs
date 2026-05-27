use std::ffi::CString;

fn main() {
    // Bug: from_vec_unchecked — bytes must have no interior nul bytes.
    // An interior 0x00 silently truncates the string at the C layer.
    let bytes: Vec<u8> = vec![b'h', b'e', b'l', b'l', b'o'];
    let _cs = unsafe { CString::from_vec_unchecked(bytes) };

    // Bug: from_vec_with_nul_unchecked — last byte must be 0x00 and no interior nuls.
    // Missing or misplaced terminator is UB when passed to any C API.
    let bytes_with_nul: Vec<u8> = vec![b'w', b'o', b'r', b'l', b'd', 0u8];
    let _cs2 = unsafe { CString::from_vec_with_nul_unchecked(bytes_with_nul) };
}
