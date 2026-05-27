use std::ffi::{OsStr, OsString};

fn main() {
    // Bug: OsStr::from_encoded_bytes_unchecked — bytes must be valid for platform encoding.
    let bytes: &[u8] = b"hello.txt";
    let _os: &OsStr = unsafe { OsStr::from_encoded_bytes_unchecked(bytes) };

    // Bug: OsString::from_encoded_bytes_unchecked — same invariant, owned version.
    let owned: Vec<u8> = b"path/to/file".to_vec();
    let _os2: OsString = unsafe { OsString::from_encoded_bytes_unchecked(owned) };
}
