#![feature(str_from_raw_parts)]

fn main() {
    // Bug: from_utf8_unchecked — bytes must be valid UTF-8.
    let valid_bytes: &[u8] = b"hello world";
    let _s: &str = unsafe { std::str::from_utf8_unchecked(valid_bytes) };

    // Bug: String::from_utf8_unchecked — same invariant.
    let valid_vec: Vec<u8> = b"hello".to_vec();
    let _owned: String = unsafe { String::from_utf8_unchecked(valid_vec) };

    // Bug: str::from_raw_parts — pointer must be valid AND bytes must be UTF-8.
    let data = b"world";
    let _s2: &str = unsafe { std::str::from_raw_parts(data.as_ptr(), data.len()) };
}
