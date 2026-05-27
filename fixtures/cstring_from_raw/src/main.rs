use std::ffi::CString;

fn main() {
    let original = CString::new("hello").unwrap();
    let raw = original.into_raw();

    // Bug: CString::from_raw — must use exact pointer from into_raw, same allocator,
    // unmodified buffer, and call exactly once.
    let rebuilt = unsafe { CString::from_raw(raw) };
    println!("{:?}", rebuilt);
}
