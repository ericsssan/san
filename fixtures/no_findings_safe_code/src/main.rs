/// Negative test: safe alternatives to dangerous APIs.
/// This fixture must produce ZERO san findings.
use std::num::NonZeroU32;
use std::sync::Arc;

fn main() {
    // Safe: char::from_u32 (returns Option) instead of from_u32_unchecked.
    let _c: Option<char> = char::from_u32(0x41);

    // Safe: NonZeroU32::new (returns Option) instead of new_unchecked.
    let _nz: Option<NonZeroU32> = NonZeroU32::new(42);

    // Safe: str::from_utf8 (returns Result) instead of from_utf8_unchecked.
    let bytes: &[u8] = b"hello";
    let _s: Result<&str, _> = std::str::from_utf8(bytes);

    // Safe: slice::get (returns Option) instead of get_unchecked.
    let v = [1u32, 2, 3];
    let _elem: Option<&u32> = v.get(1);

    // Safe: Arc::new without raw pointer manipulation.
    let _a: Arc<String> = Arc::new(String::from("shared"));

    // Safe: AtomicU32::new without from_ptr.
    let _atomic = std::sync::atomic::AtomicU32::new(0);

    // Safe: Layout::from_size_align (returns Result) instead of unchecked.
    let _layout = std::alloc::Layout::from_size_align(64, 8);

    // Safe: Option::unwrap (panics on None) instead of unwrap_unchecked.
    let opt: Option<i32> = Some(7);
    let _v: i32 = opt.unwrap();

    // Safe: Box::new without from_raw.
    let _b: Box<u32> = Box::new(42);

    // Safe: use AtomicUsize instead of static mut.
    static COUNTER: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    let _ = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}
