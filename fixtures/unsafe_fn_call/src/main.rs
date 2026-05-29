// Fixture: calls to an `unsafe fn` that no path-based checker covers. These are
// the recall gap the unsafe_fn_call backstop fills — e.g. a trait/user-defined
// `unsafe fn` like tokio's `Link::from_raw` or `LinkedList::remove`.

/// A user-defined unsafe fn with a safety contract.
unsafe fn reconstruct(ptr: *const u32) -> u32 {
    *ptr
}

fn safe_helper(x: u32) -> u32 {
    x + 1
}

fn main() {
    let x = 5u32;
    let p: *const u32 = &x;

    // san: unsafe_fn_call — calling a user-defined unsafe fn
    let _ = unsafe { reconstruct(p) };

    // Safe call — must NOT be flagged.
    let _ = safe_helper(x);

    // ptr::read is a known unsafe API: ptr_read fires here and the backstop
    // unsafe_fn_call finding is suppressed (overlap), so it is not double-reported.
    let _ = unsafe { std::ptr::read(p) };
}
