use std::alloc::{alloc, alloc_zeroed, dealloc, Layout};

fn main() {
    let layout = Layout::array::<u32>(4).unwrap();

    // Bug: alloc::alloc — layout.size() must be > 0; return value must be null-checked.
    let ptr = unsafe { alloc(layout) };
    assert!(!ptr.is_null());

    // Bug: alloc::alloc_zeroed — same rules as alloc.
    let ptr2 = unsafe { alloc_zeroed(layout) };
    assert!(!ptr2.is_null());

    // Bug: alloc::dealloc — ptr must not be used after this call; layout must match.
    unsafe { dealloc(ptr, layout) };
    unsafe { dealloc(ptr2, layout) };
}
