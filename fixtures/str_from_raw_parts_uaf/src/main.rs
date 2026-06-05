#![feature(str_from_raw_parts)]
use std::alloc::{alloc, dealloc, Layout};
use std::str;

// Bug: str::from_raw_parts on a freed allocation — use-after-free.
// The pointer comes from alloc(); dealloc() frees it; from_raw_parts then
// references the freed memory.
fn str_from_freed() {
    let layout = Layout::from_size_align(4, 1).unwrap();
    let ptr = unsafe { alloc(layout) } as *const u8;
    assert!(!ptr.is_null());
    unsafe { dealloc(ptr as *mut u8, layout) };
    // san: use_after_free — ptr was freed by dealloc above
    let _s = unsafe { str::from_raw_parts(ptr, 4) };
}

fn main() {
    str_from_freed();
}
