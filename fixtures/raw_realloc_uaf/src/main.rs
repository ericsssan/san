// Fixture: use-after-free via alloc::realloc.
// realloc consumes the old pointer regardless of success or failure;
// using old_ptr after realloc is a use-after-free.
use std::alloc::{alloc, dealloc, realloc, Layout};

fn realloc_then_free_old() {
    let layout = Layout::from_size_align(4, 4).unwrap();
    let old_ptr = unsafe { alloc(layout) };
    assert!(!old_ptr.is_null());

    let new_layout = Layout::from_size_align(8, 4).unwrap();
    let _new_ptr = unsafe { realloc(old_ptr, layout, new_layout.size()) };

    // san: ownership_double_free — old_ptr was consumed by realloc
    unsafe { dealloc(old_ptr, layout) };
}

fn main() {
    realloc_then_free_old();
}
