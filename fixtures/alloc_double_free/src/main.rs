use std::alloc::{alloc, dealloc, Layout};

// Bug: double-free via alloc::dealloc called twice on the same allocation.
fn double_dealloc() {
    let layout = Layout::new::<u32>();
    let ptr = unsafe { alloc(layout) };
    assert!(!ptr.is_null());

    unsafe {
        dealloc(ptr, layout); // first free — correct
        // san: ownership_double_free — ptr was already freed above
        dealloc(ptr, layout);
    }
}

fn main() {
    double_dealloc();
}
