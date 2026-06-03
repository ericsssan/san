#![feature(clone_to_uninit)]
use std::clone::CloneToUninit;

// Bug: clone_to_uninit with a freed destination pointer is a use-after-free write.
fn clone_to_freed_ptr() {
    let p: *mut u32 = Box::into_raw(Box::new(0u32));
    unsafe {
        let _ = Box::from_raw(p); // frees p
        let src = 42u32;
        // san: use_after_free — dst (p) was freed above; writing to it is UAF
        src.clone_to_uninit(p as *mut u8);
    }
}

fn main() {
    clone_to_freed_ptr();
}
