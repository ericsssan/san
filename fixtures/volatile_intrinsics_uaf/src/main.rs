#![feature(core_intrinsics)]
use std::intrinsics;

// Bug: volatile_load on a freed pointer is a use-after-free read.
fn volatile_load_freed() -> u32 {
    let p = Box::into_raw(Box::new(42u32));
    unsafe {
        let _ = Box::from_raw(p); // frees p
        // san: use_after_free — p was freed above; volatile_load is UAF read
        intrinsics::volatile_load(p as *const u32)
    }
}

fn main() {
    let _ = volatile_load_freed();
}
