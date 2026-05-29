// Fixture: cross-function use-after-free. `free_it` consumes its pointer
// parameter (Box::from_raw); the interprocedural summary records that, so a use
// of the pointer in the CALLER after the call is detected as a use-after-free —
// a bug that spans a function boundary, which intra-procedural analysis misses.

unsafe fn free_it(p: *mut u32) {
    let _ = Box::from_raw(p);
}

fn use_after_free_bug() -> u32 {
    let p = Box::into_raw(Box::new(7u32));
    unsafe {
        free_it(p);
        // san: use_after_free — `free_it` reclaimed the allocation; reading `*p` is UB
        *p
    }
}

fn correct() {
    // Consume exactly once, never used afterward — must NOT be flagged.
    let p = Box::into_raw(Box::new(7u32));
    unsafe { free_it(p); }
}

fn main() {
    let _ = use_after_free_bug();
    correct();
}
