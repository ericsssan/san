// Fixture: indirect-call (fn-pointer) resolution. A freeing function is called
// through a reified fn pointer; flow resolves the pointer to its concrete
// target, applies that target's consume summary, and detects the later use as
// a use-after-free. (Const-embedded vtables like RawWaker remain unresolved.)

unsafe fn free_it(p: *mut u32) {
    let _ = Box::from_raw(p);
}

fn uaf_via_fn_ptr() -> u32 {
    let p = Box::into_raw(Box::new(7u32));
    let f: unsafe fn(*mut u32) = free_it; // reify fn pointer
    unsafe {
        f(p); // indirect call -> resolved to free_it -> frees p
        // san: use_after_free — p was reclaimed by the resolved call
        *p
    }
}

fn main() {
    let _ = uaf_via_fn_ptr as fn() -> u32;
}
