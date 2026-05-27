use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

fn main() {
    let mut val: u32 = 42;
    // Bug: atomic_from_ptr — pointer must be aligned, valid, not aliased non-atomically.
    let atomic: &AtomicU32 = unsafe { AtomicU32::from_ptr(&raw mut val) };
    let _ = atomic.load(Ordering::Relaxed);

    let mut n: usize = 0;
    let atomic2: &AtomicUsize = unsafe { AtomicUsize::from_ptr(&raw mut n) };
    atomic2.store(1, Ordering::SeqCst);
}
