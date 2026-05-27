use crossbeam_epoch::{self as epoch, Atomic, Owned};
use std::sync::atomic::Ordering;

fn main() {
    let guard = &epoch::pin();

    // Load a shared pointer from an atomic.
    let a: Atomic<u32> = Atomic::new(42u32);
    let shared = a.load(Ordering::Acquire, guard);

    if !shared.is_null() {
        // Bug: deref — caller must ensure Guard is still live and object not reclaimed.
        let _val: &u32 = unsafe { shared.deref() };
        println!("{}", _val);

        // Bug: as_ref — same epoch requirements as deref.
        if let Some(v) = unsafe { shared.as_ref() } {
            println!("{}", v);
        }
    }

    // Bug: into_owned — takes exclusive ownership from the Atomic; no concurrent readers allowed.
    let owned: Owned<u32> = unsafe { a.into_owned() };

    // Bug: into_shared — transfers ownership; caller must defer_destroy to avoid leak.
    let _shared2 = unsafe { owned.into_shared(guard) };
}
