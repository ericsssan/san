use std::cell::Cell;

/// Pattern from RUSTSEC-2020-0099 (aovec):
/// impl Send/Sync without requiring T: Send/T: Sync lets non-thread-safe
/// types (Cell, Rc) cross thread boundaries, causing data races.

pub struct Wrapper<T> {
    inner: T,
}

// san: missing_send_sync_bounds — T is not required to be Send
unsafe impl<T> Send for Wrapper<T> {}

// san: missing_send_sync_bounds — T is not required to be Sync
unsafe impl<T> Sync for Wrapper<T> {}

/// This is the correct version — should NOT be flagged.
pub struct SafeWrapper<T: Send + Sync> {
    inner: T,
}

unsafe impl<T: Send + Sync> Send for SafeWrapper<T> {}
unsafe impl<T: Send + Sync> Sync for SafeWrapper<T> {}

/// Demonstrate the bug: wrapping Cell<i32> and sending across threads.
fn _send_cell_across_threads() {
    let w = Wrapper { inner: Cell::new(42) };
    std::thread::spawn(move || {
        w.inner.set(99); // data race if another thread reads concurrently
    });
}
