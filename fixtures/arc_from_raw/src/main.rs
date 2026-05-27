use std::sync::{Arc, Weak};

fn main() {
    let arc = Arc::new(42i32);

    // Bug: from_raw without ensuring the pointer came from into_raw.
    let raw: *const i32 = Arc::into_raw(arc);
    let _arc2: Arc<i32> = unsafe { Arc::from_raw(raw) };

    // Bug: manually managing the strong count.
    let arc4 = Arc::new(100i32);
    let raw4: *const i32 = Arc::into_raw(arc4);
    unsafe { Arc::increment_strong_count(raw4); }
    unsafe { Arc::decrement_strong_count(raw4); }
    drop(unsafe { Arc::from_raw(raw4) });

    // Bug: Weak::from_raw — pointer must come from Weak::into_raw,
    // control block must still be live.
    let arc5 = Arc::new(99i32);
    let weak: Weak<i32> = Arc::downgrade(&arc5);
    let raw_weak: *const i32 = Weak::into_raw(weak);
    let _weak2: Weak<i32> = unsafe { Weak::from_raw(raw_weak) };
}
