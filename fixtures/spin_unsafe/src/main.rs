fn main() {
    let m = spin::Mutex::new(42u32);
    let rw = spin::RwLock::new(0u32);

    // Bug: force_unlock — must have no live references to the protected data.
    // If a lock guard is still alive, this creates a data race (UB).
    unsafe { m.force_unlock() };

    // Bug: force_read_decrement — can underflow or unblock a writer prematurely.
    unsafe { rw.force_read_decrement() };

    // Bug: force_write_unlock — releases write lock; any live &mut T is now aliased.
    unsafe { rw.force_write_unlock() };
}
