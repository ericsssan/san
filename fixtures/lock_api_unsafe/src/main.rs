use parking_lot::Mutex;

fn correct_force_unlock(m: &Mutex<u32>) {
    // Correct: lock, forget the guard, then force_unlock.
    // Flow analysis sees the Forgotten guard → suppressed by lock_api_unsafe checker.
    let guard = m.lock();
    std::mem::forget(guard);
    unsafe { m.force_unlock() };
}

fn incorrect_force_unlock(m: &Mutex<u32>) {
    // Bug: force_unlock with no prior lock + forget on this path.
    // No Forgotten protocol in scope → lock_api_unsafe fires.
    unsafe { m.force_unlock() };
}

fn main() {
    let m = Mutex::new(42u32);
    correct_force_unlock(&m);
    // incorrect_force_unlock is UB to actually call, so just reference it.
    let _ = incorrect_force_unlock as fn(&Mutex<u32>);
}
