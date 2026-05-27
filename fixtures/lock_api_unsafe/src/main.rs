use parking_lot::{Mutex, RwLock};

fn main() {
    let m = Mutex::new(42u32);

    // Bug: force_unlock on a mutex that was locked then forgotten —
    // valid use, but must be paired with a prior mem::forget of the guard.
    let guard = m.lock();
    std::mem::forget(guard);
    // san: lock_api_unsafe — mutex must be locked before calling force_unlock
    unsafe { m.force_unlock() };

    let rw = RwLock::new(42u32);

    // Bug: force_unlock_write — must hold exclusive write lock.
    let wg = rw.write();
    std::mem::forget(wg);
    // san: lock_api_unsafe — must hold write lock before force_unlock_write
    unsafe { rw.force_unlock_write() };

    // Bug: force_unlock_read — must hold a shared read lock.
    let rg = rw.read();
    std::mem::forget(rg);
    // san: lock_api_unsafe — must hold read lock before force_unlock_read
    unsafe { rw.force_unlock_read() };
}
