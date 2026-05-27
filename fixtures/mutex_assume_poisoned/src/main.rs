use std::sync::Mutex;

fn main() {
    let m = Mutex::new(0u32);

    // Simulate poisoning by panicking inside lock.
    let _ = std::panic::catch_unwind(|| {
        let mut guard = m.lock().unwrap();
        *guard = 42; // partial modification
        panic!("poison the mutex with partial state");
    });

    // Bug: clear the poison without verifying/restoring the data.
    // Any subsequent lock() caller now sees Ok(guard) with potentially
    // inconsistent data — they have no signal that anything went wrong.
    m.clear_poison();

    // After clear_poison, lock() returns Ok — caller is unaware of the issue.
    let val = m.lock().unwrap();
    println!("val: {}", *val);
}
