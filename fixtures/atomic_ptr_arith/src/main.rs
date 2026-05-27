use std::sync::atomic::{AtomicPtr, Ordering};

fn main() {
    let mut data = [1u32, 2, 3, 4];
    let ap = AtomicPtr::new(data.as_mut_ptr());

    // Bug: fetch_ptr_add — result may escape the allocation.
    // Adding more than data.len() - 1 goes past the end (UB to dereference).
    let prev: *mut u32 = ap.fetch_ptr_add(1, Ordering::SeqCst);
    let _ = prev;

    // Bug: fetch_ptr_sub — result may go before the allocation start.
    // Subtracting more than the current offset from the base is UB to dereference.
    let prev2: *mut u32 = ap.fetch_ptr_sub(1, Ordering::SeqCst);
    let _ = prev2;
}
