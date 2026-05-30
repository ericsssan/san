// Fixture: use-after-free via NonNull::as_ref/as_mut after the underlying
// allocation was freed via Box::from_raw.
//
// NonNull wraps a raw pointer without owning the allocation. After the
// allocation is freed through a separate path, calling as_ref or as_mut
// on the NonNull creates a dangling reference.
use std::ptr::NonNull;

fn uaf_via_nonnull_as_ref() {
    let ptr = Box::into_raw(Box::new(42i32));
    let nn = unsafe { NonNull::new_unchecked(ptr) };
    unsafe {
        let _ = Box::from_raw(ptr);  // frees the allocation
        let _r: &i32 = nn.as_ref();  // san: use-after-free — nn is dangling
    }
}

// Correct: use NonNull while the allocation is still live.
fn no_uaf() {
    let ptr = Box::into_raw(Box::new(99i32));
    let nn = unsafe { NonNull::new_unchecked(ptr) };
    unsafe {
        let _r: &i32 = nn.as_ref(); // valid — Box is still alive
        let _ = Box::from_raw(ptr);
    }
}

fn main() {
    uaf_via_nonnull_as_ref();
    no_uaf();
}
