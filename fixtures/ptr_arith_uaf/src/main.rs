// Fixture: pointer arithmetic on a freed pointer is use-after-free.
// After Box::from_raw reclaims the allocation, the dangling raw pointer
// must not be used for arithmetic — the resulting pointer is invalid.
fn uaf_via_ptr_arith() {
    let ptr = Box::into_raw(Box::new([1u8, 2, 3, 4]));
    unsafe {
        let _ = Box::from_raw(ptr);  // frees the allocation
        let _q = ptr.add(1);         // san: use-after-free — ptr is dangling
    }
}

// Correct: arithmetic before freeing is valid.
fn no_uaf() {
    let ptr = Box::into_raw(Box::new([1u8, 2, 3, 4]));
    unsafe {
        let _q = ptr.add(1);  // valid — still alive
        let _ = Box::from_raw(ptr);
    }
}

fn main() {
    uaf_via_ptr_arith();
    no_uaf();
}
