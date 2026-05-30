// Fixture: MaybeUninit used to create multiple copies of a raw pointer, each
// subsequently passed to Box::from_raw — a double-free.
//
// MaybeUninit::assume_init() performs a bitwise copy of the inner value without
// consuming it, so two calls on the same MaybeUninit<*mut T> produce two aliased
// raw pointers to the same allocation.

use std::mem::MaybeUninit;

// Two assume_init calls produce two aliased pointers — both freed.
fn double_free_via_assume_init() {
    unsafe {
        let ptr = Box::into_raw(Box::new(42i32));
        let mu = MaybeUninit::new(ptr);
        let r1 = mu.assume_init();        // first copy
        let r2 = mu.assume_init();        // second copy — same allocation
        let _b1 = Box::from_raw(r1);      // first reconstitution — fine
        let _b2 = Box::from_raw(r2);      // san: double-free
    }
}

// Correct: single assume_init, single from_raw.
fn no_double_free() {
    unsafe {
        let ptr = Box::into_raw(Box::new(99i32));
        let mu = MaybeUninit::new(ptr);
        let r = mu.assume_init();
        let _b = Box::from_raw(r); // single reconstitution — fine
    }
}

fn main() {
    double_free_via_assume_init();
    no_double_free();
}
