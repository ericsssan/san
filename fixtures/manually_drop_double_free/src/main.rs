// Fixture: ManuallyDrop used to extract multiple copies of a raw pointer,
// each subsequently passed to Box::from_raw — a double-free.
//
// ManuallyDrop::into_inner / take perform a bitwise copy of the inner value,
// so two extractions from the same ManuallyDrop produce two aliased raw pointers.
// This is the pattern where forget-then-reconstitute is done twice.

use std::mem::ManuallyDrop;

// Two into_inner calls produce two aliased pointers — both freed.
fn double_free_via_into_inner() {
    unsafe {
        let ptr = Box::into_raw(Box::new(42i32));
        let md = ManuallyDrop::new(ptr);
        let r1 = ManuallyDrop::into_inner(md);
        let r2 = ManuallyDrop::into_inner(md); // second copy — same allocation
        let _b1 = Box::from_raw(r1);           // first reconstitution — fine
        let _b2 = Box::from_raw(r2);           // san: double-free
    }
}

// Correct: single into_inner, single from_raw.
fn no_double_free() {
    unsafe {
        let ptr = Box::into_raw(Box::new(99i32));
        let md = ManuallyDrop::new(ptr);
        let r = ManuallyDrop::into_inner(md);
        let _b = Box::from_raw(r); // single reconstitution — fine
    }
}

fn main() {
    double_free_via_into_inner();
    no_double_free();
}
