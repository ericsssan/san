// Fixture: ptr::read creates a bitwise copy of a value containing a raw pointer.
// Both the original and the copy hold a pointer to the same allocation;
// when both are dropped (via a custom Drop impl calling Box::from_raw),
// the result is a double-free.
//
// This is the same aliased-ownership shape as the Clone fixture, but using
// ptr::read instead of Clone::clone.

use std::ptr;

struct OwnedPtr {
    raw: *mut u32,
}

impl Drop for OwnedPtr {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { drop(Box::from_raw(self.raw)); }
        }
    }
}

// Bug: ptr::read copies the struct bit-for-bit, creating two owners of the same
// allocation. When both are dropped, Box::from_raw is called twice → double-free.
fn double_free_via_ptr_read() {
    let b = Box::new(42u32);
    let raw = Box::into_raw(b);
    let original = OwnedPtr { raw };
    let copy: OwnedPtr = unsafe { ptr::read(&original) }; // aliased copy!
    // Both `original` and `copy` will call Box::from_raw(raw) on drop → double-free
    unsafe {
        drop(Box::from_raw(original.raw)); // first reconstitution
        drop(Box::from_raw(copy.raw));     // san: double-free
    }
}

// Correct: only one OwnedPtr, from_raw called once.
fn no_double_free() {
    let b = Box::new(7u32);
    let raw = Box::into_raw(b);
    let p = OwnedPtr { raw };
    unsafe { drop(Box::from_raw(p.raw)); }
}

fn main() {
    double_free_via_ptr_read();
    no_double_free();
}
