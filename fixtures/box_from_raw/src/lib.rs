#![feature(box_vec_non_null)]
use std::ptr::NonNull;

/// Bug: Box::from_raw called on a non-Box pointer (never allocated as Box).
pub fn from_stack_ptr() -> Box<i32> {
    let x: i32 = 42;
    // san: box_from_raw — pointer was never produced by Box::into_raw
    unsafe { Box::from_raw(&x as *const i32 as *mut i32) }
}

/// Bug: Box::from_raw called twice — double-free.
pub fn double_free(ptr: *mut String) -> (Box<String>, Box<String>) {
    unsafe {
        // san: box_from_raw — same pointer freed twice
        let a = Box::from_raw(ptr);
        let b = Box::from_raw(ptr);
        (a, b)
    }
}

/// Bug: Box::from_non_null (nightly) — same ownership rules as Box::from_raw;
/// the NonNull must come from Box::into_non_null and must not be used again.
pub fn from_non_null(nn: NonNull<i32>) -> Box<i32> {
    unsafe { Box::from_non_null(nn) }
}
