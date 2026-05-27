#![feature(c_variadic)]
use std::ffi::VaList;

// Bug: VaList::next_arg — type must match the actual argument type.
// Reading i32 when a u64 was passed reinterprets bytes as i32 (UB).
// Calling more times than arguments were passed reads past the frame (UB).
unsafe extern "C" fn sum_integers(count: u32, mut args: VaList) -> i32 {
    let mut total = 0i32;
    for _ in 0..count {
        total = total.wrapping_add(unsafe { args.next_arg::<i32>() });
    }
    total
}

fn main() {
    // Fixture just needs to compile and have the unsafe fn body analyzed.
    let _ = sum_integers as unsafe extern "C" fn(u32, VaList) -> i32;
}
