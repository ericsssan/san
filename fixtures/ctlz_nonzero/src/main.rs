#![feature(core_intrinsics)]
use std::intrinsics::{ctlz_nonzero, cttz_nonzero};

fn count_bits(x: u32, y: u64) {
    // Bug: no guard on x or y — if either is 0, LLVM poison.
    let _leading_u32 = unsafe { ctlz_nonzero(x) };
    let _leading_u64 = unsafe { ctlz_nonzero(y) };
    let _trailing_u32 = unsafe { cttz_nonzero(x) };
    let _trailing_u64 = unsafe { cttz_nonzero(y) };
}

fn main() {
    // pass in runtime values so the checker can't see them as constants
    let x: u32 = std::env::args().count() as u32;
    let y: u64 = std::env::args().count() as u64;
    count_bits(x, y);
}
