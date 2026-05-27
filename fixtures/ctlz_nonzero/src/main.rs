#![feature(core_intrinsics)]
use std::intrinsics::{ctlz_nonzero, cttz_nonzero};

fn main() {
    let x: u32 = 4;
    let y: u64 = 16;

    // Bug: ctlz_nonzero — input must be non-zero; passing 0 produces LLVM poison.
    let _leading_u32 = unsafe { ctlz_nonzero(x) };
    let _leading_u64 = unsafe { ctlz_nonzero(y) };

    // Bug: cttz_nonzero — input must be non-zero; passing 0 produces LLVM poison.
    let _trailing_u32 = unsafe { cttz_nonzero(x) };
    let _trailing_u64 = unsafe { cttz_nonzero(y) };
}
