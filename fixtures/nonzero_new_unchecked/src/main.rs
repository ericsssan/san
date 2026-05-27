#![feature(nonzero_ops)]
use std::num::{NonZeroU32, NonZeroUsize};

fn main() {
    // Bug: NonZeroU32::new_unchecked — passing zero is UB (corrupts Option niche).
    let _nz: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(42) };

    // Bug: NonZeroUsize::new_unchecked — value 0 would be UB.
    let n: usize = 8;
    let _nzu: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(n) };

    // Bug: NonZero::unchecked_add — result could overflow or become zero.
    let a = NonZeroU32::new(5).unwrap();
    let _sum = unsafe { a.unchecked_add(3u32) };

    // Bug: NonZero::unchecked_mul — product could overflow T, wrapping to zero.
    let b = NonZeroU32::new(3).unwrap();
    let _prod = unsafe { a.unchecked_mul(b) };
}
