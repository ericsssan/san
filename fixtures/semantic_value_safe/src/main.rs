//! Negative fixture: san must emit ZERO findings.
//! These cases are suppressed by the NEW semantic analysis:
//!   • constant propagation (literal nonzero values)
//!   • type-level invariants (NonZero parameter, u8 bounds)
//!   • cast type bounds (x as u8 ≤ 255)
//!   • BitOr nonzero propagation
use std::num::{NonZeroU32, NonZeroUsize};

/// Literal constant: new_unchecked(5) — 5 is provably nonzero by constant propagation.
fn const_literal() -> NonZeroU32 {
    unsafe { NonZeroU32::new_unchecked(5) }
}

/// Type-level param: n is NonZeroUsize, so it's nonzero by its type invariant.
/// new_unchecked of a NonZero value should be suppressed by type facts.
fn nonzero_param(n: NonZeroUsize) -> NonZeroUsize {
    unsafe { NonZeroUsize::new_unchecked(n.get()) }
}

/// Cast type bounds: (x as u8) is always ≤ 255, so new_unchecked with a
/// value known ≤ 255 isn't specifically nonzero, but if we also have
/// a prior nonzero guard propagated through a cast it should suppress.
fn const_after_cast() -> NonZeroU32 {
    let x: u32 = 42;
    unsafe { NonZeroU32::new_unchecked(x) }
}

/// BitOr nonzero: (n | 1) is always nonzero — the low bit is always set.
fn bitor_nonzero(n: u32) -> NonZeroU32 {
    let v = n | 1;
    unsafe { NonZeroU32::new_unchecked(v) }
}

fn main() {
    println!("{} {} {} {}", const_literal(), nonzero_param(NonZeroUsize::new(3).unwrap()),
             const_after_cast(), bitor_nonzero(0));
}
