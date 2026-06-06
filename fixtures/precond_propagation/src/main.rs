//! Positive fixture: san must fire [san::precond_violation] for every call.
//!
//! These are safe functions that internally call unsafe code without verifying
//! preconditions. Any safe caller can trigger UB without writing `unsafe`.
use std::num::NonZeroU32;

/// Safe API wrapping new_unchecked — no nonzero guard.
/// This is the "implicit precondition exposed to safe callers" pattern.
fn make_nonzero(x: u32) -> NonZeroU32 {
    unsafe { NonZeroU32::new_unchecked(x) }
}

/// Safe get_unchecked wrapper — no bounds check.
fn safe_get(s: &[u32], i: usize) -> u32 {
    unsafe { *s.get_unchecked(i) }
}

fn main() {
    // Bug: calling make_nonzero with an unguarded value.
    // n is not proven nonzero — the safe caller triggers UB.
    let n = std::env::args().count() as u32;
    let _ = make_nonzero(n);   // ← san fires here

    // Bug: calling safe_get with an unguarded index.
    let v = [1u32, 2, 3];
    let idx = std::env::args().count();
    let _ = safe_get(&v, idx); // ← san fires here
}
