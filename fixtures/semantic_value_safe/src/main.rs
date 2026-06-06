//! Negative fixture: san must emit ZERO findings.
//! These cases are suppressed by value/type semantic analysis — no runtime guards.
use std::num::{NonZeroU32, NonZeroUsize};

// ── Constant propagation ──────────────────────────────────────────────────────

/// Literal 5 is provably nonzero at compile time.
fn const_literal() -> NonZeroU32 {
    unsafe { NonZeroU32::new_unchecked(5) }
}

/// Literal 0x80 as u8 is ≤ 255 (type bound) and = 128 (const), provably nonzero.
fn const_u8_nonzero() -> NonZeroU32 {
    let x: u8 = 0x80;
    unsafe { NonZeroU32::new_unchecked(x as u32) }
}

// ── Type-level invariants ─────────────────────────────────────────────────────

/// NonZeroUsize parameter is provably nonzero by its type invariant.
fn nonzero_param(n: NonZeroUsize) -> NonZeroUsize {
    unsafe { NonZeroUsize::new_unchecked(n.get()) }
}

// ── Arithmetic: BitOr ─────────────────────────────────────────────────────────

/// (n | 1) always has the low bit set — always nonzero.
fn bitor_nonzero(n: u32) -> NonZeroU32 {
    let v = n | 1;
    unsafe { NonZeroU32::new_unchecked(v) }
}

/// (n | 0x80) has bit 7 set — always nonzero.
fn bitor_const_nonzero(n: u32) -> NonZeroU32 {
    let v = n | 0x80;
    unsafe { NonZeroU32::new_unchecked(v) }
}

// ── Arithmetic: BitAnd bounds ─────────────────────────────────────────────────

/// (x & 0x7F) ≤ 127, so as_ascii_unchecked is safe.
fn bitmask_ascii(x: u8) {
    let v = x & 0x7F;
    let _c = unsafe { std::ascii::Char::from_u8_unchecked(v) };
}

/// (x & 127) ≤ 127, so as_ascii_unchecked is safe (decimal mask).
fn bitmask_decimal_ascii(x: u8) {
    let v = x & 127u8;
    let _c = unsafe { std::ascii::Char::from_u8_unchecked(v) };
}

// ── Arithmetic: Rem bounds ────────────────────────────────────────────────────

/// (x % 128) ≤ 127, provably ASCII.
fn rem_ascii(x: u8) {
    let v = x % 128;
    let _c = unsafe { std::ascii::Char::from_u8_unchecked(v) };
}

// ── Arithmetic: Shr bounds ───────────────────────────────────────────────────

/// (x >> 1) ≤ 127 when x: u8 (since u8 ≤ 255, >> 1 ≤ 127).
fn shr_ascii(x: u8) {
    let v = x >> 1u8;
    let _c = unsafe { std::ascii::Char::from_u8_unchecked(v) };
}

fn main() {
    println!("{} {}", const_literal(), const_u8_nonzero());
    println!("{}", nonzero_param(NonZeroUsize::new(3).unwrap()));
    println!("{} {}", bitor_nonzero(0), bitor_const_nonzero(0));
    bitmask_ascii(200);
    bitmask_decimal_ascii(200);
    rem_ascii(200);
    shr_ascii(200);
}
