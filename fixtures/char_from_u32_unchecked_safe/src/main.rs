//! Negative fixture: every `char::from_u32_unchecked` here is guarded by a
//! proven valid Unicode scalar range, so san must emit ZERO findings.
//!
//! The const-bound flow tracks `const_upper`/`const_lower` from comparisons
//! vs specific integer constants; `local_is_valid_scalar` checks:
//!   • upper ≤ 0x10FFFF  (within Unicode range)
//!   • upper < 0xD800  (below surrogates) OR lower > 0xDFFF (above surrogates)

/// Below-surrogate guard: `u < 0xD800` → u ≤ 0xD7FF → valid BMP char.
pub fn below_surrogates(u: u32) -> Option<char> {
    if u < 0xD800 {
        Some(unsafe { char::from_u32_unchecked(u) })
    } else {
        None
    }
}

/// At-or-below-surrogate-boundary guard: `u <= 0xD7FF`.
pub fn at_bmp_boundary(u: u32) -> Option<char> {
    if u <= 0xD7FF {
        Some(unsafe { char::from_u32_unchecked(u) })
    } else {
        None
    }
}

/// Above-surrogate + in-range guard: `u >= 0xE000 && u <= 0x10FFFF`.
/// Lowers to two sequential SwitchInts that compound into const_lower ≥ 0xE000
/// AND const_upper ≤ 0x10FFFF → above_surrogates && in_range → valid.
pub fn supplementary_plane(u: u32) -> Option<char> {
    if u >= 0xE000 && u <= 0x10FFFF {
        Some(unsafe { char::from_u32_unchecked(u) })
    } else {
        None
    }
}

fn main() {
    println!("{:?} {:?} {:?}",
        below_surrogates(0x41),
        at_bmp_boundary(0xD7FF),
        supplementary_plane(0x1F600));
}
