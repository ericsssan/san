//! Negative fixture: san must NOT fire [san::layout_unchecked] when the size
//! argument is proven small enough (const_upper ≤ isize::MAX / 2), OR when
//! the align is a constant power-of-two and the overflow concern is handled
//! by alloc_size_overflow (i.e. size ∈ mul_overflow → layout_unchecked suppressed).
use std::alloc::Layout;

fn main() {
    // size = 64 — const_upper[size] = 64 ≤ isize::MAX / 2 → suppressed.
    let size: usize = 64;
    let _layout = unsafe { Layout::from_size_align_unchecked(size, 8) };

    // Size from arithmetic with proven tight upper bound.
    // After `n & 0xFF`, const_upper[n_masked] = 255 ≤ isize::MAX / 2 → suppressed.
    let n: usize = std::env::args().count();
    let n_masked = n & 0xFF;  // provably ≤ 255
    let _layout2 = unsafe { Layout::from_size_align_unchecked(n_masked, 1) };

}
