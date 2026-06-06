// Fixture: alloc_size_overflow — unchecked arithmetic in allocation size.
//
// Positive case: n * 8 (unbounded n) feeds into Layout::from_size_align_unchecked.
// When n is large the product wraps and the allocator gets a too-small size,
// producing heap overflow on subsequent writes.
//
// Negative cases: both operands have proven bounds whose product ≤ isize::MAX.

use std::alloc::{Layout, alloc};

/// Unbounded n * 8 — product can wrap for large n.
/// san: alloc_size_overflow
fn alloc_n_u64(n: usize) -> *mut u64 {
    let size = n * 8_usize;                                      // may overflow
    let layout = unsafe { Layout::from_size_align_unchecked(size, 8) };  // san: alloc_size_overflow
    unsafe { alloc(layout) as *mut u64 }
}

/// n is bounded by mask (&0xFF → max 255); 255 * 8 = 2040 ≤ isize::MAX.
/// san: suppress — product proven ≤ isize::MAX.
fn alloc_small_bounded(n: usize) -> *mut u64 {
    let safe_n = n & 0xFF;                                       // const_upper = 255
    let size = safe_n * 8_usize;                                 // 255 * 8 = 2040, no overflow
    let layout = unsafe { Layout::from_size_align_unchecked(size, 8) };  // no finding
    unsafe { alloc(layout) as *mut u64 }
}

fn main() {
    let _ = alloc_n_u64(10);
    let _ = alloc_small_bounded(200);
}
