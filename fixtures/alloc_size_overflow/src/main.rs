// Fixture: alloc_size_overflow — unchecked arithmetic in allocation size.
//
// Positive cases:
//   1. n * 8 feeds into Layout::from_size_align_unchecked (existing)
//   2. Layout from overflow arithmetic passed to alloc() (new: layout_overflow domain)
//
// Negative cases: arithmetic proven safe (bounded product ≤ isize::MAX).

use std::alloc::{Layout, alloc};

/// Unbounded n * 8 → Layout::from_size_align_unchecked.
/// san: alloc_size_overflow at Layout construction
fn alloc_n_u64(n: usize) -> *mut u64 {
    let size = n * 8_usize;
    let layout = unsafe { Layout::from_size_align_unchecked(size, 8) };  // san: alloc_size_overflow
    unsafe { alloc(layout) as *mut u64 }
}

/// Overflow arithmetic → layout → alloc(): alloc_size_overflow fires at alloc() site too.
/// san: alloc_size_overflow at Layout construction AND at alloc() call
fn alloc_via_layout(n: usize) -> *mut u8 {
    let size = n * 8_usize;
    let layout = unsafe { Layout::from_size_align_unchecked(size, 8) };  // san: alloc_size_overflow
    unsafe { alloc(layout) }                                              // san: alloc_size_overflow
}

/// n is bounded by mask (&0xFF → max 255); 255 * 8 = 2040 ≤ isize::MAX.
/// san: suppress — product proven ≤ isize::MAX.
fn alloc_small_bounded(n: usize) -> *mut u64 {
    let safe_n = n & 0xFF;
    let size = safe_n * 8_usize;                                 // 2040, no overflow
    let layout = unsafe { Layout::from_size_align_unchecked(size, 8) };  // no finding
    unsafe { alloc(layout) as *mut u64 }
}

fn main() {
    let _ = alloc_n_u64(10);
    let _ = alloc_via_layout(10);
    let _ = alloc_small_bounded(200);
}
