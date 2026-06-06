//! Positive fixture: san must fire [san::cast_away_const].
//!
//! Patterns where *const T is cast to *mut T and written through — UB unless
//! the pointee is behind UnsafeCell. The compiler cannot catch these statically
//! because the const-pointer origin is hidden behind function calls.
use std::sync::Arc;

/// Returns a *const T from a shared Arc — caller can't directly see
/// the origin type, hiding it from the compiler's built-in UB check.
fn arc_const_ptr<T>(arc: &Arc<T>) -> *const T {
    Arc::as_ptr(arc)
}

fn main() {
    // Pattern 1: Arc::as_ptr() → *mut T → deref-write
    // Arc provides shared ownership; writing through a cast-away-const
    // *mut T while clones are alive is aliased mutation without UnsafeCell.
    let arc = Arc::new(42u32);
    let _clone = arc.clone();
    let p: *const u32 = arc_const_ptr(&arc);
    let q = p as *mut u32;
    unsafe { *q = 99; }          // ← san fires: cast-away-const mutation

    // Pattern 2: Arc::as_ptr() → *mut T → ptr::write
    let arc2 = Arc::new(7u32);
    let p2: *const u32 = arc_const_ptr(&arc2);
    let q2 = p2 as *mut u32;
    unsafe { std::ptr::write(q2, 0); } // ← san fires: cast-away-const mutation
}
