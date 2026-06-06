//! Negative fixture: every `NonZero::new_unchecked` here is guarded by a proven
//! `n != 0` (or `n > 0`, early-return `n == 0`) condition, so san must emit
//! ZERO findings. The guard lowers to a SwitchInt on an Ne/Gt/Eq comparison;
//! the value-range flow records `nonzero(n)` on the taken branch.
use std::num::NonZeroU32;

/// `n != 0` guard — nonzero_if_true on the then-edge.
fn guarded_ne(n: u32) -> Option<NonZeroU32> {
    if n != 0 { Some(unsafe { NonZeroU32::new_unchecked(n) }) } else { None }
}

/// `n > 0` guard — const_lower[n] ≥ 1 on the then-edge → local_is_nonzero.
fn guarded_gt(n: u32) -> Option<NonZeroU32> {
    if n > 0 { Some(unsafe { NonZeroU32::new_unchecked(n) }) } else { None }
}

/// Early-return `n == 0` guard — nonzero_if_false on the fall-through.
fn guarded_eq_early_return(n: u32) -> Option<NonZeroU32> {
    if n == 0 { return None; }
    Some(unsafe { NonZeroU32::new_unchecked(n) })
}

/// as_mut_ptr() is always non-null — NonNull::new_unchecked on its result is safe.
fn vec_as_mut_ptr_nonnull() -> std::ptr::NonNull<u32> {
    let mut v: Vec<u32> = Vec::with_capacity(4);
    let p = v.as_mut_ptr();
    // p is guaranteed non-null (Vec uses a dangling ptr for zero-capacity,
    // never null), so NonNull::new_unchecked is safe here.
    unsafe { std::ptr::NonNull::new_unchecked(p) }
}

fn main() {
    println!("{:?} {:?} {:?} {:?}",
        guarded_ne(1), guarded_gt(2), guarded_eq_early_return(3),
        vec_as_mut_ptr_nonnull());
}
