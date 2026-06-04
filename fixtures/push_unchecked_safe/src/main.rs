//! Negative fixture: every `push_unchecked` here is guarded by a proven
//! `len() < capacity()` (or the early-return / `capacity() > len()` forms), so
//! san must emit ZERO findings. The guard lowers to a `Lt`/`Gt` of a `len()`
//! and a `capacity()` call on the same collection feeding a `SwitchInt`; the
//! spare-capacity flow records `has_spare(coll)` on the taken edge.
use arrayvec::ArrayVec;

/// `len() < capacity()` guard — spare on the `then` edge.
fn guarded_lt(v: &mut ArrayVec<u32, 4>, x: u32) {
    if v.len() < v.capacity() {
        unsafe { v.push_unchecked(x) }
    }
}

/// `capacity() > len()` guard — same proof, operands swapped.
fn guarded_gt(v: &mut ArrayVec<u32, 4>, x: u32) {
    if v.capacity() > v.len() {
        unsafe { v.push_unchecked(x) }
    }
}

/// Early-return guard: `if len() >= capacity() { return }` proves spare on the
/// fall-through path (`!(len >= cap)` ⟹ `len < cap`).
fn guarded_early_return(v: &mut ArrayVec<u32, 4>, x: u32) {
    if v.len() >= v.capacity() {
        return;
    }
    unsafe { v.push_unchecked(x) }
}

fn main() {
    let mut v: ArrayVec<u32, 4> = ArrayVec::new();
    guarded_lt(&mut v, 1);
    guarded_gt(&mut v, 2);
    guarded_early_return(&mut v, 3);
    println!("{:?}", v.as_slice());
}
