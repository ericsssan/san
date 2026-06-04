//! Negative fixture: `into_inner_unchecked` guarded by a proven `len == CAP`
//! (the vector is exactly full), so san must emit ZERO findings. The guard
//! lowers to an `Eq`/`Ne` of `len()` and `capacity()` on the same collection
//! feeding a `SwitchInt`; the full-capacity flow records `is_full(coll)` on the
//! taken edge.
use arrayvec::ArrayVec;

/// `len() == capacity()` guard — full on the `then` edge.
fn guarded_eq(v: ArrayVec<i32, 4>) -> Option<[i32; 4]> {
    if v.len() == v.capacity() {
        Some(unsafe { v.into_inner_unchecked() })
    } else {
        None
    }
}

/// Early-return guard: `if len() != capacity() { return }` proves full on the
/// fall-through path (`!(len != cap)` ⟹ `len == cap`).
fn guarded_ne_early_return(v: ArrayVec<i32, 4>) -> Option<[i32; 4]> {
    if v.len() != v.capacity() {
        return None;
    }
    Some(unsafe { v.into_inner_unchecked() })
}

fn main() {
    let mut v: ArrayVec<i32, 4> = ArrayVec::new();
    v.push(1);
    v.push(2);
    v.push(3);
    v.push(4);
    let a = guarded_eq(v.clone());
    let b = guarded_ne_early_return(v);
    println!("{a:?} {b:?}");
}
