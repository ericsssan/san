//! Negative fixture: every `set_len` here is guarded by a proven
//! `new_len <= capacity()` (or strict `<`) bound, so san must emit ZERO
//! findings. The guard lowers to a `SwitchInt` on a `Le`/`Lt` temporary; the
//! dataflow edge-refinement records `bounded_or_eq`/`bounded` on the taken
//! branch, which both `vec_set_len` and the `unsafe_fn_call` backstop honor.

/// `<=` guard — bounded_or_eq on the `then` edge.
pub fn guarded_le(v: &mut Vec<u8>, new_len: usize) {
    if new_len <= v.capacity() {
        unsafe { v.set_len(new_len) }
    }
}

/// strict `<` guard — `new_len < capacity()` implies `<= capacity()`.
pub fn guarded_lt(v: &mut Vec<u8>, new_len: usize) {
    if new_len < v.capacity() {
        unsafe { v.set_len(new_len) }
    }
}

/// Early-return form: the negation `new_len > capacity()` bails, so the
/// fall-through path proves `new_len <= capacity()` (gt_facts on the false edge).
pub fn guarded_early_return(v: &mut Vec<u8>, new_len: usize) {
    if new_len > v.capacity() {
        return;
    }
    unsafe { v.set_len(new_len) }
}
