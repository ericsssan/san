/// Patterns from RUSTSEC-2020-0034 (arr), RUSTSEC-2021-0040 (arenavec),
/// and dozens of custom Vec implementations.

/// Bug: set_len called before elements are initialized — uninitialized read.
pub fn resize_uninit(v: &mut Vec<i32>, new_len: usize) {
    v.reserve(new_len);
    unsafe {
        // san: vec_set_len — elements in old_len..new_len are uninitialized
        v.set_len(new_len);
    }
}

/// Bug: set_len without verifying new_len <= capacity.
pub fn truncate_unchecked(v: &mut Vec<String>, new_len: usize) {
    unsafe {
        // san: vec_set_len — drops elements in new_len..old_len without running their Drop
        v.set_len(new_len);
    }
}

/// Correct usage pattern (for reference — san still flags it, user must verify).
pub fn extend_from_spare_capacity(v: &mut Vec<u8>, extra: &[u8]) {
    v.reserve(extra.len());
    let spare = v.spare_capacity_mut();
    for (slot, &byte) in spare.iter_mut().zip(extra) {
        slot.write(byte);
    }
    unsafe { v.set_len(v.len() + extra.len()) }
}
