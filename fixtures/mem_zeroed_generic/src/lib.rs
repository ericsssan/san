use std::mem;

/// Pattern from RUSTSEC-2022-0019 (crossbeam-channel):
/// zeroing a generic T is unsound if T is a reference, bool, enum, etc.
pub struct Slot<T> {
    value: T,
}

impl<T> Slot<T> {
    pub fn zeroed() -> Self {
        Slot {
            // san: mem_zeroed_generic
            value: unsafe { mem::zeroed() },
        }
    }
}

/// Fine: zeroing a concrete type with all-zero being valid is OK.
pub fn zeroed_usize() -> usize {
    unsafe { mem::zeroed() }
}

/// Bug: null reference — zero is not a valid &i32.
pub fn zeroed_ref() -> &'static i32 {
    unsafe { mem::zeroed() }
}

/// Bug: null function pointer — zero is not a valid fn().
pub fn zeroed_fn_ptr() -> fn() {
    unsafe { mem::zeroed() }
}

/// Bug: NonZero zero value — violates NonZeroU32's invariant.
pub fn zeroed_nonzero() -> std::num::NonZeroU32 {
    unsafe { mem::zeroed() }
}
