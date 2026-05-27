#![allow(deprecated)]

/// Pattern from RUSTSEC-2021-0032 (byte_struct), RUSTSEC-2021-0040 (arenavec):
/// mem::uninitialized() is UB — if a panic occurs before full init,
/// the uninitialized value is dropped, causing memory corruption.
pub fn init_array<T: Default>() -> [T; 4] {
    unsafe {
        // san: mem_uninitialized — use MaybeUninit instead
        let mut arr: [T; 4] = std::mem::uninitialized();
        for i in 0..4 {
            arr[i] = T::default(); // panic here → drop of uninit values
        }
        arr
    }
}
