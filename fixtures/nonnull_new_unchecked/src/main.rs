use std::ptr::NonNull;

fn main() {
    let mut x: u32 = 7;
    // Bug: NonNull::new_unchecked — pointer must be non-null.
    let nn: NonNull<u32> = unsafe { NonNull::new_unchecked(&raw mut x) };
    let _ = nn;

    // Bug: creating from a raw integer cast — could be null in general.
    let addr: usize = 0x1000;
    let _nn2: NonNull<u8> = unsafe { NonNull::new_unchecked(addr as *mut u8) };
}
