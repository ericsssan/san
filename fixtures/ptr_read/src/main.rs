use std::ptr;

fn main() {
    let x: u64 = 0xDEAD_BEEF_CAFE_1234;

    // Bug: ptr::read — creates a bitwise copy; dropping both original and copy is double-drop.
    let copy: u64 = unsafe { ptr::read(&x) };
    let _ = copy;

    // Bug: ptr::read_unaligned — alignment not required, but validity still is.
    let bytes = [0u8, 1, 2, 3];
    let _val: u16 = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const u16) };
}
