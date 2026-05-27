/// Bug: write to unaligned pointer — UB on architectures that require alignment.
pub fn write_to_unaligned(buf: &mut [u8], val: u32) {
    let ptr = buf.as_mut_ptr() as *mut u32;
    // san: ptr_write — dst may not be aligned for u32
    unsafe { std::ptr::write_unaligned(ptr, val) }
}

/// Bug: ptr::write does not drop the previous value — leak if T has a destructor.
pub fn overwrite_without_drop(slot: *mut String, new_val: String) {
    // san: ptr_write — previous String at slot is not dropped (memory + heap leak)
    unsafe { std::ptr::write(slot, new_val) }
}

/// Bug: write_bytes to a typed pointer may leave it in an invalid state.
pub fn zero_out_bool(b: *mut bool) {
    // Zero is valid for bool (false), but arbitrary byte patterns are not.
    unsafe { std::ptr::write_bytes(b, 0x42, 1) }
}
