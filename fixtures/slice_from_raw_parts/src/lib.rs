#![feature(str_from_raw_parts)]
/// Common slice safety bugs found across arrow, abomonation, and FFI boundary code.

/// Bug: length is in bytes, not elements — creates overlapping elements.
pub fn bytes_as_u32s(bytes: &[u8]) -> &[u32] {
    unsafe {
        // san: slice_from_raw_parts — len should be bytes.len() / 4, not bytes.len()
        std::slice::from_raw_parts(bytes.as_ptr() as *const u32, bytes.len())
    }
}

/// Bug: pointer from a Vec that may have been reallocated.
pub fn dangling_slice_after_push() -> &'static [i32] {
    let mut v = vec![1i32, 2, 3];
    let ptr = v.as_ptr();
    v.push(4); // may reallocate — ptr is now dangling
    unsafe {
        // san: slice_from_raw_parts — ptr may be dangling after vec push
        std::slice::from_raw_parts(ptr, 4)
    }
}

/// Bug: mutable alias — two mutable slices over the same memory.
pub fn aliased_mut(buf: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let ptr = buf.as_mut_ptr();
    let len = buf.len() / 2;
    unsafe {
        // san: slice_from_raw_parts — mutable aliases to overlapping memory
        (
            std::slice::from_raw_parts_mut(ptr, len),
            std::slice::from_raw_parts_mut(ptr, len),
        )
    }
}

/// Bug: NonNull::slice_from_raw_parts — len must not exceed the allocation.
pub fn nonnull_slice(buf: &[u32]) -> std::ptr::NonNull<[u32]> {
    let nn = std::ptr::NonNull::new(buf.as_ptr() as *mut u32).unwrap();
    unsafe {
        // san: slice_from_raw_parts — len is in elements but may be wrong
        std::ptr::NonNull::slice_from_raw_parts(nn, buf.len() + 1)
    }
}

/// Bug: str::from_raw_parts — bytes must be valid UTF-8 or it is UB.
pub fn bytes_as_str(bytes: &[u8]) -> &str {
    unsafe {
        // san: slice_from_raw_parts (str variant) — bytes must be valid UTF-8
        std::str::from_raw_parts(bytes.as_ptr(), bytes.len())
    }
}

/// Bug: str::from_raw_parts_mut — bytes must be valid UTF-8 and exclusively accessible.
pub fn bytes_as_str_mut(bytes: &mut [u8]) -> &mut str {
    unsafe {
        // san: slice_from_raw_parts (str variant) — bytes must be valid UTF-8
        std::str::from_raw_parts_mut(bytes.as_mut_ptr(), bytes.len())
    }
}
