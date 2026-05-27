use std::ptr;

fn main() {
    let src = [1u32, 2, 3, 4, 5];
    let mut dst = [0u32; 5];

    // Bug: ptr::copy_nonoverlapping — src and dst must not overlap.
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }

    // Bug: ptr::copy — overlapping is allowed but count must be correct.
    unsafe {
        ptr::copy(dst.as_ptr(), dst.as_mut_ptr().add(1), 3);
    }

    // Bug: copy_from — destination-perspective copy (stable 1.62).
    unsafe {
        dst.as_mut_ptr().copy_from(src.as_ptr(), 3);
        dst.as_mut_ptr().copy_from_nonoverlapping(src.as_ptr(), 3);
    }

    let _ = dst;
}
