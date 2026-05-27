#![feature(ptr_mask)]

fn main() {
    let v = [1i32, 2, 3, 4, 5];
    let base = v.as_ptr();

    // Bug: add/sub must stay within the same allocation.
    let _p = unsafe { base.add(3) };
    let _q = unsafe { base.add(4).sub(2) };

    // Bug: offset — same rules as add/sub.
    let _r = unsafe { base.offset(2) };

    // Bug: offset_from — both pointers must be in the same allocation.
    let start = v.as_ptr();
    let end = unsafe { start.add(5) };
    let _dist: isize = unsafe { end.offset_from(start) };

    // Bug: mask — resulting pointer must still be within the same allocation.
    let _masked = unsafe { base.mask(0xFFFF_FFFF_FFFF_FFF8) };
}
