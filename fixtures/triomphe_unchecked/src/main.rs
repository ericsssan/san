use triomphe::{Arc, ArcBorrow, ThinArc, UniqueArc};
use std::mem::MaybeUninit;

fn main() {
    // Bug: ArcBorrow::from_ptr — borrow does NOT increment the ref count;
    // the Arc must remain live for the entire duration of the borrow.
    let arc = Arc::new(42u32);
    let borrow: ArcBorrow<'_, u32> = unsafe { ArcBorrow::from_ptr(Arc::as_ptr(&arc)) };
    println!("{}", *borrow);

    // Bug: ThinArc::from_raw — triomphe's thin-arc has a different allocation
    // layout from std::sync::Arc; using a pointer from a different allocator is UB.
    let thin = ThinArc::from_header_and_slice(0u32, &[1u8, 2, 3]);
    let thin_ptr = ThinArc::into_raw(thin);
    let _thin2: ThinArc<u32, u8> = unsafe { ThinArc::from_raw(thin_ptr) };
}
