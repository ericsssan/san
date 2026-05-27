#![feature(unsafe_pinned)]
use std::pin::UnsafePinned;

fn main() {
    let mut cell = UnsafePinned::new(42u32);

    // Bug: get_mut_unchecked — writing through *mut T while any other alias is
    // alive is UB; prefer get_mut_pinned for self-referential types.
    let p: *mut u32 = cell.get_mut_unchecked();
    unsafe { *p = 100 };

    // Bug: get — returns *mut T from &self; writing through it while a
    // shared reference is live invalidates the shared ref (UB).
    let q: *mut u32 = cell.get();
    unsafe { *q = 200 };

    // Bug: raw_get — same aliasing requirements as get.
    let r: *mut u32 = UnsafePinned::raw_get(&cell as *const _);
    unsafe { println!("{}", *r) };

    // Bug: raw_get_mut — same as get_mut_unchecked but from raw pointer.
    let s: *mut u32 = UnsafePinned::raw_get_mut(&mut cell as *mut _);
    unsafe { *s = 300 };
}
