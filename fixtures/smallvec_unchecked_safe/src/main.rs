//! Negative fixture: `from_buf_and_len_unchecked(buf, len)` guarded by a proven
//! `len <= capacity` bound, so san must emit ZERO findings. The guard lowers to
//! a `Le`/`Lt` on `len` feeding a `SwitchInt`; the bounds flow records
//! `bounded_or_eq(len)` on the taken branch.
//!
//! The buffer is initialized with `MaybeUninit::new` (no raw-pointer writes) so
//! the fixture isolates the `smallvec_unchecked` suppression — unrelated unsafe
//! pointer code would trip other (correct) checkers.
use smallvec::SmallVec;
use std::mem::MaybeUninit;

/// `len <= 4` guard — bounded_or_eq on the `then` edge.
fn guarded(buf: MaybeUninit<[u32; 4]>, len: usize) -> Option<SmallVec<[u32; 4]>> {
    if len <= 4 {
        Some(unsafe { SmallVec::from_buf_and_len_unchecked(buf, len) })
    } else {
        None
    }
}

fn main() {
    let buf: MaybeUninit<[u32; 4]> = MaybeUninit::new([1, 2, 3, 4]);
    let sv = guarded(buf, 4);
    println!("{:?}", sv.map(|s| s.len()));
}
