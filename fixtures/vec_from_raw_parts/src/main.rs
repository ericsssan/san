#![feature(box_vec_non_null)]
use std::ptr::NonNull;

fn main() {
    let mut v: Vec<u32> = vec![1, 2, 3, 4];
    let ptr = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    std::mem::forget(v);

    // Bug: Vec::from_raw_parts — ptr must come from same allocator; len ≤ cap; T must match.
    let rebuilt: Vec<u32> = unsafe { Vec::from_raw_parts(ptr, len, cap) };
    let _ = rebuilt;

    // Bug: Vec::from_parts (nightly) — same rules as from_raw_parts, just takes NonNull.
    let mut v2: Vec<u32> = vec![5, 6, 7];
    let nn = NonNull::new(v2.as_mut_ptr()).unwrap();
    let len2 = v2.len();
    let cap2 = v2.capacity();
    std::mem::forget(v2);
    let _rebuilt2: Vec<u32> = unsafe { Vec::from_parts(nn, len2, cap2) };

    // Bug: String::from_raw_parts — bytes must be valid UTF-8 in addition to Vec rules.
    let mut s = String::from("hello");
    let sp = s.as_mut_ptr();
    let sl = s.len();
    let sc = s.capacity();
    std::mem::forget(s);
    let _rs: String = unsafe { String::from_raw_parts(sp, sl, sc) };
}
