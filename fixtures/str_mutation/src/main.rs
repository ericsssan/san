fn main() {
    // Bug: as_bytes_mut — caller must ensure the bytes remain valid UTF-8
    // after any mutation; writing non-UTF-8 bytes is UB.
    let mut s = String::from("hello");
    unsafe {
        let b = s.as_bytes_mut();
        b[0] = b'H';
    }

    // Bug: as_mut_vec — same invariant; also allows unsafe length/capacity changes.
    let mut s2 = String::from("world");
    unsafe {
        let v = s2.as_mut_vec();
        v.push(b'!');
    }
}
