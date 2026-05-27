use heapless::Vec;

fn main() {
    // Bug: push_unchecked — appends past capacity without a bounds check.
    // If len == N the write is one slot past the end of the inline array (OOB write, UB).
    let mut v: Vec<u32, 4> = Vec::new();
    unsafe { v.push_unchecked(1u32) };
    unsafe { v.push_unchecked(2u32) };
    println!("{:?}", v.as_slice());

    // Bug: set_len — elements in old_len..new_len are uninitialized; new_len must be <= N.
    let mut v2: Vec<u32, 4> = Vec::new();
    unsafe { v2.set_len(2) };
}
