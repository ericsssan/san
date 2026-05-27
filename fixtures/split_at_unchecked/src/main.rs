fn main() {
    let data: Vec<u8> = vec![1, 2, 3, 4];

    // Bug: split_at_unchecked — if mid > len, the second slice extends past
    // the end of the allocation, causing an out-of-bounds access.
    let mid = 2;
    let (left, right) = unsafe { data.split_at_unchecked(mid) };
    println!("left={}, right={}", left.len(), right.len());

    let mut data2: Vec<u8> = vec![10, 20, 30, 40];
    // Bug: split_at_mut_unchecked — same bounds requirement.
    let (lm, rm) = unsafe { data2.split_at_mut_unchecked(mid) };
    println!("lm={}, rm={}", lm.len(), rm.len());
}
