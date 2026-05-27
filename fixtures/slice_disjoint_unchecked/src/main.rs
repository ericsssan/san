fn main() {
    let mut v: Vec<u32> = vec![10, 20, 30, 40];

    // Bug: get_disjoint_unchecked_mut — indices must be in-bounds and distinct.
    // If index >= len or two indices are equal, the resulting &mut T are aliased (UB).
    let [a, b] = unsafe { v.get_disjoint_unchecked_mut([0, 2]) };
    *a += 1;
    *b += 1;
    println!("{:?}", v);
}
