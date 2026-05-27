// Bug: get2_unchecked_mut — dual mutable refs without disjointness or validity check.
// If key1 == key2 or either key is vacant, this is immediate UB.
use slab::Slab;

fn main() {
    let mut s: Slab<i32> = Slab::new();
    let k1 = s.insert(10);
    let k2 = s.insert(20);

    unsafe {
        let (a, b) = s.get2_unchecked_mut(k1, k2);
        *a += 1;
        *b += 1;
    }

    println!("{} {}", s[k1], s[k2]);
}
