// Bug: get_disjoint_unchecked_mut — N mutable refs without generation or
// disjointness checks. Duplicate or stale keys produce aliased &mut (UB).
use slotmap::SlotMap;

fn main() {
    let mut sm = SlotMap::new();
    let k1 = sm.insert(10i32);
    let k2 = sm.insert(20i32);

    unsafe {
        let [a, b] = sm.get_disjoint_unchecked_mut([k1, k2]);
        *a = 99;
        *b = 88;
    }

    println!("{} {}", sm[k1], sm[k2]);
}
