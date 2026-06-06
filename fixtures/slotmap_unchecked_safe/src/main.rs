//! Negative fixture: `get_disjoint_unchecked_mut` guarded by `k1 != k2`.
//! san must emit ZERO `slotmap_unchecked` findings.
//!
//! The keys_are_ne domain (Ne-true SwitchInt edge) proves k1 ≠ k2 before the
//! call, so the aliased-&mut precondition is discharged — no duplicate keys.
use slotmap::SlotMap;

/// If-guard: `k1 != k2` proved by SwitchInt true edge → suppress.
pub fn disjoint_if_guard(sm: &mut SlotMap<slotmap::DefaultKey, i32>) {
    let k1 = sm.insert(10i32);
    let k2 = sm.insert(20i32);

    if k1 != k2 {
        unsafe {
            let [a, b] = sm.get_disjoint_unchecked_mut([k1, k2]);
            *a = 99;
            *b = 88;
        }
    }
}

/// Early-return guard: `if k1 == k2 { return }` — on the fall-through path
/// the Ne-false edge populates keys_are_ne, so the call is also suppressed.
pub fn disjoint_early_return(sm: &mut SlotMap<slotmap::DefaultKey, i32>, k1: slotmap::DefaultKey, k2: slotmap::DefaultKey) {
    if k1 == k2 {
        return;
    }
    unsafe {
        let [a, b] = sm.get_disjoint_unchecked_mut([k1, k2]);
        *a = 1;
        *b = 2;
    }
}

fn main() {
    let mut sm = SlotMap::new();
    disjoint_if_guard(&mut sm);

    let mut sm2 = SlotMap::new();
    let k1 = sm2.insert(1i32);
    let k2 = sm2.insert(2i32);
    disjoint_early_return(&mut sm2, k1, k2);
    println!("{} {}", sm2[k1], sm2[k2]);
}
