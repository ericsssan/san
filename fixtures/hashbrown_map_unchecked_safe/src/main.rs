//! Negative fixture: `get_many_unchecked_mut` / `get_many_key_value_unchecked_mut`
//! guarded by `k1 != k2`. san must emit ZERO `hashbrown_map_unchecked` findings.
//!
//! The keys_are_ne domain (BinOp::Ne true-edge SwitchInt) proves k1 ≠ k2.
//! locals_are_ne looks through ref_base so [&k1, &k2] array components resolve
//! to the originals — duplicate keys producing aliased &mut are impossible.
use hashbrown::HashMap;

/// If-guard: `k1 != k2` — duplicate keys impossible → suppress get_many variant.
pub fn safe_get_many_mut(map: &mut HashMap<i32, i32>, k1: i32, k2: i32) {
    if k1 != k2 {
        unsafe {
            let [_a, _b] = map.get_many_unchecked_mut([&k1, &k2]);
        }
    }
}

/// Same guard for the key-value variant.
pub fn safe_get_many_kv_mut(map: &mut HashMap<i32, i32>, k1: i32, k2: i32) {
    if k1 != k2 {
        unsafe {
            let [_a, _b] = map.get_many_key_value_unchecked_mut([&k1, &k2]);
        }
    }
}

/// Early-return guard: `if k1 == k2 { return }` — fall-through gives k1 ≠ k2
/// via the Eq-false (Ne-true) SwitchInt edge.
pub fn safe_get_many_early(map: &mut HashMap<i32, i32>, k1: i32, k2: i32) {
    if k1 == k2 {
        return;
    }
    unsafe {
        let [_a, _b] = map.get_many_unchecked_mut([&k1, &k2]);
    }
}

fn main() {
    let mut map = HashMap::new();
    map.insert(1i32, 10i32);
    map.insert(2i32, 20i32);
    safe_get_many_mut(&mut map, 1, 2);
    safe_get_many_kv_mut(&mut map, 1, 2);
    safe_get_many_early(&mut map, 1, 2);
    println!("done");
}
