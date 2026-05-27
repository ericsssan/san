// Bug: insert_unique_unchecked — inserts without checking for duplicate keys/values.
// Bug: get_many_unchecked_mut — returns aliased &mut if duplicate keys are passed.
use hashbrown::{HashMap, HashSet};

fn main() {
    let mut map: HashMap<i32, i32> = HashMap::new();
    map.insert(1, 10);
    // Bug: key 1 already exists — two entries with the same key (logical UB).
    unsafe {
        let (_k, _v) = map.insert_unique_unchecked(1, 99);
    }

    let mut set: HashSet<i32> = HashSet::new();
    set.insert(42);
    // Bug: value 42 already exists — set uniqueness invariant violated.
    unsafe {
        let _r = set.insert_unique_unchecked(42);
    }

    let mut map2: HashMap<i32, i32> = HashMap::new();
    map2.insert(1, 10);
    map2.insert(2, 20);
    // Bug: if duplicate keys passed, produces aliased &mut V (UB).
    unsafe {
        let [_v1, _v2] = map2.get_many_unchecked_mut([&1, &2]);
    }

    // Bug: get_many_key_value_unchecked_mut — same aliasing hazard as above.
    unsafe {
        let [_opt] = map2.get_many_key_value_unchecked_mut([&1]);
    }
}
