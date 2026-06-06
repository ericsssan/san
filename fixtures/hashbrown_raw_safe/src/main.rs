//! Negative fixture: `RawTable::insert_no_grow` guarded by `len < capacity`.
//! san must emit ZERO `hashbrown_raw` findings.
//!
//! The spare-capacity domain (len() < capacity() true-edge SwitchInt) proves
//! the table has a free slot — the insert_no_grow precondition is discharged.
use hashbrown::raw::RawTable;
use std::hash::{DefaultHasher, Hash, Hasher};

fn hash_of<K: Hash>(k: &K) -> u64 {
    let mut s = DefaultHasher::new();
    k.hash(&mut s);
    s.finish()
}

/// Guard: `if table.len() < table.capacity()` proves spare capacity → suppress.
pub fn guarded_insert(table: &mut RawTable<(u32, u32)>, key: u32, val: u32) {
    if table.len() < table.capacity() {
        let h = hash_of(&key);
        unsafe { table.insert_no_grow(h, (key, val)); }
    }
}

/// Early-return guard: `if table.len() >= table.capacity() { return }` —
/// on the fall-through the Ge-false SwitchInt edge gives `len < capacity`.
pub fn guarded_insert_early(table: &mut RawTable<(u32, u32)>, key: u32, val: u32) {
    if table.len() >= table.capacity() {
        return;
    }
    let h = hash_of(&key);
    unsafe { table.insert_no_grow(h, (key, val)); }
}

fn main() {
    let mut table: RawTable<(u32, u32)> = RawTable::new();
    table.reserve(8, |x| hash_of(&x.0));
    guarded_insert(&mut table, 1, 10);
    guarded_insert_early(&mut table, 2, 20);
    println!("len={}", table.len());
}
