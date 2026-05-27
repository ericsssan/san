use hashbrown::raw::RawTable;
use std::hash::{DefaultHasher, Hash, Hasher};

fn hash<K: Hash>(k: &K) -> u64 {
    let mut s = DefaultHasher::new();
    k.hash(&mut s);
    s.finish()
}

fn main() {
    let mut table: RawTable<(u32, u32)> = RawTable::new();
    table.reserve(8, |x| hash(&x.0));

    let h = hash(&42u32);

    // Bug: insert_no_grow — table must have capacity; hash must match the key.
    let bucket = unsafe { table.insert_no_grow(h, (42u32, 100u32)) };

    // Bug: Bucket::as_ref — bucket must be occupied and not invalidated by resize.
    let entry = unsafe { bucket.as_ref() };
    println!("{}", entry.0);

    // Bug: Bucket::as_mut — exclusive access required; no concurrent readers.
    let entry_mut = unsafe { bucket.as_mut() };
    entry_mut.1 = 200u32;

    // Bug: erase — marks empty but does NOT drop the value (leak if Box/String/etc.)
    let bucket2 = unsafe { table.insert_no_grow(hash(&99u32), (99u32, 300u32)) };
    unsafe { table.erase(bucket2) };

    // Bug: remove — bucket must be occupied; bucket pointer invalid after call.
    let bucket3 = unsafe { table.insert_no_grow(hash(&88u32), (88u32, 400u32)) };
    let removed = unsafe { table.remove(bucket3) };
    println!("{}", removed.0.0);
}
