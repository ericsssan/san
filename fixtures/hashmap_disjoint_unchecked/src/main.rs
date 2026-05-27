// Demonstrates HashMap::get_disjoint_unchecked_mut (stable since Rust 1.86).
// This method skips the pairwise-distinct key check; duplicate keys in the array
// produce two Option<&mut V> pointing to the same slot — aliased mutable references (UB).

use std::collections::HashMap;

fn main() {
    let mut scores: HashMap<&str, u32> = HashMap::new();
    scores.insert("alice", 100);
    scores.insert("bob", 200);
    scores.insert("carol", 300);

    // Bug: caller must ensure "alice" and "bob" are different keys.
    // If the array contained a duplicate (e.g., ["alice", "alice"]), both elements
    // would be Some(&mut 100), aliasing the same slot — immediate UB.
    let [alice, bob] = unsafe { scores.get_disjoint_unchecked_mut(["alice", "bob"]) };
    if let (Some(a), Some(b)) = (alice, bob) {
        *a += 10;
        *b += 10;
    }
}
