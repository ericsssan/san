#![feature(btree_cursors)]
// Demonstrates BTreeMap cursor unchecked insertion (nightly feature `btree_cursors`,
// tracking issue #107540). These skip sort-order and uniqueness checks, silently
// corrupting the tree's internal structure if preconditions are violated.

use std::collections::BTreeMap;

fn main() {
    let mut map: BTreeMap<i32, &str> = BTreeMap::new();
    map.insert(10, "ten");
    map.insert(30, "thirty");

    // Bug: insert_after_unchecked — key (5) must be > all keys before cursor and
    // < the key immediately after (10). Here key=5 violates that ordering: 5 < 10
    // but the cursor is at the beginning, so 5 must be < 10 — that part is fine,
    // but we use 25 to show the pattern; caller must manually verify ordering.
    let mut cursor = map.lower_bound_mut(std::ops::Bound::Included(&10));
    // Inserts key=20 between 10 and 30 — caller must ensure 10 < 20 < 30.
    unsafe { cursor.insert_after_unchecked(20, "twenty") };

    // Bug: insert_before_unchecked — key must be > the key immediately before cursor
    // and < all keys after cursor position.
    let mut cursor2 = map.upper_bound_mut(std::ops::Bound::Included(&20));
    // Inserts key=25 between 20 and 30 — caller must ensure 20 < 25 < 30.
    unsafe { cursor2.insert_before_unchecked(25, "twenty-five") };

    // Bug: with_mutable_key — the returned CursorMutKey lets you mutate keys directly;
    // any mutation must preserve sorted order and uniqueness or the tree is corrupted.
    let cursor3 = map.lower_bound_mut(std::ops::Bound::Included(&20));
    let _ck = unsafe { cursor3.with_mutable_key() };
}
