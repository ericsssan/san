#![feature(binary_heap_as_mut_slice, binary_heap_from_raw_vec)]
// Demonstrates nightly BinaryHeap unsafe operations (features `binary_heap_as_mut_slice`
// tracking #63421 and `binary_heap_from_raw_vec` tracking #123628).
// Both bypass the max-heap invariant, causing silent incorrect results if misused.

use std::collections::BinaryHeap;

fn main() {
    // Bug: as_mut_slice — writes through the slice can violate the max-heap invariant.
    // Any subsequent pop()/push()/peek() after an invariant-breaking write produces
    // incorrect results silently (no panic, just wrong ordering).
    let mut heap: BinaryHeap<i32> = BinaryHeap::from(vec![9, 5, 4, 3, 1]);
    let slice: &mut [i32] = unsafe { heap.as_mut_slice() };
    // Writing 0 to position 0 (the root) breaks the max-heap invariant.
    slice[0] = 0;
    // heap.pop() now returns wrong results.

    // Bug: from_raw_vec — Vec must already satisfy the max-heap property.
    // [1, 5, 9] is NOT a valid max-heap (9 is not at root).
    let bad_vec = vec![1i32, 5, 9];
    let _bad_heap: BinaryHeap<i32> = unsafe { BinaryHeap::from_raw_vec(bad_vec) };
    // All heap operations on _bad_heap produce incorrect results.
}
