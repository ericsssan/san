use heapless::{Deque, Vec};

fn main() {
    // Bug: swap_remove_unchecked — no bounds check on index.
    // If index >= len, reads/writes past the end of the inline array (OOB, UB).
    let mut v: Vec<u32, 4> = Vec::new();
    v.push(1u32).ok();
    v.push(2u32).ok();
    unsafe { v.swap_remove_unchecked(5) };

    // Bug: push_back_unchecked — no capacity check.
    // If the deque is full, pushes past the end of the ring buffer (OOB write, UB).
    let mut d: Deque<u32, 4> = Deque::new();
    unsafe { d.push_back_unchecked(1u32) };
}
