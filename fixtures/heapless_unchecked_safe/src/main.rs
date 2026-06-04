//! Negative fixture: each heapless unchecked call here is guarded by the proof
//! its safety condition requires, so san must emit ZERO findings:
//!   • `push_unchecked` — `len() < capacity()` (spare capacity)
//!   • `set_len(n)`     — `n <= capacity()` (bounded-or-equal)
//!   • `swap_remove_unchecked(i)` — `i < len()` (bounded index)
use heapless::Vec;

/// push guarded by `len() < capacity()` — has_spare on the `then` edge.
fn guarded_push(v: &mut Vec<u8, 4>, x: u8) {
    if v.len() < v.capacity() {
        unsafe { v.push_unchecked(x) }
    }
}

/// set_len guarded by `n <= capacity()` — bounded_or_eq on the `then` edge.
fn guarded_set_len(v: &mut Vec<u8, 4>, n: usize) {
    if n <= v.capacity() {
        unsafe { v.set_len(n) }
    }
}

/// swap_remove guarded by `i < len()` — bounded index on the `then` edge.
fn guarded_swap_remove(v: &mut Vec<u8, 4>, i: usize) -> Option<u8> {
    if i < v.len() {
        Some(unsafe { v.swap_remove_unchecked(i) })
    } else {
        None
    }
}

fn main() {
    let mut v: Vec<u8, 4> = Vec::new();
    guarded_push(&mut v, 1);
    guarded_push(&mut v, 2);
    let r = guarded_swap_remove(&mut v, 0);
    guarded_set_len(&mut v, 1);
    println!("{r:?} {}", v.len());
}
