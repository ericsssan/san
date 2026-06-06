//! Negative fixture: san must emit ZERO findings.
//! Demonstrates collection-specific bounds tracking:
//! the index is proven < THIS slice's len (not just any bound).
//! Also tests get_unchecked(0) suppression when len != 0.

fn get_safe(s: &[u32], i: usize) -> u32 {
    if i < s.len() {
        unsafe { *s.get_unchecked(i) }
    } else {
        0
    }
}

fn split_safe(s: &[u32], mid: usize) -> (&[u32], &[u32]) {
    if mid <= s.len() {
        unsafe { s.split_at_unchecked(mid) }
    } else {
        (s, &[])
    }
}

/// get_unchecked(0) guarded by len != 0: index 0 is always valid.
/// San should suppress because len ∈ nonzero on the taken branch.
fn first_if_nonempty(s: &[u32]) -> Option<u32> {
    if s.len() != 0 {
        Some(unsafe { *s.get_unchecked(0) })
    } else {
        None
    }
}

fn main() {
    let v = [1u32, 2, 3, 4, 5];
    println!("{}", get_safe(&v, 2));
    let (a, b) = split_safe(&v, 3);
    println!("{} {}", a.len(), b.len());
    println!("{:?}", first_if_nonempty(&v));
}
