//! Negative fixture: san must emit ZERO findings.
//! Demonstrates collection-specific bounds tracking:
//! the index is proven < THIS slice's len (not just any bound).

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

fn main() {
    let v = [1u32, 2, 3, 4, 5];
    println!("{}", get_safe(&v, 2));
    let (a, b) = split_safe(&v, 3);
    println!("{} {}", a.len(), b.len());
}
