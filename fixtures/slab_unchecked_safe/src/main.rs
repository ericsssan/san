//! Negative fixture: `Slab::get2_unchecked_mut` guarded by proven `key1 != key2`.
//! san must emit ZERO `slab_unchecked` findings.
//!
//! The keys_are_ne domain tracks `Ne(a, b)` → SwitchInt true edge to prove
//! the two keys are disjoint before the call.
use slab::Slab;

/// Guard: `if k1 != k2` — keys proven distinct on the true edge.
fn mutate_two(s: &mut Slab<i32>, k1: usize, k2: usize) -> Option<()> {
    if k1 != k2 {
        unsafe {
            let (a, b) = s.get2_unchecked_mut(k1, k2);
            *a += 1;
            *b += 1;
        }
        Some(())
    } else {
        None
    }
}

/// Early-return guard: `if k1 == k2 { return }` — false edge ⟹ k1 ≠ k2.
fn mutate_two_early_return(s: &mut Slab<i32>, k1: usize, k2: usize) {
    if k1 == k2 {
        return;
    }
    unsafe {
        let (a, b) = s.get2_unchecked_mut(k1, k2);
        *a *= 2;
        *b *= 2;
    }
}

fn main() {
    let mut s: Slab<i32> = Slab::new();
    let k1 = s.insert(10);
    let k2 = s.insert(20);
    mutate_two(&mut s, k1, k2);
    mutate_two_early_return(&mut s, k1, k2);
    println!("{} {}", s[k1], s[k2]);
}
