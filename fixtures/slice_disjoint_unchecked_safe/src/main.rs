//! Negative fixture: `get_disjoint_unchecked_mut` with guarded indices.
//! san must emit ZERO `slice_disjoint_unchecked` findings.
//!
//! The combined `i < len && j < len` (bounded domain) and `i != j`
//! (keys_are_ne domain) guards discharge both slice preconditions.

/// Full if-guard: bounds AND disjointness checked together → suppress.
pub fn disjoint_bounded(v: &mut [i32], i: usize, j: usize) {
    let len = v.len();
    if i < len && j < len && i != j {
        unsafe {
            let [a, b] = v.get_disjoint_unchecked_mut([i, j]);
            *a += 1;
            *b += 1;
        }
    }
}

/// Early-return disjointness guard: `if i == j { return }` gives `i != j`
/// on the fall-through path via the Eq-false SwitchInt edge.
pub fn disjoint_early_return(v: &mut [i32], i: usize, j: usize) {
    if i == j {
        return;
    }
    if i >= v.len() || j >= v.len() {
        return;
    }
    unsafe {
        let [a, b] = v.get_disjoint_unchecked_mut([i, j]);
        *a = 0;
        *b = 0;
    }
}

fn main() {
    let mut v = vec![1, 2, 3, 4, 5];
    disjoint_bounded(&mut v, 1, 3);
    disjoint_early_return(&mut v, 0, 4);
    println!("{:?}", v);
}
