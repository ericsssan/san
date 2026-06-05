//! Negative fixture: every `uget`/`uget_mut`/`uswap` here is guarded by an
//! explicit bounds check whose components are proven bounded on all reaching
//! paths. san must emit ZERO `ndarray_unchecked` findings.
//!
//! The array_components domain decomposes `[i, j]`/`(i, j)` index aggregates
//! into scalar locals; `local_is_bounded` (from the lt_facts → bounded path
//! through refine_switchint_edge) proves each < some length.
use ndarray::{Array1, Array2};

/// 2-D guard: `if i < arr.nrows() && j < arr.ncols()` — both components of
/// the `[i, j]` aggregate are proven bounded before the `uget` call.
pub fn uget_2d_guarded(arr: &Array2<f64>, i: usize, j: usize) -> Option<f64> {
    if i < arr.nrows() && j < arr.ncols() {
        Some(unsafe { *arr.uget([i, j]) })
    } else {
        None
    }
}

/// 2-D mutable guard: same pattern for `uget_mut`.
pub fn uget_mut_2d_guarded(arr: &mut Array2<f64>, i: usize, j: usize, val: f64) {
    if i < arr.nrows() && j < arr.ncols() {
        unsafe { *arr.uget_mut([i, j]) = val };
    }
}

/// 1-D guard: single-component index, proven bounded by `if i < arr.len()`.
pub fn uget_1d_guarded(arr: &Array1<f64>, i: usize) -> Option<f64> {
    if i < arr.len() {
        Some(unsafe { *arr.uget(i) })
    } else {
        None
    }
}

/// uswap guard: both index args have all-local bounded components.
/// `i` and `j` are both bounded (< nrows, < ncols) so `[i, j]` and `[j, i]`
/// each have fully-bounded components after the guard.
pub fn uswap_guarded(arr: &mut Array2<f64>, i: usize, j: usize) {
    if i < arr.nrows() && j < arr.ncols() {
        unsafe { arr.uswap([i, j], [j, i]) };
    }
}

fn main() {
    let arr = Array2::<f64>::zeros((4, 4));
    let arr1 = Array1::<f64>::zeros(4);
    let mut arr2 = Array2::<f64>::zeros((4, 4));
    println!("{:?}", uget_2d_guarded(&arr, 1, 2));
    println!("{:?}", uget_1d_guarded(&arr1, 2));
    uget_mut_2d_guarded(&mut arr2, 1, 2, 99.0);
    uswap_guarded(&mut arr2, 0, 1);
}
