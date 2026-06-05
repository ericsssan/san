//! Negative fixture: every `NotNan::new_unchecked` here is guarded by a proven
//! not-NaN condition, so san must emit ZERO findings. The guard is either
//! `!f.is_nan()` (finite_if_true on the not-branch) or early-return on
//! `f.is_nan()` (nan_if_true on the fall-through false-edge).
use ordered_float::NotNan;

/// `!f.is_nan()` guard — finite on the then-edge.
fn guarded_not_nan(f: f64) -> Option<NotNan<f64>> {
    if !f.is_nan() {
        Some(unsafe { NotNan::new_unchecked(f) })
    } else {
        None
    }
}

/// `f.is_nan()` early-return — finite on the fall-through.
fn guarded_is_nan_early_return(f: f64) -> Option<NotNan<f64>> {
    if f.is_nan() { return None; }
    Some(unsafe { NotNan::new_unchecked(f) })
}

/// `f.is_finite()` guard — explicitly finite on the then-edge.
fn guarded_is_finite(f: f64) -> Option<NotNan<f64>> {
    if f.is_finite() {
        Some(unsafe { NotNan::new_unchecked(f) })
    } else {
        None
    }
}

fn main() {
    println!("{:?} {:?} {:?}",
        guarded_not_nan(1.0),
        guarded_is_nan_early_return(2.0),
        guarded_is_finite(3.0));
}
