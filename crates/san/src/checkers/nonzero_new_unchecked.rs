/// Detects calls to `NonZero::new_unchecked`, the type-specific variants
/// (`NonZeroU8::new_unchecked`, `NonZeroUsize::new_unchecked`, etc.),
/// `NonZero::from_mut_unchecked` (nightly `#![feature(nonzero_from_mut)]`),
/// `NonZero::unchecked_add`, and `NonZero::unchecked_mul`
/// (nightly `#![feature(nonzero_ops)]`).
///
/// `NonZero<T>::new_unchecked(n)` creates a non-zero integer without checking
/// for zero. The caller must guarantee:
///   • `n != 0` — passing zero is immediate undefined behaviour
///
/// NonZero types are niche-optimized: `Option<NonZeroU32>` has the same size as
/// `u32`, using 0 as the None discriminant. Passing zero to `new_unchecked`
/// creates a `NonZeroU32` with value zero, corrupting the niche and causing
/// `None` and `Some(NonZeroU32::new_unchecked(0))` to have the same bit pattern.
///
/// `NonZero::unchecked_add(self, rhs: T) -> NonZero<T>`:
///   • The sum `self + rhs` must not overflow T (wrapping to any value including zero is UB)
///   • The result must be non-zero (if rhs is negative and cancels self, result is zero = UB)
///
/// `NonZero::unchecked_mul(self, rhs: NonZero<T>) -> NonZero<T>`:
///   • The product must not overflow T — overflow that wraps to zero breaks the NonZero
///     invariant and corrupts the Option<NonZero<T>> niche
///
/// The safe alternative is `NonZero::new` which returns `Option<NonZero<T>>`.
///
/// Common bugs: integer computations that should never be zero but can be in
/// edge cases (empty collections, overflows), values from FFI that may be zero.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NonZeroNewUnchecked;

impl Checker for NonZeroNewUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            // Matches NonZeroU8::new_unchecked, NonZeroUsize::new_unchecked, etc.
            // and the new unified NonZero::<T>::new_unchecked / from_mut_unchecked forms.
            if !path.contains("NonZero") {
                continue;
            }

            let (fn_name, msg) = if path.ends_with("::new_unchecked") {
                (
                    "NonZero::new_unchecked",
                    "passing zero is UB (corrupts niche optimization, breaks \
                     Option<NonZero<T>> discriminant); use `NonZero::new` (returns Option) \
                     unless zero is provably impossible",
                )
            } else if path.ends_with("::from_mut_unchecked") {
                (
                    "NonZero::from_mut_unchecked",
                    "caller must ensure the value is never set to zero through the returned \
                     `&mut NonZero<T>`; if zero is written, the NonZero invariant is broken \
                     and all subsequent uses that rely on the niche (e.g. Option<NonZero<T>>) \
                     are UB; use `NonZero::from_mut` for the checked version (nightly)",
                )
            } else if path.ends_with("::unchecked_add") {
                (
                    "NonZero::unchecked_add",
                    "self + rhs must not overflow T and must not produce zero; overflow or a \
                     zero result breaks the NonZero invariant and corrupts the \
                     Option<NonZero<T>> niche (UB); use checked_add or saturating_add instead \
                     (nightly `nonzero_ops`)",
                )
            } else if path.ends_with("::unchecked_mul") {
                (
                    "NonZero::unchecked_mul",
                    "self * rhs must not overflow T; overflow that wraps to zero breaks the \
                     NonZero invariant and corrupts the Option<NonZero<T>> niche (UB); \
                     use checked_mul or saturating_mul instead (nightly `nonzero_ops`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "nonzero_new_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {msg}"),
            });
        }

        findings
    }
}
