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
use crate::analysis::transfer::first_arg_local;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NonZeroNewUnchecked;

impl Checker for NonZeroNewUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, msg) = if path.ends_with("::new_unchecked") {
                (
                    path.rsplit("::").next().unwrap_or("new_unchecked"),
                    "the caller must satisfy the type's invariant; bypassing the checked \
                     constructor may produce an invalid value — immediate UB if the invariant \
                     is violated (e.g., zero for NonZero, NaN for NotNan wrapper types); \
                     use the checked constructor (returns Option/Result) instead",
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
            } else if path.ends_with("::unchecked_new") {
                (
                    path.rsplit("::").next().unwrap_or("unchecked_new"),
                    "the caller must satisfy the type's invariant (e.g., not NaN for float \
                     wrappers); an invalid value produces immediate UB; use the checked \
                     constructor (returns Option/Result) instead",
                )
            } else {
                continue;
            };

            // Suppress when the argument is proven ≠ 0 on all reaching paths
            // (e.g. guarded by `if n != 0`, `if n > 0`, `assert!(n != 0)`).
            // Only applies to new_unchecked/from_mut_unchecked — unchecked_add/mul
            // have overflow as an additional condition we cannot prove here.
            if path.ends_with("::new_unchecked")
                || path.ends_with("::from_mut_unchecked")
                || path.ends_with("::unchecked_new")
            {
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    if let Some(arg) = first_arg_local(args) {
                        // nonzero: `if n != 0` guards; finite: `if x.is_finite()` guards
                        if state.local_is_nonzero(arg) || state.local_is_finite(arg) {
                            continue;
                        }
                    }
                }
            }

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
