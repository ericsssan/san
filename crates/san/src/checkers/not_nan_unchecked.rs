/// Detects calls to `ordered_float::NotNan::new_unchecked` and
/// `noisy_float::NoisyFloat::unchecked_new`.
///
/// `NotNan<T>` and `NoisyFloat<T, C>` are wrapper types that implement a total
/// ordering over floats by asserting the wrapped value is never NaN. All trait
/// implementations (`Ord`, `Eq`, `Hash`, `PartialOrd`) rely on this invariant.
///
/// `NotNan::new_unchecked(val)`:
///   • Wraps `val` without checking `val.is_nan()`
///   • If `val` is NaN, the resulting `NotNan` violates the `Ord`/`Eq`/`Hash` contracts:
///     — `a == a` returns `false` (NaN != NaN), breaking reflexivity of `Eq`
///     — `a.cmp(&b)` returns inconsistent results, making sort results arbitrary
///     — `HashMap` or `BTreeMap` keys may become permanently inaccessible
///   • These violations cause UB in the mathematical sense (broken contract) and
///     may produce logical corruption, infinite loops, or panics in BTreeMap
///
/// `NoisyFloat::unchecked_new(val)`:
///   • Bypasses the checker closure that enforces the float validity invariant
///   • If the value is invalid per the checker, subsequent arithmetic operations
///     may propagate the invalid value silently
///
/// Safe alternatives:
///   • `NotNan::new(val).unwrap()` — panics on NaN
///   • `NotNan::new(val).ok_or(Error)` — returns an error on NaN
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NotNanUnchecked;

impl Checker for NotNanUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.contains("ordered_float")
                && path.ends_with("::new_unchecked")
            {
                (
                    "NotNan::new_unchecked",
                    "value must not be NaN; if it is, the resulting NotNan violates the Ord, \
                     Eq, and Hash contracts — sort results are undefined, BTreeMap/HashMap keys \
                     may become permanently unreachable; use NotNan::new (returns Result) instead",
                )
            } else if path.contains("noisy_float") && path.ends_with("::unchecked_new") {
                (
                    "NoisyFloat::unchecked_new",
                    "bypasses the validity checker closure; if the value is invalid per the \
                     checker, arithmetic operations will propagate the invalid state silently; \
                     use NoisyFloat::new (runs the checker) instead",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "not_nan_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
