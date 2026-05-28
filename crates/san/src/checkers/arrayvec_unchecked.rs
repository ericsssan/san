/// Detects `arrayvec::ArrayVec::into_inner_unchecked` — converts an `ArrayVec`
/// into a fixed-size array without checking that the vector is fully populated.
///
/// `ArrayVec::into_inner_unchecked(self) -> [T; CAP]`:
///   • Returns ownership of the backing array as `[T; CAP]`
///   • Safety requirement: `self.len() == CAP` — the vector must be completely
///     full; every element slot must hold an initialized `T`
///   • If `len < CAP`, the trailing `CAP - len` slots are still `MaybeUninit<T>`;
///     reading them as initialized `T` is undefined behavior (type confusion,
///     uninitialized memory)
///   • The safe alternative is `into_inner()` which returns `Err(self)` if
///     the vector is not full
///
/// Common bugs:
///   • Calling after a `truncate` or `remove` that reduced the length below CAP
///   • Filling from an external source (network, file) and calling
///     `into_inner_unchecked` before verifying the full CAP bytes were received
///   • Using it in generic code where CAP is a type parameter — the caller
///     may not always guarantee the vector is full
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ArrayvecUnchecked;

impl Checker for ArrayvecUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if path.ends_with("::into_inner_unchecked") && path.contains("arrayvec") {
                findings.push(Finding {
                    rule_id: "arrayvec_unchecked",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`ArrayVec::into_inner_unchecked` — the vector must be completely \
                              full (len == CAP) before calling; trailing uninitialized slots \
                              become uninitialized `T` values in the returned array (UB); \
                              use `into_inner()` for the checked version"
                        .to_string(),
                });
            }
        }

        findings
    }
}
