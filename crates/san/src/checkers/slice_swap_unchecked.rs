/// Detects calls to `<[T]>::swap_unchecked` (nightly feature `slice_swap_unchecked`).
///
/// `swap_unchecked(a, b)` exchanges the elements at indices `a` and `b` in-place
/// without performing any bounds checks. The caller must guarantee:
///   • `a < self.len()` and `b < self.len()` — if either index is out of bounds,
///     the function reads from or writes to memory past the end of the slice
///     allocation (out-of-bounds memory access UB)
///
/// Unlike `slice::swap` which panics on out-of-bounds, this variant silently
/// causes memory corruption when indices are invalid.
///
/// The safe alternative is `<[T]>::swap(a, b)` which checks both indices.
///
/// Nightly: `#![feature(slice_swap_unchecked)]`
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceSwapUnchecked;

impl Checker for SliceSwapUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::swap_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "slice_swap_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`swap_unchecked` — both indices a and b must be < slice.len(); \
                          out-of-bounds indices produce memory accesses past the end of the \
                          allocation (UB); use `slice::swap` for the bounds-checked version"
                    .to_string(),
            });
        }

        findings
    }
}
