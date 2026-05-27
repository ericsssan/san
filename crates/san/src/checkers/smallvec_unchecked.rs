/// Detects calls to `SmallVec::from_buf_and_len_unchecked` from the `smallvec` crate.
///
/// `SmallVec::from_buf_and_len_unchecked(buf, len)` constructs a SmallVec from a
/// `MaybeUninit<A>` buffer and a length without checking that `len <= A::size()`.
///
/// The caller must guarantee:
///   • `len <= A::size()` — exceeding the inline buffer capacity creates a SmallVec
///     whose stored length is larger than its actual inline capacity; any subsequent
///     access (push, pop, index, drop) reads or writes past the end of the stack array
///   • All elements in `buf[0..len]` must be fully initialized; accessing uninitialized
///     bytes through the SmallVec is immediate UB (invalid bit patterns, wrong Drop impls)
///
/// SmallVec has a history of soundness issues (RUSTSEC-2019-0012 double-free, overflow
/// in grow). This unchecked constructor bypasses the only capacity check that prevents
/// OOB memory corruption in the inline-storage path.
///
/// Safe alternative: `SmallVec::from_buf_and_len` which panics on len > capacity.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SmallVecUnchecked;

impl Checker for SmallVecUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("smallvec") || !path.ends_with("::from_buf_and_len_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "smallvec_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`SmallVec::from_buf_and_len_unchecked` — len must be ≤ the inline \
                          buffer capacity (A::size()); exceeding it causes OOB reads/writes on \
                          every subsequent SmallVec operation; all buf[0..len] elements must be \
                          initialized; use `from_buf_and_len` (panics on overflow) instead"
                    .to_string(),
            });
        }

        findings
    }
}
