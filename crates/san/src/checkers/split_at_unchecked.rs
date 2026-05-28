/// Detects calls to `<[T]>::split_at_unchecked` and
/// `<[T]>::split_at_mut_unchecked` (stable since Rust 1.79).
///
/// The checked counterparts (`split_at`, `split_at_mut`) perform a bounds check
/// and panic if `mid >= self.len()`. The unchecked variants skip that check.
///
/// The caller must guarantee:
///   • `mid <= self.len()` — if mid is out of bounds, both returned references
///     will have overlapping or nonsensical memory ranges, and accessing elements
///     past the original slice end is an out-of-bounds read (UB)
///   • For `split_at_mut_unchecked`: the standard borrow checker rules apply —
///     no other references to any part of the slice may exist during the mutable
///     borrow (the function itself cannot enforce this beyond the split point)
///
/// Common bugs: computing `mid` from an unvalidated user input or an external
/// protocol field, then passing it directly without checking the length first.
///
/// Safe alternatives: `split_at` and `split_at_mut` (both check the index and
/// return a panic on failure), or `split_at_checked` which returns `Option`.
///
/// Stable since Rust 1.79.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SplitAtUnchecked;

impl Checker for SplitAtUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("split_at_mut_unchecked") {
                (
                    "split_at_mut_unchecked",
                    "mid must be <= self.len(); out-of-bounds mid produces overlapping \
                     mutable references whose ranges extend past the allocation (UB); \
                     use `split_at_mut` or `split_at_mut_checked` instead",
                )
            } else if path.ends_with("split_at_unchecked") {
                (
                    "split_at_unchecked",
                    "mid must be <= self.len(); out-of-bounds mid creates a reference \
                     that extends past the allocation (OOB read UB); \
                     use `split_at` or `split_at_checked` instead",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "split_at_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
