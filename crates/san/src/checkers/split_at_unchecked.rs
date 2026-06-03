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
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
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

            // Suppress when mid is proven <= self.len() on all predecessor paths.
            // split_at_unchecked(self, mid) — mid is args[1].
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(mid_local) = args.get(1).and_then(|a| {
                    use rustc_middle::mir::Operand;
                    match &a.node {
                        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                        _ => None,
                    }
                }) {
                    if state.local_is_bounded_or_eq(mid_local) {
                        continue;
                    }
                }
            }

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
