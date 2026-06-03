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
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceSwapUnchecked;

impl Checker for SliceSwapUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("::swap_unchecked") {
                continue;
            }

            // Suppress when both indices are proven bounded (< slice.len()) on all paths.
            // swap_unchecked(self, a, b) — a is args[1], b is args[2].
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                let get_local = |idx: usize| {
                    args.get(idx).and_then(|a| match &a.node {
                        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                        _ => None,
                    })
                };
                let a_bounded = get_local(1).map_or(false, |l| state.local_is_bounded(l));
                let b_bounded = get_local(2).map_or(false, |l| state.local_is_bounded(l));
                if a_bounded && b_bounded {
                    continue;
                }
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
