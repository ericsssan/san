/// Detects calls to `<[T]>::get_disjoint_unchecked_mut` (stable since Rust 1.87).
///
/// `get_disjoint_unchecked_mut([i, j, ...])` returns N simultaneous mutable
/// references into the slice at the specified indices. The checked version
/// (`get_disjoint_mut`) returns `Err` if any index is out of bounds or if
/// any two indices are equal. The unchecked variant skips both checks.
///
/// The caller must guarantee:
///   • All indices are within `[0, self.len())` — an out-of-bounds index
///     creates a reference to memory past the end of the slice's allocation
///     (OOB write/read UB)
///   • All indices are pairwise distinct — duplicate indices yield two `&mut T`
///     references to the same memory location, which is aliased `&mut T` (UB);
///     the optimizer exploits the noalias annotation and may miscompile both uses
///
/// Common bugs: constructing indices from user input or computed offsets without
/// bounds-checking, accidentally duplicating an index (e.g. when building index
/// arrays programmatically).
///
/// Safe alternative: `<[T]>::get_disjoint_mut` (stable since Rust 1.87), which
/// returns `Err(GetDisjointMutError)` on bounds or overlap violations.
///
/// Stable since Rust 1.87.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceDisjointUnchecked;

impl Checker for SliceDisjointUnchecked {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            // Only the slice primitive implementation; not HashMap, slotmap, etc.
            // (those have dedicated checkers with their own suppression logic).
            if !path.ends_with("get_disjoint_unchecked_mut")
                || path.contains("HashMap")
                || path.contains("slotmap")
            {
                continue;
            }

            // Suppress when all index components are provably in-bounds AND
            // pairwise distinct: `if i < len && j < len && i != j { ... }`.
            // arg[0] = &mut self (the slice); arg[1] = [i, j, ...] index array.
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(arr_local) = args.get(1).and_then(|a| match &a.node {
                    Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => {
                        Some(p.local)
                    }
                    _ => None,
                }) {
                    if let Some(components) = state.array_components_of(arr_local) {
                        if !components.is_empty() {
                            let all_bounded = components.iter().all(|&c| state.index_is_fully_bounded(c));
                            let all_ne = components.len() <= 1
                                || components.iter().enumerate().all(|(i, &a)| {
                                    components[..i].iter().all(|&b| state.locals_are_ne(a, b))
                                });
                            if all_bounded && all_ne {
                                continue;
                            }
                        }
                    }
                }
            }

            findings.push(Finding {
                rule_id: "slice_disjoint_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`get_disjoint_unchecked_mut` — all indices must be in-bounds \
                          (< slice.len()) and pairwise distinct; duplicate indices produce \
                          aliased `&mut T` references (immediate UB); use \
                          `get_disjoint_mut` for the checked version"
                    .to_string(),
            });
        }

        findings
    }
}
