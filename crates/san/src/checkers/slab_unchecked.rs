/// Detects `slab::Slab::get2_unchecked_mut` — returns two simultaneous mutable
/// references into a `Slab` without validating that the two keys are disjoint.
///
/// `Slab::get2_unchecked_mut(key1, key2) -> (&mut T, &mut T)`:
///   • Both keys must be valid occupied slab entries (not vacant)
///   • The keys must be different — if key1 == key2, the return value is
///     two aliased `&mut T` references to the same memory (immediate UB)
///   • Neither key may have been vacated since it was obtained
///   • The slab must not be modified (insert/remove) while the returned
///     references are live
///
/// `Slab::get_unchecked` and `Slab::get_unchecked_mut` (single-key variants):
///   • Key must be valid and occupied — accessing a vacant entry is UB
///   • These are caught generically by the `slice_get_unchecked` rule
///
/// Common bugs:
///   • Calling get2_unchecked_mut with key1 == key2 after a remove/reinsert
///     cycle that happens to produce the same key value
///   • Forgetting that slab keys are reused after `remove` — a stale key
///     silently points to whatever new value was inserted at that slot
///
/// Safe alternatives: `slab.get_mut(key)` (returns Option, panics-free),
/// or split the borrows explicitly with sequential lookups.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SlabUnchecked;

impl Checker for SlabUnchecked {
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

            if !path.contains("slab") {
                continue;
            }

            if path.ends_with("::get2_unchecked_mut") {
                // Suppress when key1 ≠ key2 is proven (aliasing cannot occur).
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    let key = |idx: usize| args.get(idx).and_then(|a| match &a.node {
                        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => {
                            Some(p.local)
                        }
                        _ => None,
                    });
                    if let (Some(k1), Some(k2)) = (key(1), key(2)) {
                        if state.locals_are_ne(k1, k2) {
                            continue;
                        }
                    }
                }

                findings.push(Finding {
                    rule_id: "slab_unchecked",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`Slab::get2_unchecked_mut` — both keys must be valid occupied \
                              entries and must be different; equal keys produce aliased &mut T \
                              (immediate UB); stale keys (after remove) silently alias a \
                              reallocated entry"
                        .to_string(),
                });
            }
        }

        findings
    }
}
