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
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SlabUnchecked;

impl Checker for SlabUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("slab") {
                continue;
            }

            if path.ends_with("::get2_unchecked_mut") {
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
