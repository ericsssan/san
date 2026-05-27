/// Detects unsafe operations on `slotmap` arena maps:
/// `get_disjoint_unchecked_mut` across all map types.
///
/// `SlotMap::get_disjoint_unchecked_mut<const N>([k1, …]) -> [&mut V; N]`
/// (also `DenseSlotMap`, `HopSlotMap`, `SecondaryMap`, `SparseSecondaryMap`):
///   • Returns N simultaneous mutable references without checking:
///     1. That all N keys are valid and occupied (dead key → dangling or UB)
///     2. That all N keys are pairwise distinct — duplicate keys produce
///        aliased `&mut V` references (immediate UB)
///   • Slotmap keys encode a generation counter; a key is valid only for
///     the generation it was issued in — a stale key from before a `remove`
///     and re-`insert` is rejected by the safe API but bypassed here
///
/// `SlotMap::get_unchecked` / `get_unchecked_mut`:
///   • Single-key variants that bypass the generation check
///   • Caught generically by the `slice_get_unchecked` rule
///
/// Common bugs:
///   • Passing duplicate keys to `get_disjoint_unchecked_mut` — the
///     generation-counter check that prevents this in safe code is skipped
///   • Using a stored key after the corresponding slot was removed and
///     reallocated (generation mismatch that would normally return None)
///
/// Safe alternatives: `slot_map.get_disjoint_mut([k1, k2])` (returns None on
/// invalid/duplicate keys), or sequential `get_mut` calls.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SlotmapUnchecked;

impl Checker for SlotmapUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("slotmap") {
                continue;
            }

            if path.ends_with("::get_disjoint_unchecked_mut") {
                findings.push(Finding {
                    rule_id: "slotmap_unchecked",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`get_disjoint_unchecked_mut` — all N keys must be valid occupied \
                              entries from the current generation and must be pairwise distinct; \
                              duplicate or stale keys produce aliased &mut references (immediate UB); \
                              use get_disjoint_mut() for the checked alternative"
                        .to_string(),
                });
            }
        }

        findings
    }
}
