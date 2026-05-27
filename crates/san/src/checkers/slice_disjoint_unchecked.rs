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
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceDisjointUnchecked;

impl Checker for SliceDisjointUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("get_disjoint_unchecked_mut") || path.contains("HashMap") {
                continue;
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
