/// Detects `Layout::from_size_align_unchecked(size, _)` where `size` was
/// produced by an integer multiplication or addition whose result can exceed
/// `isize::MAX` without an overflow check.
///
/// **Why this is dangerous**: `Layout::from_size_align_unchecked` requires that
/// `size` fits in `isize` (i.e. ≤ `isize::MAX`). When `size = n * size_of::<T>()`
/// wraps on overflow, the allocator silently receives a small size. Subsequent
/// writes based on the intended (large) count overflow the allocation, producing
/// a heap buffer overflow — the most common class of allocator arithmetic CVEs.
///
/// **Suppression**: fires only when the size argument is in `BlockState::mul_overflow`,
/// meaning the analysis could not prove the product/sum ≤ `isize::MAX`. If both
/// operands have proven upper bounds whose product ≤ `isize::MAX`, the finding is
/// automatically suppressed (the multiplication is safe).
///
/// **Safe alternatives**:
///   • `Layout::array::<T>(n)` — performs the overflow check and returns `Result`
///   • `n.checked_mul(size_of::<T>())` then `Layout::from_size_align_unchecked`
///   • `Layout::from_size_align` — validates both constraints, returns `Result`
///
/// Common CVE patterns: bumpalo size overflow, smallvec capacity-doubling overflow,
/// custom allocator wrappers using `n * elem_size` without `checked_mul`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AllocSizeOverflow;

impl Checker for AllocSizeOverflow {
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
            if !path.ends_with("Layout::from_size_align_unchecked")
                && !path.ends_with("Layout::from_size_alignment_unchecked")
            {
                continue;
            }

            // The first argument is the `size` parameter.
            let size_local = match args.first().map(|a| &a.node) {
                Some(Operand::Move(p) | Operand::Copy(p)) if p.projection.is_empty() => p.local,
                _ => continue,
            };

            let Some(state) = flow.state_before_terminator(tcx, body, bb) else { continue };

            if state.mul_overflow.contains(&size_local) {
                findings.push(Finding {
                    rule_id: "alloc_size_overflow",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: "`Layout::from_size_align_unchecked` — size argument came from \
                              arithmetic (mul/add) that can exceed isize::MAX without overflow \
                              check; wrapping produces a too-small allocation and heap overflow \
                              on subsequent writes; use `Layout::array::<T>(n)` or \
                              `n.checked_mul(size_of::<T>())` to handle overflow safely"
                        .to_string(),
                });
            }
        }

        findings
    }
}
