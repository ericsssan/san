/// Detects unsafe operations on `bitvec` types that skip bounds or invariant checks.
///
/// **Index/position constructors** (skip range validation):
///   • `BitIdx::new_unchecked(idx)` — idx must be < T::BITS; OOB crosses storage words (UB)
///   • `BitPos::new_unchecked(pos)` — pos must be < T::BITS; OOB is UB
///   • `BitSel::new_unchecked(sel)` — sel must be one-hot; multi-bit violates invariant
///
/// **Slice mutation without bounds checks**:
///   • `BitSlice::set_unchecked(index, value)` — sets a bit without checking index < len (UB)
///   • `BitSlice::replace_unchecked(index, value)` — replaces a bit without bounds check (UB)
///   • `BitSlice::copy_within_unchecked(src, dest)` — copies bits without checking ranges (UB)
///   • `BitSlice::set_aliased_unchecked(index, value)` — concurrent access without atomics (data race)
///
/// **Slice construction without length/alignment checks**:
///   • `BitSlice::from_slice_unchecked(slice)` — caller must ensure slice.len() * T::BITS <= isize::MAX
///   • `BitSlice::from_slice_unchecked_mut(slice)` — same, mutable variant
///   • `bitvec::slice::from_raw_parts_unchecked(ptr, len)` — ptr must be a valid BitPtr,
///     len must be in-bounds; violating either is immediate UB
///   • `bitvec::slice::from_raw_parts_unchecked_mut(ptr, len)` — same, mutable variant
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BitvecUnchecked;

impl Checker for BitvecUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("bitvec") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::set_unchecked") && path.contains("BitSlice") {
                (
                    "BitSlice::set_unchecked",
                    "sets a bit without checking that index < self.len(); out-of-bounds access \
                     writes into adjacent storage words (UB); use index-checked bit assignment instead",
                )
            } else if path.ends_with("::replace_unchecked") && path.contains("BitSlice") {
                (
                    "BitSlice::replace_unchecked",
                    "replaces a bit without checking that index < self.len(); out-of-bounds access \
                     is immediate UB; use the checked replace() method instead",
                )
            } else if path.ends_with("::copy_within_unchecked") {
                (
                    "BitSlice::copy_within_unchecked",
                    "copies bits within the slice without verifying that src and dest ranges are \
                     in-bounds; out-of-bounds access is UB; use copy_within() for checked variant",
                )
            } else if path.ends_with("::set_aliased_unchecked") {
                (
                    "BitSlice::set_aliased_unchecked",
                    "writes to a shared bit without atomic operations; concurrent access from \
                     multiple threads is a data race (UB); ensure exclusive access or use \
                     atomic storage types",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "bitvec_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
