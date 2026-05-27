/// Detects calls to unchecked portable SIMD operations:
/// `Simd::gather_select_unchecked`, `Simd::scatter_select_unchecked`,
/// `Simd::load_select_unchecked`, `Simd::store_select_unchecked`,
/// `Simd::gather_ptr`, `Simd::gather_select_ptr`,
/// `Simd::load_select_ptr`, `Simd::scatter_ptr`, `Simd::scatter_select_ptr`,
/// `Mask::set_unchecked`, `Mask::test_unchecked`, and `Mask::from_simd_unchecked`.
/// (Nightly: `#![feature(portable_simd)]`)
///
/// Index-based unchecked operations (`gather_select_unchecked`, `scatter_select_unchecked`,
/// `load_select_unchecked`, `store_select_unchecked`):
///   • For every active lane (where enable[i] is true), the index or lane offset must
///     be within bounds of the slice (< slice.len()); out-of-bounds reads/writes are UB
///   • For scatter variants: active indices must be unique (aliased &mut writes are UB)
///
/// Raw-pointer operations (`gather_ptr`, `gather_select_ptr`, `load_select_ptr`,
/// `scatter_ptr`, `scatter_select_ptr`):
///   • Each active pointer lane must be non-null, properly aligned for T, and valid for
///     read/write; dangling or unaligned pointers are UB
///   • For scatter variants: all active destination pointers must be unique
///
/// Mask operations:
///   • `set_unchecked` / `test_unchecked`: index must be < lane_count (OOB is UB)
///   • `from_simd_unchecked`: every lane must be 0 (false) or -1/all-bits-set (true);
///     any other value produces an invalid mask that corrupts subsequent mask operations
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SimdUnchecked;

impl Checker for SimdUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::gather_select_unchecked")
                && path.contains("simd")
            {
                (
                    "Simd::gather_select_unchecked",
                    "every active lane index (where enable[i] is true) must be < slice.len(); \
                     out-of-bounds active index reads arbitrary memory (UB); \
                     use Simd::gather_or for the bounds-checked version",
                )
            } else if path.ends_with("::scatter_select_unchecked")
                && path.contains("simd")
            {
                (
                    "Simd::scatter_select_unchecked",
                    "every active lane index (where enable[i] is true) must be < slice.len() \
                     and all active indices must be unique (aliased writes are UB); \
                     use Simd::scatter for the bounds-checked version",
                )
            } else if path.ends_with("::load_select_unchecked") && path.contains("simd") {
                (
                    "Simd::load_select_unchecked",
                    "for every enabled lane i, lane i is read from slice[i]; i must be < \
                     slice.len() for all active lanes — out-of-bounds reads arbitrary memory (UB); \
                     use Simd::load_select for the bounds-checked version",
                )
            } else if path.ends_with("::store_select_unchecked") && path.contains("simd") {
                (
                    "Simd::store_select_unchecked",
                    "for every enabled lane i, lane i is written to slice[i]; i must be < \
                     slice.len() for all active lanes — out-of-bounds writes arbitrary memory (UB); \
                     use Simd::store_select for the bounds-checked version",
                )
            } else if path.ends_with("::gather_ptr") && path.contains("simd") {
                (
                    "Simd::gather_ptr",
                    "every pointer lane must be non-null, properly aligned for T, and valid \
                     for a read of size_of::<T>() bytes; a dangling or unaligned pointer in any \
                     lane is immediate UB",
                )
            } else if path.ends_with("::gather_select_ptr") && path.contains("simd") {
                (
                    "Simd::gather_select_ptr",
                    "every active (mask=true) pointer lane must be non-null, properly aligned for T, \
                     and valid for a read; inactive lanes read from the fallback — only the active \
                     pointers need validity",
                )
            } else if path.ends_with("::load_select_ptr") && path.contains("simd") {
                (
                    "Simd::load_select_ptr",
                    "the base pointer must be non-null, properly aligned for T, and valid for \
                     lane_count reads; for inactive lanes the fallback is used — only the active \
                     lane positions within the array need to be valid",
                )
            } else if path.ends_with("::scatter_ptr") && path.contains("simd") {
                (
                    "Simd::scatter_ptr",
                    "every pointer lane must be non-null, properly aligned for T, valid for \
                     writes, and all destination pointers must be distinct (aliased mutable \
                     writes to the same address are UB)",
                )
            } else if path.ends_with("::scatter_select_ptr") && path.contains("simd") {
                (
                    "Simd::scatter_select_ptr",
                    "every active (mask=true) pointer lane must be non-null, properly aligned for T, \
                     valid for writes, and all active destination pointers must be distinct; \
                     inactive lanes are ignored",
                )
            } else if path.ends_with("::set_unchecked") && path.contains("Mask") {
                (
                    "Mask::set_unchecked",
                    "index must be < mask.len() (the number of lanes); an out-of-bounds \
                     index writes past the end of the mask's internal storage — immediate UB; \
                     use Mask::set (bounds-checked, panics on OOB) instead",
                )
            } else if path.ends_with("::test_unchecked") && path.contains("Mask") {
                (
                    "Mask::test_unchecked",
                    "index must be < mask.len() (the number of lanes); an out-of-bounds \
                     index reads past the end of the mask's internal storage — immediate UB; \
                     use Mask::test (bounds-checked, panics on OOB) instead",
                )
            } else if path.ends_with("::from_simd_unchecked") && path.contains("Mask") {
                (
                    "Mask::from_simd_unchecked",
                    "every lane in the source Simd must be exactly 0 (false) or -1/all-bits-set \
                     (true); any other value produces an invalid mask — subsequent operations that \
                     read this mask may miscompile or produce wrong results",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "simd_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
