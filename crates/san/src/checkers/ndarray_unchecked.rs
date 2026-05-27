/// Detects calls to unsafe ndarray operations: `ArrayBase::uget`, `ArrayBase::uget_mut`,
/// `ArrayBase::uswap`, `ArrayBase::from_shape_vec_unchecked`, and
/// `ArrayView::from_shape_ptr` / `RawArrayView::from_shape_ptr`.
///
/// `ndarray` provides multi-dimensional array operations heavily used in
/// numerical computing. The `uget`/`uget_mut` methods return element references
/// without bounds checking.
///
/// `array.uget(index)` — returns `&T` at the given index without checking:
///   • Each index component must be < the corresponding array dimension
///   • Out-of-bounds index reads from memory past the array's allocation (UB)
///   • No check is made for slice views whose strides could make an in-bounds
///     computed offset actually point outside the backing allocation
///
/// `array.uget_mut(index)` — returns `&mut T` additionally requires:
///   • No other reference (shared or mutable) to the same element may exist
///     for the lifetime of the returned reference (aliasing &mut T is UB)
///   • In views created with `as_ptr`-based reconstruction, the caller must
///     ensure the view's element range is disjoint from any other mutable view
///
/// Common bugs:
///   • Transposed or reordered axis indices that are in-bounds but access
///     the wrong element (silently computes wrong results rather than UB,
///     but combined with other errors can produce OOB access)
///   • Dynamic shape arrays where the shape changes between the bounds check
///     and the `uget` call (TOCTOU on the shape)
///   • Parallel (rayon) iterations over overlapping sliced views that both
///     call `uget_mut` → data race (UB) even if the indices look distinct
///
/// Safe alternative: index via `array[[i, j]]` or `array.get(index)`
/// (returns `Option<&T>`).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NdarrayUnchecked;

impl Checker for NdarrayUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("ndarray") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::uget_mut") {
                (
                    "ArrayBase::uget_mut",
                    "each index component must be < the corresponding dimension; \
                     out-of-bounds index reads/writes outside the allocation (UB); \
                     additionally, no other reference to the same element may exist \
                     while this mutable reference is live (aliased &mut is UB); \
                     use array[[i, j]] for the checked panicking version",
                )
            } else if path.ends_with("::uget") {
                (
                    "ArrayBase::uget",
                    "each index component must be < the corresponding array dimension; \
                     out-of-bounds index reads memory past the array's allocation (UB); \
                     use array[[i, j]] or array.get(index) (returns Option<&T>)",
                )
            } else if path.ends_with("::uswap") {
                (
                    "ArrayBase::uswap",
                    "both index1 and index2 must be in-bounds for all dimensions; \
                     out-of-bounds index swaps memory outside the array allocation (UB); \
                     use array.swap(i, j) for the checked panicking version",
                )
            } else if path.ends_with("::from_shape_vec_unchecked") {
                (
                    "ArrayBase::from_shape_vec_unchecked",
                    "shape.size() must equal v.len(); if the shape product does not match \
                     the vector length, subsequent indexing reads outside the vec's allocation \
                     (out-of-bounds UB); use ArrayBase::from_shape_vec which returns Result",
                )
            } else if path.ends_with("::from_shape_ptr") && path.contains("ndarray") {
                (
                    "ArrayView::from_shape_ptr",
                    "ptr must point to a contiguous allocation of at least shape.size() elements \
                     of type A; the shape and strides must not produce index addresses outside \
                     the pointed-to allocation (OOB read UB); no safe alternative — \
                     validate layout manually before calling",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ndarray_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
