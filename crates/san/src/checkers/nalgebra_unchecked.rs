/// Detects calls to unsafe mathematical operations in the `nalgebra` crate that
/// bypass invariant checks:
///   • `Rotation::matrix_mut_unchecked()` — mutable access to the rotation matrix
///     without enforcing the rotation invariant (orthogonality + det == 1)
///   • `Scale::inverse_unchecked()` — computes the inverse scale without verifying
///     that no scale factor is zero (division by zero for the zero component)
///   • `MatrixView::from_slice_unchecked(data, start)` — creates a matrix view into
///     a slice without checking that `start + rows * cols <= data.len()`
///   • `MatrixView::from_slice_with_strides_unchecked(data, start, rstride, cstride)` —
///     same but with explicit memory strides; misaligned strides read arbitrary memory
///
/// **`Rotation::matrix_mut_unchecked()`**:
///   • The underlying storage is a square matrix that must remain orthogonal with
///     determinant +1 at all times; mutating the matrix directly can break this
///     invariant, causing all subsequent rotation operations (inverse, composition,
///     `transform_point`) to produce geometrically incorrect results silently
///
/// **`Scale::inverse_unchecked()`**:
///   • If any diagonal component is zero, `1 / component = infinity` (for floats)
///     or division-by-zero panic/UB (for integer-backed types); the caller must
///     ensure all scale factors are non-zero before calling this method
///
/// **`from_slice_unchecked` / `from_slice_with_strides_unchecked`**:
///   • Constructs a matrix view backed by a slice without performing bounds checks;
///     if `start + size` exceeds the slice length, subsequent element access reads
///     memory beyond the slice boundary (out-of-bounds read → UB)
///   • For the strides variant: strides that cause elements to be mapped beyond
///     the slice also produce UB
///
/// Common bugs: building a rotation matrix by composing raw component writes without
/// re-normalizing (a common 3D graphics mistake), computing a transform inverse in a
/// tight loop without checking for degenerate zero-scale inputs.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NalgebraUnchecked;

impl Checker for NalgebraUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("nalgebra") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::matrix_mut_unchecked") {
                (
                    "Rotation::matrix_mut_unchecked",
                    "direct mutable access bypasses the rotation invariant (orthogonal matrix, \
                     det = +1); modifying the matrix can silently corrupt all subsequent \
                     rotation operations (inverse, composition, point transformation)",
                )
            } else if path.ends_with("::inverse_unchecked") && path.contains("Scale") {
                (
                    "Scale::inverse_unchecked",
                    "all scale factors must be non-zero; a zero component produces \
                     `1/0 = infinity` for float types or a panic for integer-backed types; \
                     validate all components before calling",
                )
            } else if path.ends_with("::from_slice_with_strides_unchecked") {
                (
                    "MatrixView::from_slice_with_strides_unchecked",
                    "slice bounds and stride arithmetic are not checked; if any element \
                     address (start + row*rstride + col*cstride) falls outside the slice, \
                     the read is an out-of-bounds access (UB)",
                )
            } else if path.ends_with("::from_slice_unchecked") && path.contains("nalgebra") {
                (
                    "MatrixView::from_slice_unchecked",
                    "slice length is not checked; if start + rows*cols > data.len(), \
                     the view reads beyond the slice boundary (out-of-bounds UB)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "nalgebra_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
