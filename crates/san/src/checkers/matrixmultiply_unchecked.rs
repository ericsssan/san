/// Detects calls to `matrixmultiply::sgemm`, `dgemm`, `cgemm`, and `zgemm`:
/// raw BLAS-style matrix-matrix multiply functions (single/double/complex precision).
///
/// These functions compute `C = alpha * op(A) * op(B) + beta * C` using raw
/// pointer arithmetic. They are unsafe because no bounds checking is performed:
///   • `a` must point to a contiguous array of at least `m * k` elements
///     with layout defined by `rsa` (row stride) and `csa` (column stride)
///   • `b` must point to at least `k * n` elements with strides `rsb`, `csb`
///   • `c` must point to at least `m * n` elements with strides `rsc`, `csc`
///   • Strides must produce valid in-bounds addresses for all element accesses
///   • Any mismatch between the declared dimensions/strides and the actual
///     allocation sizes causes out-of-bounds reads or writes (UB)
///
/// Typical mistakes:
///   • Swapping row-major and column-major strides (stride 1 and stride N
///     inverted for the array's actual layout)
///   • Passing a submatrix view with strides that place rows outside the parent
///     allocation
///   • Using `m/n/k = 0` without checking — not necessarily UB but often a bug
///   • Column-vector matrix arguments where a caller erroneously passes stride 0
///     (stride 0 means all rows alias the same row; writing to C with stride 0
///     produces nonsensical results)
///
/// `matrixmultiply` is used internally by `ndarray` and `nalgebra` for
/// high-performance BLAS kernels. Direct use by application code is rare but
/// possible when building custom numeric kernels.
///
/// Safe alternatives: use `ndarray::linalg::dot`, `nalgebra::Matrix::mul`, or
/// the `blas`/`cblas` crates which often provide safer wrappers.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MatrixmultiplyUnchecked;

impl Checker for MatrixmultiplyUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("matrixmultiply") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::sgemm") || path == "matrixmultiply::sgemm" {
                (
                    "sgemm (f32)",
                    "all pointer arguments must point to valid allocations of the declared size; \
                     incorrect dimensions or strides cause OOB reads/writes (UB); \
                     verify layout (row-major vs column-major) before calling",
                )
            } else if path.ends_with("::dgemm") || path == "matrixmultiply::dgemm" {
                (
                    "dgemm (f64)",
                    "all pointer arguments must point to valid allocations; \
                     incorrect strides or dimensions produce OOB reads/writes (UB)",
                )
            } else if path.ends_with("::cgemm") || path == "matrixmultiply::cgemm" {
                (
                    "cgemm (c32)",
                    "complex single-precision GEMM; each complex element is 2 floats; \
                     pointers must be valid for m*k, k*n, m*n complex elements respectively",
                )
            } else if path.ends_with("::zgemm") || path == "matrixmultiply::zgemm" {
                (
                    "zgemm (c64)",
                    "complex double-precision GEMM; pointers must be valid for m*k, k*n, m*n \
                     complex double elements; incorrect strides produce OOB reads/writes (UB)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "matrixmultiply_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
