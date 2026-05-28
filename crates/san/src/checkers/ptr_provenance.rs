/// Detects calls to `ptr::with_exposed_provenance` and
/// `ptr::with_exposed_provenance_mut` (stable since Rust 1.84).
///
/// These functions reconstruct a raw pointer from an integer address using
/// "exposed provenance" — a model that allows pointer-integer-pointer round-trips
/// at the cost of disabling some pointer-aliasing optimizations.
///
/// The caller must guarantee ALL of the following:
///   • The integer `addr` was obtained from `ptr::expose_provenance(p)` for some
///     pointer `p` that is still live and has the expected type
///   • The original pointer `p` must still be valid (not dangling, not freed)
///   • The reconstructed pointer must respect the original pointer's aliasing rules
///   • The integer must not have come from `ptr::without_provenance` or from
///     arithmetic on an arbitrary integer — doing so produces a pointer with no
///     attached provenance that may not be safely dereferenced
///
/// Using `with_exposed_provenance` with an integer that does not have valid
/// provenance is immediate undefined behaviour.
///
/// Prefer:
///   • `NonNull::new` + keeping the pointer as `*const T` instead of converting
///     through integers if possible
///   • `ptr::from_ref` / `ptr::from_mut` for coercions that don't need integer round-trips
///
/// Stable since Rust 1.84 as part of the strict-provenance stabilization.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrProvenance;

impl Checker for PtrProvenance {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("ptr::with_exposed_provenance_mut") {
                (
                    "ptr::with_exposed_provenance_mut",
                    "address must have been obtained via `ptr::expose_provenance` on a \
                     live, valid *mut T; using an arbitrary integer or a non-exposed \
                     pointer address is immediate UB",
                )
            } else if path.ends_with("ptr::with_exposed_provenance") {
                (
                    "ptr::with_exposed_provenance",
                    "address must have been obtained via `ptr::expose_provenance` on a \
                     live, valid *const T; using an arbitrary integer or a non-exposed \
                     pointer address is immediate UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_provenance",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
