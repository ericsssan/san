/// Detects calls to `ptr::drop_in_place`.
///
/// `ptr::drop_in_place` runs the destructor for the value pointed-to without
/// freeing the memory. The caller must:
///   • Ensure the pointer is non-null and properly aligned for T
///   • Ensure the pointed-to value is valid and initialized
///   • Ensure this is the only drop — calling it twice is a double-free
///   • When used inside a loop (e.g. to drain a Vec), use a DropGuard to reset
///     the length BEFORE the loop, so a panic mid-drop doesn't leave a dangling
///     length that causes elements to be dropped again on collection teardown
///
/// Panic-safety pattern: the double-free caused by missing DropGuard when
/// element drops can panic has been independently rediscovered in thin-vec
/// (RUSTSEC-2026-0103), rkyv (RUSTSEC-2026-0122), id-map (RUSTSEC-2021-0052),
/// and dozens of other custom collection implementations.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrDropInPlace;

impl Checker for PtrDropInPlace {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let fn_name = if path.ends_with("ptr::drop_in_place") {
                "ptr::drop_in_place"
            } else if path.ends_with("::drop_in_place") && path.contains("NonNull") {
                "NonNull::drop_in_place"
            } else if path.ends_with("::drop_in_place")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                "ptr::drop_in_place"
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_drop_in_place",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — ensure the pointer is valid and aligned, \
                     call it exactly once (double-drop if called twice), and use a \
                     DropGuard (reset len to 0 before the loop) if iterating to \
                     protect against double-free when element drops panic"
                ),
            });
        }

        findings
    }
}
