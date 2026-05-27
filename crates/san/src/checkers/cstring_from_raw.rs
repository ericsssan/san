/// Detects calls to `CString::from_raw`.
///
/// `CString::from_raw(ptr)` retakes ownership of a `CString` that was previously
/// released via `CString::into_raw`. The caller must guarantee:
///   • `ptr` was obtained from `CString::into_raw` using the same allocator that
///     backs the current `CString` — typically the global Rust allocator; passing
///     a pointer from C's `malloc` or a different allocator causes a mismatched-
///     allocator free, which is UB or a crash
///   • The pointer has not been modified between `into_raw` and `from_raw`;
///     in particular, no byte after the original nul terminator should have been
///     written and the nul terminator must still be present; changing the layout
///     (e.g. by appending bytes) corrupts the allocation metadata
///   • `from_raw` is called **exactly once** per `into_raw` call;
///     calling it twice on the same pointer double-frees the allocation;
///     not calling it at all leaks memory
///   • The pointer must not be used after `from_raw` reconstitutes the `CString`
///     (use-after-free if the CString is subsequently dropped)
///
/// Common bugs: round-tripping through C code that modifies the buffer or
/// reallocates it, losing track of whether the pointer has been reclaimed,
/// or failing to call `from_raw` after passing the pointer over FFI.
///
/// Pattern: always pair `into_raw` with `from_raw` within the same allocator
/// context, and document the ownership transfer at every FFI boundary.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CStringFromRaw;

impl Checker for CStringFromRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("CString::from_raw") {
                continue;
            }

            findings.push(Finding {
                rule_id: "cstring_from_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`CString::from_raw` — ptr must have been obtained from \
                          `CString::into_raw` with the same allocator; do not call twice \
                          (double-free); do not use ptr after this call (use-after-free); \
                          buffer must be unmodified with nul terminator intact"
                    .to_string(),
            });
        }

        findings
    }
}
