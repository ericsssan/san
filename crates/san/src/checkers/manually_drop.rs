/// Detects calls to `ManuallyDrop::drop` and `ManuallyDrop::take`.
///
/// `ManuallyDrop<T>` wraps a value to prevent the compiler from automatically
/// dropping it. Explicit teardown through these methods has strict requirements:
///
/// `ManuallyDrop::drop(slot)`:
///   • Must be called at most once — calling it twice is a double-drop (UB)
///   • The value inside must still be valid (not yet moved out)
///   • After calling, the `ManuallyDrop` must not be used again
///
/// `ManuallyDrop::take(slot)` → T:
///   • Copies (bit-for-bit) the value out, returning ownership
///   • Calling it multiple times copies the same value — dropping all copies
///     is a double-drop
///   • After calling, the `ManuallyDrop` contains a potentially-invalid copy
///
/// Common bugs: calling drop/take on a ManuallyDrop that was already consumed
/// (double-drop), using the ManuallyDrop after take (use-after-move).
///
/// Seen in: FFI glue code, custom arena allocators, and MaybeUninit-based
/// collections across dozens of RustSec advisories.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ManuallyDropOps;

impl Checker for ManuallyDropOps {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("ManuallyDrop::<T>::drop")
                || path.ends_with("ManuallyDrop::drop")
            {
                (
                    "ManuallyDrop::drop",
                    "must be called exactly once; double-drop if called twice or if the \
                     inner value was already moved out via ManuallyDrop::take",
                )
            } else if path.ends_with("ManuallyDrop::<T>::take")
                || path.ends_with("ManuallyDrop::take")
            {
                (
                    "ManuallyDrop::take",
                    "moves out by copy — calling twice yields two owners of the same value; \
                     dropping both is a double-drop; do not use the ManuallyDrop afterwards",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "manually_drop",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
