/// Detects calls to `<*const T>::as_ref_unchecked`, `<*mut T>::as_ref_unchecked`,
/// and `<*mut T>::as_mut_unchecked` (stable since Rust 1.95).
///
/// These methods convert a raw pointer directly to a reference without null-checking.
/// Unlike `as_ref()`/`as_mut()` which return `Option<&T>`, these skip the null check:
///   • A null pointer causes immediate UB (no `None` safety net)
///   • The pointer must be valid for reads/writes of size_of::<T>() bytes
///   • The pointer must be properly aligned for T
///   • The pointed-to T must be fully initialized
///   • The returned reference must not outlive the pointed-to allocation
///   • For `as_mut_unchecked`: no other reference (mutable or shared) to the same
///     memory may exist for the lifetime of the returned `&mut T`
///
/// Common bugs: calling on a pointer that might be null (should use `as_ref()`),
/// producing a dangling reference to a freed or stack-escaped allocation,
/// aliasing a mutable reference with another reference to the same memory.
///
/// Safe alternatives: `as_ref()` (returns `Option<&T>`, handles null) and
/// `as_mut()` (returns `Option<&mut T>`).
///
/// Stable since Rust 1.95.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrAsRefUnchecked;

impl Checker for PtrAsRefUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, extra) = if path.ends_with("::as_ref_unchecked")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "as_ref_unchecked",
                    "no check is made for null; pointer must be non-null, valid, aligned, \
                     and point to initialized T; no mutable alias may exist",
                )
            } else if path.ends_with("::as_mut_unchecked") && path.contains("mut_ptr") {
                (
                    "as_mut_unchecked",
                    "no check is made for null; pointer must be non-null, valid, aligned, \
                     and point to initialized T; exclusive access required — no other reference \
                     (shared or mutable) may exist for the lifetime of the returned &mut T",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_as_ref_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — {extra}; use `as_ref()`/`as_mut()` for the \
                     checked `Option`-returning variants"
                ),
            });
        }

        findings
    }
}
