/// Detects calls to `<*const T>::as_ref` and `<*mut T>::as_mut`.
/// (For `NonNull::as_ref` and `NonNull::as_mut` see the `nonnull_deref` rule.)
///
/// These methods convert a raw pointer to an `Option<&T>` / `Option<&mut T>`:
///   • Returns `None` if the pointer is null
///   • Returns `Some(&T)` / `Some(&mut T)` otherwise
///
/// The caller must guarantee for the non-null case:
///   • The pointer is valid for reads (or writes for `as_mut`) of size_of::<T>() bytes
///   • The pointer is properly aligned for T
///   • The pointed-to T is fully initialized
///   • The returned reference must not outlive the pointed-to allocation
///   • For `as_mut`: no other reference (mutable or shared) to the same memory
///     may exist for the returned reference's lifetime
///
/// Unlike `&*ptr`, these methods silently return `None` for null pointers instead
/// of triggering immediate UB — but a non-null dangling or misaligned pointer
/// still causes UB via the returned reference.
///
/// Common bugs: returning a reference to a stack variable via raw pointer
/// (dangling after function returns), aliasing mutable and shared references
/// through different raw pointers to the same allocation.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrAsRef;

impl Checker for PtrAsRef {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, extra) = if path.ends_with("::as_ref")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                (
                    "*const T::as_ref",
                    "no mutable reference to the same memory must exist simultaneously",
                )
            } else if path.ends_with("::as_mut") && path.contains("mut_ptr") {
                (
                    "*mut T::as_mut",
                    "no other reference (mutable or shared) to the same memory must exist \
                     for the lifetime of the returned &mut T",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "ptr_as_ref",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — if non-null: pointer must be valid, aligned, and point to \
                     initialized T; {extra}; returned reference must not outlive the allocation"
                ),
            });
        }

        findings
    }
}
