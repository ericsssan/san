/// Detects calls to `NonNull::as_ref`, `NonNull::as_mut`,
/// `NonNull::as_uninit_ref`, `NonNull::as_uninit_mut`, and `NonNull::as_uninit_slice`.
///
/// These methods dereference a `NonNull<T>` raw pointer to create a reference.
/// The caller must guarantee ALL of the following:
///
/// `NonNull::as_ref(&self) -> &T`:
///   • The pointer must be valid for reads of size_of::<T>() bytes
///   • The pointer must be properly aligned for T
///   • The pointed-to T must be fully initialized
///   • The returned reference must not outlive the pointed-to allocation
///   • No mutable reference to the same memory must exist simultaneously
///
/// `NonNull::as_mut(&mut self) -> &mut T`:
///   • All the above, plus:
///   • No other reference (mutable or shared) to the same memory must exist
///     for the lifetime of the returned `&mut T`
///
/// Common bugs: creating multiple mutable references through distinct NonNull
/// pointers to the same allocation, calling as_ref/as_mut after the allocation
/// has been freed or invalidated, using a dangling NonNull from a moved value.
///
/// Seen in: custom arena allocators, intrusive data structures, and any crate
/// that passes NonNull pointers across function boundaries.
use crate::analysis::state::FreedKind;
use crate::analysis::transfer::first_arg_base_local;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct NonNullDeref;

impl Checker for NonNullDeref {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, extra) = if path.ends_with("NonNull::<T>::as_ref")
                || path.ends_with("NonNull::as_ref")
            {
                (
                    "NonNull::as_ref",
                    "no mutable reference to the same memory must exist simultaneously",
                )
            } else if path.ends_with("NonNull::<T>::as_mut")
                || path.ends_with("NonNull::as_mut")
            {
                (
                    "NonNull::as_mut",
                    "no other reference (mutable or shared) to the same memory must exist for \
                     the lifetime of the returned &mut T",
                )
            } else if path.ends_with("::as_uninit_ref") && path.contains("NonNull") {
                (
                    "NonNull::as_uninit_ref",
                    "pointer must be valid and aligned for T even though the value may be uninit; \
                     no mutable reference to the same memory must exist simultaneously",
                )
            } else if path.ends_with("::as_uninit_mut") && path.contains("NonNull") {
                (
                    "NonNull::as_uninit_mut",
                    "pointer must be valid and aligned for T; no other reference to the same \
                     memory must exist for the lifetime of the returned &mut MaybeUninit<T>",
                )
            } else if path.ends_with("::as_uninit_slice") && path.contains("NonNull") {
                (
                    "NonNull::as_uninit_slice",
                    "pointer must be valid for len elements and properly aligned for T; \
                     no mutable reference to any of the elements may exist simultaneously",
                )
            } else {
                continue;
            };

            // Flow-sensitive checks: detect UAF and suppress valid patterns.
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(ptr_local) = first_arg_base_local(args) {
                    // UAF: as_ref/as_mut on a pointer whose allocation was already freed.
                    match state.freed_kind(ptr_local) {
                        FreedKind::Definite => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", false));
                            continue;
                        }
                        FreedKind::Potential => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", true));
                            continue;
                        }
                        FreedKind::NotFreed => {}
                    }
                    // Suppress the generic warning when the pointer is still live and owned.
                    if state.ptr_is_raw_owned(ptr_local) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "nonnull_deref",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{fn_name}` — pointer must be valid, aligned, and point to initialized T; \
                     {extra}; returned reference must not outlive the allocation"
                ),
            });
        }

        findings
    }
}
