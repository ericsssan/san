/// Detects calls made through `unsafe fn(...)` function pointers at the MIR level.
///
/// A call through an `unsafe fn` pointer (as opposed to a direct named function call)
/// requires the caller to verify additional invariants that the type system cannot
/// enforce:
///   • The function pointer must be valid and non-null; a null or dangling fn pointer
///     is immediate UB on call (no null check is implicit)
///   • The ABI must match: the pointer must have been obtained from a function whose
///     ABI, argument types, and return type exactly match the pointer type; a mismatch
///     (e.g. calling a `extern "C"` function through a `extern "Rust"` fn ptr) silently
///     corrupts registers, the stack, or the return address
///   • If the pointer was obtained by casting an integer or via transmute, the
///     pointed-to code must still be valid and accessible (not unloaded, not freed)
///   • For function pointers from dynamic libraries (`dlsym` / `GetProcAddress`):
///     the library must still be loaded; unloading a library while holding its fn
///     pointers is use-after-free for code pages
///
/// Common patterns: custom vtables (raw `*const VTable` with fn pointer fields),
/// FFI callbacks stored as `unsafe fn(...)` fields, and hand-rolled dynamic dispatch.
///
/// Note: direct calls to named `unsafe fn` functions are handled by the specific
/// per-API checkers; this checker targets *indirect* calls through stored fn pointers.
use crate::{Checker, Finding, Severity};
use rustc_hir::Safety;
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::{self, TyCtxt};

pub struct UnsafeFnPtr;

impl Checker for UnsafeFnPtr {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };

            // Direct calls (named functions) return Some from const_fn_def.
            // We only want indirect calls through stored fn pointers.
            if func.const_fn_def().is_some() {
                continue;
            }

            let fn_ty = func.ty(&body.local_decls, tcx);
            let is_unsafe_fn_ptr = match fn_ty.kind() {
                ty::FnPtr(_sig_tys, hdr) => hdr.safety() == Safety::Unsafe,
                _ => false,
            };

            if !is_unsafe_fn_ptr {
                continue;
            }

            findings.push(Finding {
                rule_id: "unsafe_fn_ptr",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "call through `unsafe fn` pointer (`{fn_ty}`) — verify the pointer is \
                     non-null and valid, the ABI matches the callee exactly, and any required \
                     library/module is still loaded; a null or ABI-mismatched fn pointer call \
                     is immediate UB"
                ),
            });
        }

        findings
    }
}
