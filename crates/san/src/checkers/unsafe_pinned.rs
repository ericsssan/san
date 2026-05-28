/// Detects calls to `UnsafePinned::get_mut_unchecked`, `UnsafePinned::get`,
/// `UnsafePinned::raw_get`, `UnsafePinned::raw_get_mut`, and
/// `UnsafePinned::get_mut_pinned`.
/// (Nightly feature `unsafe_pinned`, tracking issue #125735.)
///
/// `UnsafePinned<T>` is the counterpart to `UnsafeCell<T>` for the mutable-
/// reference aliasing problem. `UnsafeCell` allows mutation behind `&T`;
/// `UnsafePinned` allows aliasing of `&mut T`. Both return `*mut T` through
/// their accessor methods, and correct use requires carefully upholding
/// aliasing invariants the compiler cannot check.
///
/// `get_mut_unchecked(&mut self) -> *mut T`:
///   • Caller must ensure no other live alias to this memory exists while
///     the returned pointer is active; writing through it while any other
///     reference (including another `*const T` derived from `get()`) is
///     live is UB.
///   • Prefer `get_mut_pinned` (Pin-aware path) for self-referential types.
///
/// `get(&self) -> *mut T`:
///   • Like `UnsafeCell::get` — returns a raw mutable pointer from a shared ref.
///   • Writing through the result while any `&T` reference derived from this
///     cell is still live is UB (read-only shared refs are invalidated by writes).
///   • The "safe mutation behind shared ref" contract only holds if there are no
///     simultaneous reads through `&T` or `*const T` derived from the same cell.
///
/// `raw_get(*const Self) -> *mut T` / `raw_get_mut(*mut Self) -> *mut T`:
///   • Same aliasing requirements; additionally the raw pointer itself must be
///     non-null, valid, and properly aligned for the lifetime of the access.
///
/// `get_mut_pinned(Pin<&mut Self>) -> *mut T`:
///   • The Pin guarantee must hold for the entire lifetime of the returned
///     pointer; the value must not be moved or invalidated while the pointer
///     is live; this is the correct path for self-referential types.
///
/// Common bugs:
///   • Holding a `*const T` from an earlier `get()` call and then writing
///     through `get_mut_unchecked` — subsequent read through the const pointer
///     is UB (invalidated alias).
///   • Passing `&mut UnsafePinned<T>` to generic code (`mem::swap`, any
///     `T: Sized` function using the reference) which assumes exclusive
///     ownership — aliased `&mut` arguments to such functions is UB.
///   • Implementing `Unpin for WrapperContainingUnsafePinned` defeats the
///     pin invariant the type is designed to maintain.
///
/// Nightly: `#![feature(unsafe_pinned)]`
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnsafePinned;

impl Checker for UnsafePinned {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("UnsafePinned") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::get_mut_unchecked") {
                (
                    "UnsafePinned::get_mut_unchecked",
                    "writing through the returned *mut T while any other live alias to this \
                     memory exists (including *const T from get()) is UB; prefer \
                     get_mut_pinned which requires Pin for self-referential types",
                )
            } else if path.ends_with("::get_mut_pinned") {
                (
                    "UnsafePinned::get_mut_pinned",
                    "the Pin guarantee must hold for the entire lifetime of the returned \
                     *mut T; the value must not be moved or invalidated while the pointer \
                     is live",
                )
            } else if path.ends_with("::raw_get_mut") {
                (
                    "UnsafePinned::raw_get_mut",
                    "the raw pointer must be non-null, valid, and aligned; writing through \
                     the result while any other alias is active is UB",
                )
            } else if path.ends_with("::raw_get") {
                (
                    "UnsafePinned::raw_get",
                    "the raw pointer must be non-null, valid, and aligned; writing through \
                     the result while any &T or *const T alias is live is UB",
                )
            } else if path.ends_with("::get") {
                (
                    "UnsafePinned::get",
                    "writing through the returned *mut T while any shared reference or \
                     *const T derived from this cell is still live is UB; \
                     like UnsafeCell::get but for the mutable-aliasing use case",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "unsafe_pinned",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
