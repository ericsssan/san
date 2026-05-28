/// Detects calls to `AtomicPtr::fetch_ptr_add` and `AtomicPtr::fetch_ptr_sub`
/// (stable since Rust 1.91.0).
///
/// These functions atomically perform pointer arithmetic on an `AtomicPtr<T>`:
///
/// `AtomicPtr::fetch_ptr_add(val, order)`:
///   • Atomically adds `val * size_of::<T>()` to the stored pointer, returning
///     the previous value
///   • The function itself is safe to call, but the resulting pointer may be out
///     of bounds — dereferencing it is UB if it no longer points into the allocation
///   • NOT a substitute for atomic integer arithmetic — the unit is `sizeof(T)` bytes
///
/// `AtomicPtr::fetch_ptr_sub(val, order)`:
///   • Atomically subtracts `val * size_of::<T>()` from the stored pointer
///   • The resulting pointer may go before the start of the allocation — dereferencing
///     it would be UB
///
/// Common bugs:
///   • Treating `fetch_ptr_add(1, ...)` as adding 1 byte when T is wider than u8
///   • Pointer escaping the allocation on a concurrent increment/decrement race
///   • Using the returned (old) pointer after a concurrent free
///
/// Stable since Rust 1.91.0 (was nightly `strict_provenance_atomic_ptr`).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct AtomicPtrArith;

impl Checker for AtomicPtrArith {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("fetch_ptr_add") && path.contains("Atomic") {
                (
                    "AtomicPtr::fetch_ptr_add",
                    "atomically adds val*size_of::<T>() to the pointer; the result must remain \
                     within the same allocation (or one byte past its end) — dereferencing an \
                     out-of-bounds result is UB; unit is T elements, not bytes",
                )
            } else if path.ends_with("fetch_ptr_sub") && path.contains("Atomic") {
                (
                    "AtomicPtr::fetch_ptr_sub",
                    "atomically subtracts val*size_of::<T>() from the pointer; result must not \
                     go before the start of the allocation — dereferencing such a result is UB; \
                     unit is T elements, not bytes",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "atomic_ptr_arith",
                severity: Severity::Info,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
