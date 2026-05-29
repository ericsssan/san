/// Detects calls to `ptr::read`, `ptr::read_unaligned`, `ptr::read_volatile`,
/// `NonNull::read`, and the inherent method forms on `*const T`/`*mut T`.
///
/// `ptr::read` copies a T out of the pointed-to location. The caller must:
///   • Ensure `src` is non-null and valid for reads of size_of::<T>() bytes
///   • Ensure `src` is properly aligned for T (`read` only; `read_unaligned` relaxes this)
///   • Ensure the pointed-to T is initialized (invalid bit patterns are UB)
///   • Manage ownership: `read` creates a bitwise copy, which means the
///     original T is effectively moved. Dropping both causes double-drop.
///
/// `ptr::read_volatile` additionally:
///   • Prevents the compiler from caching or eliminating the read
///   • Does NOT provide atomic ordering guarantees (unlike atomics)
///   • Typically used for MMIO registers — must be used on volatile hardware addresses only
///
/// Common bugs: reading from a pointer after the allocation was freed
/// (use-after-free), double-drop when both the original and the copy are dropped.
///
/// RustSec: appears in RUSTSEC-2020-0146 (heapsize), custom Vec implementations,
/// and every crate that hand-rolls MaybeUninit-based collections.
use crate::analysis::transfer::first_arg_local;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrRead;

impl Checker for PtrRead {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let message = if path.ends_with("ptr::read_unaligned") {
                "`ptr::read_unaligned` — verify src is non-null, valid for size_of::<T>() \
                 bytes, and fully initialized; the copy is a semantic move — dropping both \
                 the original and the copy is a double-drop"
                    .to_string()
            } else if path.ends_with("::read_volatile")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                "`ptr::read_volatile` — src must be non-null, aligned, and valid for the \
                 hardware address; does NOT provide atomic ordering — not safe for \
                 concurrent access without additional synchronization"
                    .to_string()
            } else if path.ends_with("ptr::read") {
                "`ptr::read` — verify src is non-null, properly aligned for T, valid for \
                 size_of::<T>() bytes, and fully initialized; the copy is a semantic move \
                 — dropping both the original and the copy is a double-drop"
                    .to_string()
            } else if path.ends_with("::read") && path.contains("NonNull") {
                "`NonNull::read` — NonNull guarantees non-null but NOT validity or alignment; \
                 the pointer must be properly aligned for T, valid for size_of::<T>() bytes, \
                 and point to initialized memory; copy semantics apply — double-drop if both \
                 the original and copy are dropped"
                    .to_string()
            } else if path.ends_with("::read_volatile") && path.contains("NonNull") {
                "`NonNull::read_volatile` — pointer must be non-null (guaranteed), properly \
                 aligned, and a valid hardware address; does NOT provide atomic ordering; \
                 copy semantics apply"
                    .to_string()
            } else if path.ends_with("::read_unaligned") && path.contains("NonNull") {
                "`NonNull::read_unaligned` — pointer must be non-null (guaranteed) and valid \
                 for size_of::<T>() bytes; copy semantics — dropping both the original and \
                 the copy is a double-drop"
                    .to_string()
            } else if path.ends_with("::read_unaligned")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                "`ptr::read_unaligned` — verify src is non-null, valid for size_of::<T>() \
                 bytes, and fully initialized; the copy is a semantic move — dropping both \
                 the original and the copy is a double-drop"
                    .to_string()
            } else if path.ends_with("::read")
                && (path.contains("const_ptr") || path.contains("mut_ptr"))
            {
                "`ptr::read` — verify src is non-null, properly aligned for T, valid for \
                 size_of::<T>() bytes, and fully initialized; the copy is a semantic move \
                 — dropping both the original and the copy is a double-drop"
                    .to_string()
            } else {
                continue;
            };

            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(ptr_local) = first_arg_local(args) {
                    // Reading through a pointer whose allocation was already
                    // handed off (reconstituted by a `from_raw`/consuming call,
                    // possibly in another function via its summary) is a
                    // use-after-free — a real bug, not just an audit flag.
                    match state.freed_kind(ptr_local) {
                        crate::analysis::state::FreedKind::Definite => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", false));
                            continue;
                        }
                        crate::analysis::state::FreedKind::Potential => {
                            findings.push(uaf_finding(terminator.source_info.span, "read", true));
                            continue;
                        }
                        crate::analysis::state::FreedKind::NotFreed => {}
                    }
                    // Suppress if flow proves this pointer came from a live
                    // into_raw and has not been freed (still valid).
                    if state.ptr_is_raw_owned(ptr_local) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "ptr_read",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
