/// Detects calls to `ptr::swap`, `ptr::swap_nonoverlapping`, and `NonNull::swap`.
///
/// `ptr::swap(x, y)` performs a bitwise swap of the values at two raw pointers.
/// The caller must ensure:
///   • Both `x` and `y` are non-null, properly aligned for T, and valid for
///     reads and writes of size_of::<T>() bytes
///   • The pointed-to values are fully initialized (invalid bit patterns are UB)
///   • The two pointed-to regions may overlap (ptr::swap handles this) but both
///     regions must be within a single allocation (no cross-allocation swaps)
///
/// `ptr::swap_nonoverlapping(x, y, count)` swaps `count` elements:
///   • Same alignment and validity requirements as ptr::swap
///   • The regions `x..x+count*size_of::<T>()` and `y..y+count*size_of::<T>()`
///     must NOT overlap — passing overlapping regions is immediate UB
///   • Often misused with byte counts instead of element counts
///
/// Common bugs: passing raw pointer offsets from the same allocation that
/// happen to overlap, or confusing byte-count with element-count for the
/// `count` parameter of `swap_nonoverlapping`.
///
/// Stable since Rust 1.0 (`ptr::swap`) and 1.27 (`ptr::swap_nonoverlapping`).
use crate::analysis::state::FreedKind;
use crate::analysis::transfer::first_arg_local;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PtrSwap;

impl Checker for PtrSwap {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::swap_nonoverlapping")
                || path.ends_with("ptr::swap_nonoverlapping")
                || path.ends_with("intrinsics::swap_nonoverlapping")
            {
                (
                    "ptr::swap_nonoverlapping",
                    "both pointers must be non-null, aligned, and each valid for \
                     count*size_of::<T>() bytes; the two regions must NOT overlap — \
                     overlapping regions are immediate UB; common mistake: passing byte \
                     counts instead of element counts",
                )
            } else if path.ends_with("ptr::swap")
                || (path.ends_with("::swap")
                    && (path.contains("const_ptr") || path.contains("mut_ptr")))
            {
                (
                    "ptr::swap",
                    "both pointers must be non-null, properly aligned for T, valid for \
                     size_of::<T>() bytes of reads and writes, and point to initialized values; \
                     regions may overlap (ptr::swap handles this), but each must be within \
                     a single allocation",
                )
            } else if path.ends_with("::swap") && path.contains("NonNull") {
                (
                    "NonNull::swap",
                    "both NonNull pointers must be properly aligned for T and valid for \
                     size_of::<T>() bytes of reads and writes; non-null is guaranteed but \
                     alignment and initialization are not",
                )
            } else {
                continue;
            };

            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                if let Some(ptr_local) = first_arg_local(args) {
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
                    if state.ptr_is_raw_owned(ptr_local) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "ptr_swap",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
