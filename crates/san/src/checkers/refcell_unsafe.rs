/// Detects calls to `RefCell::try_borrow_unguarded`.
/// (Nightly: `#![feature(cell_leak)]`)
///
/// `RefCell::try_borrow_unguarded(&self) -> Result<&T, BorrowError>` returns
/// a shared reference to the inner value WITHOUT borrowing the `RefCell` —
/// meaning no `BorrowRef` guard is held. The returned `&T` is not tracked by
/// the RefCell's dynamic borrow counter.
///
/// The caller must guarantee ALL of the following for the ENTIRE lifetime of
/// the returned reference:
///   • No mutable borrow of the RefCell (via `borrow_mut()` or other unsafe means)
///     may be created while the reference is alive — doing so would create a
///     `&T` and `&mut T` to the same value simultaneously (aliased mutable
///     reference = immediate UB)
///   • No `try_borrow_unguarded` may coexist with any mutable borrow
///   • If the returned reference is passed across thread boundaries the caller
///     is responsible for all synchronization (RefCell is NOT Sync)
///
/// The safe alternative is `RefCell::borrow()`, which returns a `Ref<'_, T>`
/// guard that is automatically dropped when it goes out of scope and prevents
/// simultaneous mutable borrows at runtime.
///
/// Nightly feature: `cell_leak`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct RefCellUnsafe;

impl Checker for RefCellUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("RefCell") || !path.ends_with("try_borrow_unguarded") {
                continue;
            }

            findings.push(Finding {
                rule_id: "refcell_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`RefCell::try_borrow_unguarded` — returns &T without a borrow guard; \
                          no mutable borrow (borrow_mut) may be created while this reference \
                          is alive; simultaneous mutable borrow is immediate UB; \
                          use `RefCell::borrow()` for the safe guarded version"
                    .to_string(),
            });
        }

        findings
    }
}
