/// Detects unsafe operations on `BorrowedCursor` (nightly `#![feature(core_io_borrowed_buf)]`).
///
/// `BorrowedCursor` provides access to the unfilled portion of a `BorrowedBuf`,
/// used in the `Read::read_buf` API to allow `Read` implementations to fill a
/// caller-provided, potentially-uninitialized buffer.
///
/// `BorrowedCursor::advance(n)` marks the first `n` bytes of the cursor as
/// initialized and filled, advancing the internal filled cursor. The caller
/// must guarantee:
///   • The first `n` bytes of the unfilled region have been written with valid
///     initialized data — if they have not, the caller of `Read::read_buf` will
///     read uninitialized bytes (UB)
///   • `n <= self.capacity()` — advancing past the capacity corrupts the
///     buffer's length tracking and causes out-of-bounds memory access
///
/// `BorrowedCursor::set_init()` (nightly `#![feature(borrowed_buf_init)]`) marks
/// the entire unfilled region as initialized without writing to it. The caller
/// must guarantee that every byte in the unfilled region has been initialized;
/// if any byte is still uninitialized, subsequent callers reading the buffer
/// will observe uninitialized memory (UB).
///
/// Common bugs: calling `advance(n)` before actually writing `n` bytes, or
/// calling `set_init()` after a partial write that did not fill the full region.
///
/// Nightly-only: `#![feature(core_io_borrowed_buf)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BorrowedCursorAdvance;

impl Checker for BorrowedCursorAdvance {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("BorrowedCursor") {
                continue;
            }

            let message = if path.ends_with("::advance") {
                "`BorrowedCursor::advance(n)` — the first `n` bytes of the cursor's \
                 unfilled region must be fully initialized before this call; advancing \
                 without writing exposes uninitialized bytes to the caller; \
                 `n` must also be <= self.capacity()"
                    .to_string()
            } else if path.ends_with("::set_init") {
                "`BorrowedCursor::set_init()` — marks the entire unfilled region as \
                 initialized; every byte must have been written before calling; \
                 if any byte is still uninitialized, readers of the buffer observe \
                 uninitialized memory (UB)"
                    .to_string()
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "borrowed_cursor_advance",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message,
            });
        }

        findings
    }
}
