/// Detects calls to `push_unchecked` and `try_push_unchecked` on third-party
/// collection types (e.g., `arrayvec::ArrayVec`, `smallvec::SmallVec`).
///
/// `push_unchecked(element)` appends an element to a fixed-capacity collection
/// without checking whether there is remaining capacity. The caller must:
///   • Ensure `len < capacity` before calling — if the collection is already
///     full, the element is written one past the end of the allocated storage
///     (out-of-bounds write → immediate UB)
///   • Track the collection's current length carefully — this is especially
///     subtle when used inside loops where the iteration count may exceed
///     the capacity
///
/// `try_push_unchecked(element)` — analogous but on some types returns a
/// `Result`; the _unchecked variant skips the capacity assertion entirely.
///
/// Common bugs:
///   • Off-by-one: capacity = N, but the loop runs N+1 times
///   • Calling `push_unchecked` after a `set_len` that reduced the length
///     counter without leaving memory in a valid state
///   • Using `push_unchecked` in unsafe collection implementations where
///     the capacity arithmetic uses integer overflow (→ write past allocation)
///
/// Safe alternative: use the checked `push(element)` which returns an error or
/// panics when the capacity is exceeded.
///
/// Caught in: arrayvec, smallvec, tinyvec, and custom fixed-capacity collections.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PushUnchecked;

impl Checker for PushUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("::push_unchecked") {
                (
                    "push_unchecked",
                    "collection must have remaining capacity (len < capacity) before this call; \
                     writing to a full collection is an out-of-bounds write (immediate UB); \
                     use the checked push() which panics or returns an error on overflow",
                )
            } else if path.ends_with("::try_push_unchecked") {
                (
                    "try_push_unchecked",
                    "collection must have remaining capacity before this call; \
                     the _unchecked variant skips the capacity assertion entirely — \
                     out-of-bounds write if the collection is already at capacity (UB)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "push_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
