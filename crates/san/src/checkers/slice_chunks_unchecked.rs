/// Detects calls to `<[T]>::as_chunks_unchecked` and `<[T]>::as_chunks_unchecked_mut`
/// (stable since Rust 1.88).
///
/// These functions reinterpret a slice `&[T]` as `&[[T; N]]`, asserting that
/// the slice length is an exact multiple of `N`. The checked counterparts
/// (`as_chunks`, `as_rchunks`) return the remainder separately and never go
/// out of bounds; the unchecked variants skip that check.
///
/// The caller must guarantee:
///   • `self.len()` is an exact multiple of `N` (or a multiple for rchunks)
///   • If `self.len() % N != 0`, the last returned chunk extends past the end
///     of the original allocation — reading it is an out-of-bounds access (UB)
///   • For `_mut` variants: additionally, no other reference to the slice may
///     exist while the returned mutable slice of chunks is live
///
/// Common bugs: passing a slice obtained from a socket recv (variable length)
/// to `as_chunks_unchecked` without first checking `len() % N == 0`, or
/// mistaking byte count for element count when computing the expected length.
///
/// Safe alternatives: `slice::as_chunks` (returns the remainder separately),
/// `slice::array_chunks` (iterates, skipping incomplete chunks).
///
/// Stable since Rust 1.88.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SliceChunksUnchecked;

impl Checker for SliceChunksUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("as_chunks_unchecked_mut") {
                (
                    "as_chunks_unchecked_mut",
                    "self.len() must be an exact multiple of N; if not, the last chunk reads \
                     past the allocation (OOB write UB); no other reference may exist during \
                     the mutable borrow — use `as_chunks_mut` for the safe checked version",
                )
            } else if path.ends_with("as_chunks_unchecked") {
                (
                    "as_chunks_unchecked",
                    "self.len() must be an exact multiple of N; if not, the last chunk \
                     extends past the end of the allocation (OOB read UB); \
                     use `as_chunks` or `array_chunks` for the safe alternatives",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "slice_chunks_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
