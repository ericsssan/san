/// Detects calls to `BinaryHeap::as_mut_slice` and `BinaryHeap::from_raw_vec`
/// (nightly, features `binary_heap_as_mut_slice` and `binary_heap_from_raw_vec`).
///
/// A `BinaryHeap<T>` maintains a max-heap invariant: every parent is ≥ both
/// of its children. These functions bypass that invariant:
///
/// `BinaryHeap::as_mut_slice(&mut self) -> &mut [T]`:
///   Exposes the raw storage as a mutable slice. The caller must guarantee:
///   • After the borrow ends, every write through the returned slice must leave
///     the heap in a valid max-heap state — otherwise subsequent `pop`, `peek`,
///     and `push` operations produce incorrect results silently (wrong ordering,
///     missed elements, invalid priorities)
///   • In practice this means: either restore the heap property manually (e.g.
///     via `BinaryHeap::rebuild`) before any heap operation, or limit writes to
///     changes that preserve the heap property (e.g. decreasing a leaf node's value)
///
/// `BinaryHeap::from_raw_vec(vec: Vec<T>) -> BinaryHeap<T>`:
///   Constructs a BinaryHeap directly from a Vec without verifying the heap property.
///   Safety: the Vec's elements must already satisfy the max-heap invariant. If they
///   do not, all subsequent heap operations produce incorrect results silently.
///
/// Safe alternative: `BinaryHeap::from(vec)` (re-heapifies in O(n)).
///
/// Nightly: `binary_heap_as_mut_slice` (#63421), `binary_heap_from_raw_vec` (#123628).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BinaryHeapUnsafe;

impl Checker for BinaryHeapUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("BinaryHeap") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::as_mut_slice") {
                (
                    "BinaryHeap::as_mut_slice",
                    "any write through the returned slice must leave a valid max-heap; \
                     if the heap property is violated, all subsequent pop/push/peek \
                     operations silently return wrong results; restore with rebuild() \
                     if needed",
                )
            } else if path.ends_with("::from_raw_vec") {
                (
                    "BinaryHeap::from_raw_vec",
                    "the Vec's elements must already satisfy the max-heap invariant; \
                     if not, subsequent heap operations produce incorrect results silently; \
                     use `BinaryHeap::from(vec)` to re-heapify safely in O(n)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "binary_heap_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
