/// Detects calls to `CursorMut::insert_after_unchecked`,
/// `CursorMut::insert_before_unchecked`, and `CursorMut::with_mutable_key`
/// on `BTreeMap`/`BTreeSet` (nightly, feature `btree_cursors`, tracking issue #107540).
///
/// These methods insert key-value pairs adjacent to a cursor position without
/// checking the BTree's invariants. The caller must guarantee:
///
///   For `insert_after_unchecked(key, val)`:
///     1. `key` does not already exist in the map (duplicate key corrupts the tree)
///     2. `key` > all keys currently before the cursor position
///     3. `key` < the key immediately after the cursor position (if any)
///
///   For `insert_before_unchecked(key, val)`:
///     1. `key` does not already exist in the map
///     2. `key` > the key immediately before the cursor position (if any)
///     3. `key` < all keys currently after the cursor position
///
/// Violating either the uniqueness or ordering invariant corrupts the BTree's
/// internal node structure. Subsequent `get`, `insert`, `remove`, or iteration
/// operations on the map may then produce wrong results or trigger UB in the
/// allocator when the corrupted structure is traversed.
///
/// Safe alternatives: `CursorMut::insert_after` and `CursorMut::insert_before`
/// (panic on invariant violation — not yet stable as of the tracking issue).
///
/// Nightly: requires `#![feature(btree_cursors)]`.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct BTreeCursorUnchecked;

impl Checker for BTreeCursorUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("CursorMut") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::insert_after_unchecked") {
                (
                    "CursorMut::insert_after_unchecked",
                    "key must not already exist in the map; key must be greater than all \
                     keys before the cursor and less than the key immediately after; \
                     invariant violation silently corrupts the BTree structure",
                )
            } else if path.ends_with("::insert_before_unchecked") {
                (
                    "CursorMut::insert_before_unchecked",
                    "key must not already exist in the map; key must be greater than the \
                     key immediately before the cursor and less than all keys after; \
                     invariant violation silently corrupts the BTree structure",
                )
            } else if path.ends_with("::with_mutable_key") {
                (
                    "CursorMut::with_mutable_key",
                    "returns CursorMutKey which allows direct mutation of keys; caller must \
                     maintain the BTree invariant: keys must remain in sorted order and be \
                     unique after any mutation; violating the ordering silently corrupts \
                     traversal and all subsequent map operations \
                     (nightly feature `btree_cursors`, tracking issue #107540)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "btree_cursor_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
