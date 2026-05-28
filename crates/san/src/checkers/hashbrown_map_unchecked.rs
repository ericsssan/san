/// Detects unsafe operations on `hashbrown::HashMap`, `HashSet`, and `HashTable`
/// that bypass duplicate or overlap checks.
///
/// `HashMap::insert_unique_unchecked(k, v) -> (&K, &mut V)`:
///   • Inserts without checking whether `k` already exists in the map
///   • If the key is already present, two entries with the same key exist —
///     future lookups may return either one (logical UB / invariant violation)
///
/// `HashSet::insert_unique_unchecked(value) -> &T`:
///   • Inserts without checking for duplicate values; set contains two identical
///     entries, violating the uniqueness invariant used by all lookups
///
/// `HashMap::get_many_unchecked_mut<const N>([k1, k2, …])`:
///   • Returns up to N mutable references simultaneously without checking that
///     keys are distinct; duplicate keys produce aliased `&mut V` (immediate UB)
///   • Safe alternative: `get_many_mut()` (returns None on conflict)
///
/// `HashMap::get_many_key_value_unchecked_mut<const N>([k1, …])`:
///   • Same aliasing hazard as `get_many_unchecked_mut`, also returning key refs
///
/// `HashMap::OccupiedEntry::replace_key_unchecked(new_key)` (hashbrown 0.17+):
///   • Replaces the key in an occupied entry without checking that `new_key`
///     produces the same hash; if the hash differs, the entry is now under the
///     wrong bucket and future lookups for `new_key` will not find it —
///     the old key is also gone, creating an invisible "ghost" entry
///
/// These APIs are present in hashbrown 0.15+ and re-exported into
/// `std::collections::HashMap` in recent nightly builds.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HashbrownMapUnchecked;

impl Checker for HashbrownMapUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("hashbrown") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::insert_unique_unchecked")
                && path.contains("HashSet")
            {
                (
                    "HashSet::insert_unique_unchecked",
                    "inserts without checking for duplicate values — if the value is already \
                     present, the set contains two identical entries, violating uniqueness \
                     invariants; use insert() instead",
                )
            } else if path.ends_with("::insert_unique_unchecked") && path.contains("HashMap") {
                (
                    "HashMap::insert_unique_unchecked",
                    "inserts without checking for duplicate keys — if the key already exists, \
                     two entries with the same key are created, causing future lookups to return \
                     either one (logical UB); use insert() or entry() instead",
                )
            } else if path.ends_with("::get_many_unchecked_mut") {
                (
                    "get_many_unchecked_mut",
                    "returns N mutable references without verifying that keys/indices are distinct; \
                     duplicate keys produce aliased &mut references to the same value (immediate UB); \
                     use get_many_mut() which checks for duplicates and returns None on conflict",
                )
            } else if path.ends_with("::get_many_key_value_unchecked_mut") {
                (
                    "get_many_key_value_unchecked_mut",
                    "returns N mutable value references alongside key references without checking \
                     for duplicate keys; duplicate keys produce aliased &mut V (immediate UB); \
                     use get_many_key_value_mut() for the checked alternative",
                )
            } else if path.ends_with("::replace_key_unchecked")
                && path.contains("hashbrown")
            {
                (
                    "OccupiedEntry::replace_key_unchecked",
                    "replaces the key without verifying that the new key hashes to the same \
                     bucket; if the new key's hash differs, the entry is now under the wrong \
                     bucket — future lookups for the new key will not find it, and the old key \
                     is gone too (invisible ghost entry; invariant violation); only safe if \
                     old and new keys compare equal under the map's hasher",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "hashbrown_map_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
