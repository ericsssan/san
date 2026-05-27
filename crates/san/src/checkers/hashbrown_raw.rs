/// Detects unsafe operations on `hashbrown::raw::RawTable` and `hashbrown::raw::Bucket`.
///
/// `hashbrown` is the backing implementation of Rust's `std::collections::HashMap`
/// (re-exported via the stdlib). The `raw` feature exposes low-level table internals
/// used when implementing custom hash map types (e.g., `DashMap`, `indexmap`).
///
/// `RawTable::insert_no_grow(hash, value) -> Bucket<T>`:
///   • Inserts without checking table capacity — if the table is full, this
///     overwrites an existing slot or corrupts the table's control bytes (UB)
///   • The `hash` argument must be the actual hash of the key stored in `value`;
///     a mismatched hash causes future lookups to miss the entry (logical UB)
///   • Callers must call `reserve` or ensure the load factor allows insertion
///
/// `Bucket::as_ref(&self) -> &T` / `Bucket::as_mut(&mut self) -> &mut T`:
///   • The bucket must be occupied (not erased/empty); reading an empty bucket
///     is UB (uninitialized memory)
///   • For `as_mut`: no other reference (shared or mutable) to this bucket's
///     element may exist simultaneously (aliased &mut T is UB)
///   • The bucket must not have been invalidated by a subsequent table resize
///     or rehash — `Bucket` pointers are valid only until the next mutation
///
/// `RawTable::erase(bucket)`:
///   • Marks the bucket as empty (writes a tombstone to the control byte)
///   • Does NOT drop the value — the value leaks if it was initialized;
///     caller is responsible for reading and dropping it first if needed
///   • After calling, the bucket pointer is invalid — any subsequent deref is UB
///
/// `RawTable::remove(bucket) -> T`:
///   • Marks the bucket as empty and moves out the value (returns ownership)
///   • The bucket must be occupied; calling on an empty bucket is UB
///   • After calling, the bucket pointer is invalid
///
/// Common bugs in custom hash map implementations:
///   • Calling `insert_no_grow` without ensuring capacity, causing silent corruption
///   • Stale `Bucket` pointers after a `reserve` (which rehashes the table)
///   • `erase` without first dropping the value → memory leak of complex types
///   • Using `as_mut` while an immutable reference to the same element exists
///
/// Seen in: DashMap, custom concurrent hash maps, and any crate that wraps
/// `hashbrown::raw::RawTable` for a specialized access pattern.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct HashbrownRaw;

impl Checker for HashbrownRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("hashbrown") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::insert_no_grow") {
                (
                    "RawTable::insert_no_grow",
                    "inserts without checking capacity — table must have a free slot; \
                     if full, this corrupts control bytes or overwrites an occupied slot (UB); \
                     hash must match the key stored in value, or future lookups will miss it; \
                     call reserve() before inserting if capacity is uncertain",
                )
            } else if path.ends_with("::as_mut") && path.contains("Bucket") {
                (
                    "Bucket::as_mut",
                    "bucket must be occupied (not erased/empty) — reading an empty bucket is \
                     UB (uninitialized memory); no other reference to this element may exist \
                     simultaneously (aliased &mut T is UB); bucket pointer is invalidated \
                     by any subsequent table resize or rehash",
                )
            } else if path.ends_with("::as_ref") && path.contains("Bucket") {
                (
                    "Bucket::as_ref",
                    "bucket must be occupied (not erased/empty) — reading an empty bucket is \
                     UB (uninitialized memory); bucket pointer is invalidated by any subsequent \
                     table resize or rehash (e.g. after insert or reserve)",
                )
            } else if path.ends_with("::erase") && path.contains("RawTable") {
                (
                    "RawTable::erase",
                    "marks the bucket as empty but does NOT drop the value — if the value \
                     owns heap memory, it leaks; read and drop the value before erasing \
                     (or use remove() which returns ownership); after erasing, the bucket \
                     pointer is invalid",
                )
            } else if path.ends_with("::remove") && path.contains("RawTable") {
                (
                    "RawTable::remove",
                    "bucket must be occupied; calling on an empty bucket is UB; \
                     moves out the value (returns ownership) and marks the slot empty; \
                     after calling, the bucket pointer is invalid",
                )
            } else if path.ends_with("::get_bucket_unchecked") && path.contains("HashTable") {
                (
                    "HashTable::get_bucket_unchecked",
                    "index must correspond to an occupied bucket; reading an empty or \
                     out-of-bounds bucket is UB (uninitialized memory); there is no bounds \
                     check — index must be < table.capacity(); use find() for safe access",
                )
            } else if path.ends_with("::get_bucket_unchecked_mut") && path.contains("HashTable") {
                (
                    "HashTable::get_bucket_unchecked_mut",
                    "index must correspond to an occupied bucket; reading or writing an empty \
                     or out-of-bounds bucket is UB; no other reference to this bucket entry \
                     may exist simultaneously (aliased &mut T is UB)",
                )
            } else if path.ends_with("::get_bucket_entry_unchecked") && path.contains("HashTable") {
                (
                    "HashTable::get_bucket_entry_unchecked",
                    "index must correspond to an occupied bucket; accessing an empty or \
                     out-of-bounds bucket is UB; the returned OccupiedEntry must not \
                     outlive a concurrent resize or rehash",
                )
            } else if path.ends_with("::insert_in_slot") && path.contains("hashbrown") {
                (
                    "RawTable::insert_in_slot",
                    "slot must have been returned by find_or_find_insert_slot on this same table \
                     and must not have been invalidated by any subsequent insert, reserve, or \
                     grow; hash must be the actual hash of the key stored in value — a mismatch \
                     causes future lookups to miss the entry (logical UB)",
                )
            } else if path.ends_with("::is_bucket_full") && path.contains("hashbrown") {
                (
                    "RawTable::is_bucket_full",
                    "index must be < table.buckets(); reading the control byte of an \
                     out-of-bounds index is UB (reads past the allocated control array)",
                )
            } else if path.ends_with("::iter_hash") && path.contains("hashbrown") {
                (
                    "RawTable::iter_hash",
                    "iterates over all buckets whose stored hash matches the given hash; \
                     the caller must compare the actual key of each returned bucket to \
                     detect hash collisions — treating the first hit as the target entry \
                     without equality check may access the wrong value (logical UB); \
                     the table must not be mutated while the RawIterHash is live",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "hashbrown_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
