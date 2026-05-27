/// Detects unsafe operations in the `crossbeam-epoch` crate:
/// `Shared::deref`, `Shared::deref_mut`, `Shared::as_ref`, `Shared::into_owned`,
/// `Atomic::into_owned`, `Owned::into_shared`, `Owned::from_raw`,
/// `Guard::defer_unchecked`, `Guard::defer_destroy`, and `unprotected()`.
///
/// `crossbeam-epoch` implements epoch-based memory reclamation for lock-free
/// data structures. The central invariant is:
///   • Objects referenced by a `Shared<'g, T>` are guaranteed not to be
///     reclaimed ONLY for the duration of the epoch `'g` (the scope of the
///     `Guard` obtained by calling `epoch::pin()`)
///   • Once the guard is dropped, any `Shared` pointers derived from it may
///     point to freed memory — dereference is immediate UB
///
/// `Shared::deref(&self) -> &T` / `Shared::deref_mut(&mut self) -> &mut T`:
///   • The guard must still be active; the pointed-to object must not have been
///     reclaimed during this epoch
///   • For `deref_mut`: no other `Shared` or `Owned` reference to the same
///     object may be dereferenced concurrently — aliased `&mut T` is UB
///   • Null `Shared` pointers produce immediate UB (no null check performed)
///
/// `Shared::as_ref(&self) -> Option<&T>`:
///   • Returns `None` for null pointers (safer than `deref` for null handling)
///   • Still requires the guard to be active and the object to be live
///
/// `Atomic::into_owned(self) -> Owned<T>`:
///   • The `Atomic` must currently hold a valid, non-null owned pointer
///   • The caller takes exclusive ownership — the `Atomic` must not be
///     accessed by other threads concurrently, and must not be used for
///     further reads (they would be use-after-free or double-free)
///   • Null `Atomic` → calling `into_owned` is UB
///
/// `Owned::into_shared<'g>(self, _: &'g Guard) -> Shared<'g, T>`:
///   • Transfers ownership: the `Owned` is consumed; caller is now responsible
///     for ensuring the object is eventually reclaimed (via `defer_destroy`)
///   • The returned `Shared` must not outlive the guard's epoch
///
/// Common bugs in lock-free data structures:
///   • Dereferencing a `Shared` after the guard is dropped (use-after-free)
///   • Calling `into_owned` while another thread is still reading the pointer
///     (concurrent mutation of the reference count or the pointed-to data)
///   • Forgetting to call `defer_destroy` after `into_owned` (memory leak)
///   • Using `deref_mut` with aliased readers (concurrent readers via clone)
///
/// Real-world: RUSTSEC-2019-0009 (crossbeam-epoch 0.7) — a missing memory
/// barrier allowed Shared pointers to outlive their epoch protection.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct CrossbeamEpoch;

impl Checker for CrossbeamEpoch {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("crossbeam_epoch") {
                continue;
            }

            let (fn_name, note) = if path.contains("Shared") && path.ends_with("::deref_mut") {
                (
                    "Shared::deref_mut",
                    "pointer must be non-null, point to a live object within the current epoch, \
                     and have no concurrent readers or writers; aliased &mut T is immediate UB; \
                     the returned reference must not outlive the Guard",
                )
            } else if path.contains("Shared") && path.ends_with("::deref") {
                (
                    "Shared::deref",
                    "pointer must be non-null and point to a live object within the current epoch; \
                     after the Guard is dropped, the reference becomes dangling — use-after-free; \
                     use `as_ref()` if the pointer might be null",
                )
            } else if path.contains("Shared") && path.ends_with("::as_ref") {
                (
                    "Shared::as_ref",
                    "returns None for null (safer than deref for null handling), but still \
                     requires the Guard to be active and the object to be live; the returned \
                     reference must not outlive the Guard's epoch",
                )
            } else if path.contains("Atomic") && path.ends_with("::into_owned") {
                (
                    "Atomic::into_owned",
                    "the Atomic must hold a valid non-null owned pointer; caller takes \
                     exclusive ownership — no other thread may read or write this Atomic \
                     concurrently; null Atomic causes UB; the Owned must eventually be \
                     reclaimed (defer_destroy) or the allocation leaks",
                )
            } else if path.contains("Owned") && path.ends_with("::into_shared") {
                (
                    "Owned::into_shared",
                    "the Owned is consumed (caller no longer owns it); the returned Shared \
                     must not outlive the Guard's epoch; caller is responsible for ensuring \
                     the object is later reclaimed via defer_destroy to avoid memory leaks",
                )
            } else if path.contains("Shared") && path.ends_with("::into_owned") {
                (
                    "Shared::into_owned",
                    "converts a Shared pointer to an Owned, taking exclusive ownership; \
                     the pointer must be non-null and point to a live object; no other \
                     thread may hold a Shared or dereference the same pointer concurrently \
                     after this call — doing so is use-after-free",
                )
            } else if path.contains("Owned") && path.ends_with("::from_raw") {
                (
                    "Owned::from_raw",
                    "constructs an Owned<T> from a raw pointer; the pointer must be non-null, \
                     properly aligned, and exclusively owned by the caller (not shared with \
                     any other Owned, Shared, or Atomic); Owned will drop the allocation when \
                     it goes out of scope — double-free if another owner exists",
                )
            } else if path.ends_with("::defer_unchecked") && path.contains("crossbeam") {
                (
                    "Guard::defer_unchecked",
                    "defers a closure to run at a future epoch without enforcing Send bounds; \
                     if the closure captures non-Send data (e.g., Rc, raw pointers, RefCell) \
                     and the epoch collection runs on a different thread, the closure executes \
                     on the wrong thread — data race or use-after-free (UB); \
                     use defer() which requires F: Send",
                )
            } else if path.ends_with("::defer_destroy") && path.contains("crossbeam") {
                (
                    "Guard::defer_destroy",
                    "schedules the object at `ptr` for drop once the current epoch ends; \
                     the Shared must point to a live, exclusively-owned object — if any \
                     thread still holds a reference or another defer_destroy fires for the \
                     same pointer, the drop runs twice (double-free, UB); \
                     verify no other Shared or Owned references exist for this pointer",
                )
            } else if path == "crossbeam_epoch::unprotected"
                || (path.ends_with("::unprotected") && path.contains("crossbeam"))
            {
                (
                    "crossbeam_epoch::unprotected",
                    "returns a static Guard without pinning the current thread to an epoch; \
                     any Shared pointers derived from this guard may be reclaimed at any time \
                     — dereference is immediately unsound; only valid in single-threaded \
                     programs or when the caller can guarantee no concurrent reclamation \
                     (e.g., during program teardown)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "crossbeam_epoch",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
