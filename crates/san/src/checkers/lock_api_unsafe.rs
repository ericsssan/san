/// Detects calls to `parking_lot::Mutex::force_unlock`, `force_unlock_fair`,
/// `RwLock::force_unlock_read`, `force_unlock_write`, and related methods on
/// `lock_api::Mutex`, `lock_api::RwLock`, and `lock_api::ReentrantMutex`.
///
/// These methods bypass the normal lock/unlock protocol and are only valid when
/// the lock is known to be held by the current thread but the guard has been
/// discarded via `mem::forget`. Common uses: custom scoped-guard patterns,
/// panic recovery in FFI context.
///
/// `force_unlock` / `force_unlock_fair`:
///   • The mutex MUST be in the locked state; calling on an unlocked mutex
///     corrupts the internal atomic state → spurious wakeups or deadlock; UB
///   • Intended pattern: `mem::forget(guard)` then `force_unlock` in a
///     matching scope
///
/// `force_unlock_read` / `force_unlock_write`:
///   • Same invariant as `force_unlock` but for RwLock read/write locks
///   • `force_unlock_write` is especially dangerous: calling when no exclusive
///     lock is held opens a write+concurrent-read race window → data race UB
///
/// `make_guard_unchecked` / `make_read_guard_unchecked` / `make_write_guard_unchecked`:
///   • Creates a guard without acquiring the lock; the caller must guarantee
///     the lock is actually held — otherwise two guards exist simultaneously,
///     producing aliased mutable references (immediate UB)
///
/// `raw`:
///   • Returns `&RawMutex`/`&RawRwLock`; calling `unlock()` through this
///     handle while a guard is still live causes a double-unlock → UB
///
/// RustSec: RUSTSEC-2020-0070 (lock_api guard `Send`/`Sync` bounds).
use crate::analysis::transfer::is_force_unlock;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct LockApiUnsafe;

impl Checker for LockApiUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.contains("lock_api") && !path.contains("parking_lot") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::force_unlock_write_fair") {
                (
                    "RwLock::force_unlock_write_fair",
                    "must only be called when an exclusive write lock is held by this thread \
                     (e.g., after mem::forget of a write guard); calling on an unlocked or \
                     read-locked RwLock opens a concurrent write+read race window → data race UB",
                )
            } else if path.ends_with("::force_unlock_write") {
                (
                    "RwLock::force_unlock_write",
                    "must only be called when an exclusive write lock is held by this thread \
                     (e.g., after mem::forget of a write guard); calling on an unlocked or \
                     read-locked RwLock allows concurrent writers → data race UB",
                )
            } else if path.ends_with("::force_unlock_read_fair") {
                (
                    "RwLock::force_unlock_read_fair",
                    "must only be called when a shared read lock is held by this thread; \
                     underflowing the read-lock count corrupts the RwLock state → UB",
                )
            } else if path.ends_with("::force_unlock_read") {
                (
                    "RwLock::force_unlock_read",
                    "must only be called when a shared read lock is held by this thread; \
                     underflowing the read-lock count corrupts the RwLock state → UB",
                )
            } else if path.ends_with("::force_unlock_fair") {
                (
                    "Mutex::force_unlock_fair",
                    "must only be called when the mutex is locked by this thread (e.g., after \
                     mem::forget of a MutexGuard); calling on an unlocked mutex corrupts \
                     internal atomic state → spurious wakeups, deadlock, or UB",
                )
            } else if path.ends_with("::force_unlock") {
                (
                    "Mutex::force_unlock",
                    "must only be called when the mutex is locked by this thread (e.g., after \
                     mem::forget of a MutexGuard); calling on an unlocked mutex corrupts \
                     internal atomic state → spurious wakeups, deadlock, or UB",
                )
            } else if path.ends_with("::make_write_guard_unchecked") {
                (
                    "RwLock::make_write_guard_unchecked",
                    "creates an exclusive write guard without acquiring the lock; the caller must \
                     guarantee an exclusive lock is already held — if not, two write guards alias \
                     the same T → immediate data race UB",
                )
            } else if path.ends_with("::make_read_guard_unchecked") {
                (
                    "RwLock::make_read_guard_unchecked",
                    "creates a read guard without acquiring the lock; the caller must guarantee \
                     a read lock is already held — if a write lock is concurrently held, \
                     the resulting &T aliases the writer's &mut T → data race UB",
                )
            } else if path.ends_with("::make_guard_unchecked")
                && (path.contains("Mutex") || path.contains("ReentrantMutex"))
            {
                (
                    "Mutex::make_guard_unchecked",
                    "creates a mutex guard without acquiring the lock; if no lock is held, \
                     two guards for the same T exist simultaneously → aliased &mut T (UB)",
                )
            } else {
                continue;
            };

            // For force_unlock*, suppress when flow confirms a guard was forgotten
            // in this function (the correct usage pattern). LockState handles the
            // violation case. Keep firing when flow has no information (inter-procedural).
            if is_force_unlock(&path) {
                if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                    if state.has_forgotten_protocol() {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                rule_id: "lock_api_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
