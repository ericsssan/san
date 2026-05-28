/// Detects calls to `spin::Mutex::force_unlock`, `spin::RwLock::force_read_decrement`,
/// and `spin::RwLock::force_write_unlock`.
///
/// The `spin` crate provides spinlock-based synchronization primitives for `no_std`
/// environments. These force-unlock methods bypass the normal guard-drop mechanism:
///
/// **`Mutex::force_unlock()`**:
///   • Unlocks the mutex without a guard — if any thread still holds a reference
///     to the protected data (via a live guard or raw pointer derived from one),
///     the lock is gone but the reference is still alive → data race → UB
///   • Safe to call only if you can prove no other code has access to the data
///     (e.g., after a panic where the guard was lost without running Drop)
///
/// **`RwLock::force_read_decrement()`**:
///   • Decrements the reader count by one without a read guard; if the count
///     underflows or a writer was blocked waiting for readers to go to zero, the
///     writer may proceed while readers are still active → data race → UB
///
/// **`RwLock::force_write_unlock()`**:
///   • Releases the write lock without a write guard; any code that still has a
///     live mutable reference to the inner data gains an aliasing mutable reference
///     → immediate UB
///
/// Common bugs: using force_unlock to recover from a panic without ensuring the
/// data is in a consistent state; calling force_unlock in a loop that assumes the
/// caller is the only lock holder.
///
/// Safe alternatives: let the guard drop naturally (RAII), or restructure the code
/// to not need force unlock (e.g., use `try_lock` with a timeout or error path).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct SpinUnsafe;

impl Checker for SpinUnsafe {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("spin") {
                continue;
            }

            let (fn_name, note) = if path.ends_with("::force_unlock") {
                (
                    "Mutex::force_unlock",
                    "unlocks the spin mutex without a guard; any live reference to the protected \
                     data derived from a previous lock() is now a data race — immediate UB; only \
                     safe if you can guarantee no code has access to the inner value",
                )
            } else if path.ends_with("::force_read_decrement") {
                (
                    "RwLock::force_read_decrement",
                    "decrements the reader count without a read guard; underflowing the count or \
                     releasing a count that a writer is waiting on can unblock a writer while \
                     readers are still active — data race (UB)",
                )
            } else if path.ends_with("::force_write_unlock") {
                (
                    "RwLock::force_write_unlock",
                    "releases the write lock without a write guard; any live &mut T derived from \
                     the previous write lock is now aliased by the newly unblocked writer — \
                     two simultaneous mutable references is immediate UB",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "spin_unsafe",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
