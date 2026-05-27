/// Detects calls to `Mutex::clear_poison` and `RwLock::clear_poison`.
/// (Stable since Rust 1.77; tracking issue #96469.)
///
/// When a thread panics while holding a `Mutex` or `RwLock`, the lock becomes
/// "poisoned". Any subsequent `lock()` or `read()`/`write()` call returns
/// `Err(PoisonError<...>)` to signal that the protected data may be in an
/// inconsistent state.
///
/// `Mutex::clear_poison(&self)` clears the poisoned flag. This is a safe fn
/// because the Rust safety model does not guarantee that poisoned data is
/// actually inconsistent — the panic may have occurred after the critical
/// section completed. However, calling `clear_poison` before verifying the
/// data is in a consistent state is a common footgun:
///
///   • After calling, all subsequent `lock()` callers receive `Ok(MutexGuard)`
///     even if the protected data was partially modified by the panicking thread
///   • The inconsistency becomes invisible to callers — they have no signal that
///     anything went wrong
///   • Any invariants the protected data is supposed to maintain may be violated
///
/// Common bugs:
///   • Silencing `PoisonError` by calling `clear_poison` without inspecting or
///     repairing the data (used as a "just make it work" hack)
///   • Calling `clear_poison` in recovery logic that runs concurrently with
///     threads holding a reference from `PoisonError::into_inner()` — those
///     guards are still valid and hold references to the (possibly inconsistent) data
///
/// Safe alternatives:
///   • `lock().unwrap_or_else(|e| e.into_inner())` — accesses the data anyway
///     but caller explicitly handles the fact that it might be inconsistent
///   • Inspect and repair the data inside a `PoisonError::into_inner()` guard
///     before calling `clear_poison`
///
/// Stable since Rust 1.77.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MutexAssumeUnpoisoned;

impl Checker for MutexAssumeUnpoisoned {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            if !path.ends_with("::clear_poison") {
                continue;
            }

            let container = if path.contains("RwLock") {
                "RwLock"
            } else if path.contains("Mutex") {
                "Mutex"
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "mutex_clear_poison",
                severity: Severity::Info,
                span: terminator.source_info.span,
                message: format!(
                    "`{container}::clear_poison` — clears the poison flag; subsequent lock() \
                     callers will receive Ok(...) with no indication that the protected data \
                     may be in an inconsistent state; verify or repair the data before clearing; \
                     prefer `PoisonError::into_inner()` to access and inspect the data first"
                ),
            });
        }

        findings
    }
}
