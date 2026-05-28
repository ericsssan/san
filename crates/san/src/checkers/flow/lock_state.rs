/// Flow-sensitive lock protocol checker.
///
/// `lock_api::Mutex::force_unlock` (and `force_unlock_fair`, `force_unlock_write`,
/// etc.) is only valid when the lock is held but the guard has been dropped via
/// `mem::forget`. Calling it without a prior lock + forget corrupts the mutex's
/// internal state.
///
/// This checker tracks each `lock()` / `try_lock()` / `write()` / `read()` call
/// as a ProtocolId with state `Active`. `mem::forget(guard)` transitions the guard's
/// protocol to `Forgotten`. At `force_unlock` call sites, it checks whether any
/// `Forgotten` guard exists in scope. If not — no guard was ever obtained and
/// forgotten — it warns.
///
/// Limitation: the checker can't yet link a specific guard to its owning mutex,
/// so if multiple mutexes are in scope it may not warn when the wrong guard was
/// forgotten. That requires interprocedural alias tracking.
use crate::analysis::transfer::is_force_unlock;
use crate::analysis::FlowResults;
use crate::{Finding, Checker, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct LockState;

impl Checker for LockState {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(state) = flow.state_before_terminator(tcx, body, bb) else {
                continue;
            };

            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };
            let path = tcx.def_path_str(def_id);

            if !is_force_unlock(&path) {
                continue;
            }

            // Valid pattern: some guard was acquired and then mem::forgotten.
            if state.has_forgotten_protocol() {
                continue;
            }

            findings.push(Finding {
                rule_id: "lock_force_unlock_unpaired",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!(
                    "`{op}` called without a preceding `lock()` + `mem::forget(guard)` on \
                     this path — calling force_unlock on an unlocked mutex corrupts its \
                     internal state",
                    op = force_unlock_name(&path),
                ),
            });
        }

        findings
    }
}

fn force_unlock_name(path: &str) -> &str {
    if path.ends_with("::force_unlock_write") || path.ends_with("::force_unlock_write_fair") {
        "force_unlock_write"
    } else if path.ends_with("::force_unlock_read") || path.ends_with("::force_unlock_read_fair") {
        "force_unlock_read"
    } else if path.ends_with("::force_unlock_fair") {
        "force_unlock_fair"
    } else {
        "force_unlock"
    }
}
