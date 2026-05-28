/// Flow-sensitive crossbeam-epoch guard liveness checker.
///
/// `crossbeam_epoch::pin()` returns a `Guard` whose lifetime bounds the validity
/// of any `Shared<T>` pointer loaded while the guard is active.
/// `Shared::deref` (and variants) are only sound while a guard is live.
///
/// This checker tracks each `epoch::pin()` call site as a ProtocolId and
/// transitions its state through `Active → Consumed` (on drop) or `Forgotten`
/// (on `mem::forget`). At any `Shared::deref` / `Shared::deref_mut` /
/// `Guard::defer_destroy` call where all protocol instances in scope are
/// `Consumed` or `MaybeActive`, it warns that the guard may have expired.
///
/// Limitation: when multiple guards are in scope, the checker conservatively
/// warns if ANY is in a hazard state, not specifically the one tied to the
/// dereferenced `Shared`. Precise per-Shared guard tracking requires
/// interprocedural analysis.
use crate::analysis::transfer::is_shared_deref;
use crate::analysis::FlowResults;
use crate::{Finding, FlowChecker, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct EpochGuard;

impl FlowChecker for EpochGuard {
    fn check_flow<'tcx>(
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

            if !is_shared_deref(&path) && !is_defer_destroy(&path) {
                continue;
            }

            // If any guard protocol in scope is in a hazard state, warn.
            if state.has_hazard_protocol() {
                findings.push(Finding {
                    rule_id: "epoch_guard_expired",
                    severity: Severity::Warning,
                    span: terminator.source_info.span,
                    message: format!(
                        "`{op}` called but an epoch guard may have been dropped — \
                         dereferencing a `Shared` pointer after its guard is dropped is \
                         use-after-free",
                        op = op_name(&path),
                    ),
                });
            }
        }

        findings
    }
}

fn is_defer_destroy(path: &str) -> bool {
    path.ends_with("::defer_destroy") && path.contains("Guard")
}

fn op_name(path: &str) -> &str {
    if path.ends_with("::deref_mut") {
        "Shared::deref_mut"
    } else if path.ends_with("::defer_destroy") {
        "Guard::defer_destroy"
    } else {
        "Shared::deref"
    }
}
