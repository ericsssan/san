/// Detects calls to `parking_lot_core::park` — the low-level unsafe parking primitive
/// underlying all `parking_lot` synchronization types.
///
/// `park(key, validate, before_sleep, timed_out, token, timeout)` is an unsafe function
/// with strict requirements on all closure arguments:
///
///   • `validate` is called while an internal queue lock is held:
///     — must not panic (abort-level, cannot be caught)
///     — must not call any parking_lot function (deadlock)
///     — must not allocate (lock is held)
///   • `before_sleep` is called after the queue lock is released, just before the thread
///     actually sleeps:
///     — must not call `park` (recursive park with same key corrupts the queue)
///     — must not panic
///   • `timed_out` is called with the queue lock held when the timeout fires:
///     — same restrictions as `validate` (no panic, no parking_lot, no alloc)
///   • The `key` must be a consistent address for the guarded object across all
///     concurrent `park`/`unpark_one`/`unpark_all` calls; using different keys for
///     the same object causes spurious unparks and missed wake-ups
///
/// Violating any constraint corrupts the thread queue, causing deadlocks, data races,
/// or memory corruption in the internal parker state.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ParkingLotCorePark;

impl Checker for ParkingLotCorePark {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.contains("parking_lot_core") || !path.ends_with("::park") {
                continue;
            }

            findings.push(Finding {
                rule_id: "parking_lot_core_park",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`parking_lot_core::park` — all three closures (validate, \
                          before_sleep, timed_out) must not panic, must not call any \
                          parking_lot function, and validate/timed_out must not allocate \
                          (they run with the internal queue lock held); violating these \
                          constraints corrupts the parker state (deadlock or memory corruption)"
                    .to_string(),
            });
        }

        findings
    }
}
