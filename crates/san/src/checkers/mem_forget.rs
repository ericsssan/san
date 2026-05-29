/// Detects calls to `mem::forget`.
///
/// `mem::forget(val)` prevents `val`'s destructor from running. While safe
/// in Rust (leaking is always allowed), in unsafe code it creates a critical
/// invariant: callers must ensure no other path can drop the same data.
///
/// `ManuallyDrop::new` is intentionally NOT flagged here: it is a safe
/// constructor (like `Box::new`) whose only effect is to suppress the inner
/// value's automatic drop — a leak concern, never UB on its own. The genuinely
/// unsafe siblings `ManuallyDrop::drop` and `ManuallyDrop::take` (the
/// double-drop / use-after-move hazards) are covered by the `manually_drop`
/// checker, so flagging `new` here would only add noise.
///
/// Common unsafe patterns involving `mem::forget`:
///   • "Split ownership" — create raw pointer to fields, forget the container,
///     then manage each field independently. A panic between the pointer
///     creation and the `forget` causes the container to be dropped with the
///     raw pointers still live → use-after-free.
///   • "Prevent double-drop" — passing ownership through a raw pointer to
///     another owner; forgetting ensures the Rust side doesn't also drop.
///     A missed `forget` causes double-drop.
///   • "Ownership transfer to C" — passing a Box/Arc to FFI that will free it;
///     `mem::forget` surrenders Rust's ownership. Forgetting without the FFI
///     call also happening (e.g. due to early return) causes a memory leak.
///
/// Review all `mem::forget` call sites to ensure:
///   1. No panic path exists between taking raw pointers and calling `forget`
///   2. The forgetting is paired with a corresponding ownership pickup elsewhere
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct MemForget;

impl Checker for MemForget {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            let (fn_name, note) = if path.ends_with("mem::forget") {
                (
                    "mem::forget",
                    "verify no panic path exists between taking raw pointers to the \
                     forgotten value and this call; ownership must be picked up elsewhere",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "mem_forget",
                severity: Severity::Info,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
