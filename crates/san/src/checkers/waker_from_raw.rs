/// Detects calls to `Waker::from_raw`, `Waker::new`, `LocalWaker::from_raw`,
/// and `LocalWaker::new`.
///
/// `Waker::from_raw(raw_waker)` constructs a `Waker` from a `RawWaker`.
/// Because `Waker` is `Send + Sync`, the caller must guarantee:
///   • All function pointers in the `RawWakerVTable` are valid, non-null,
///     and implement the correct semantics (clone, wake, wake_by_ref, drop)
///   • The `data` pointer embedded in the `RawWaker` must remain valid
///     for the entire lifetime of the `Waker` and any clones derived from it
///   • All vtable functions must be safe to call from any thread
///     (`Send + Sync` requirement — data-race-free access to the `data` pointer)
///   • The `clone` vtable function must return a new `RawWaker` whose
///     `data` lifetime is independent from the original (no dangling clones)
///   • The `drop` vtable function must correctly release ownership exactly once
///
/// `LocalWaker::from_raw` has the same requirements except thread-safety
/// (it is `!Send + !Sync`).
///
/// Common bugs: using a stack-allocated `data` pointer that becomes dangling
/// when the creating scope exits; forgetting to implement `drop` (leaks the
/// resource the data pointer points to); non-atomic reference counting in
/// `clone`/`drop` while `Waker` is cloned across threads.
///
/// RustSec: RUSTSEC-2020-0061 (futures-task noop_waker_ref — UnsafeCell in TLS
/// returned across threads).
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct WakerFromRaw;

impl Checker for WakerFromRaw {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>, _flow: &crate::analysis::FlowResults) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);

            let (fn_name, note) = if path.ends_with("Waker::from_raw")
                && !path.contains("LocalWaker")
            {
                (
                    "Waker::from_raw",
                    "vtable fn pointers must be valid and thread-safe (Waker is Send+Sync); \
                     data pointer must outlive all Waker clones; \
                     clone/drop must be correctly paired — missing drop leaks, double-drop is UB",
                )
            } else if path.ends_with("Waker::new")
                && !path.contains("Local")
                && !path.contains("Raw")
            {
                (
                    "Waker::new",
                    "data pointer must be valid for the lifetime of all Waker clones; \
                     all four vtable function pointers (clone, wake, wake_by_ref, drop) must be \
                     valid and thread-safe (Waker is Send+Sync); drop must free the data exactly \
                     once — stable since 1.83.0",
                )
            } else if path.ends_with("LocalWaker::from_raw") {
                (
                    "LocalWaker::from_raw",
                    "vtable fn pointers must be valid; data pointer must outlive the LocalWaker \
                     and all clones; clone/drop must be correctly paired",
                )
            } else if path.ends_with("LocalWaker::new") {
                (
                    "LocalWaker::new",
                    "data pointer must be valid for the lifetime of all LocalWaker clones; \
                     vtable functions must be valid; LocalWaker is !Send+!Sync so the data pointer \
                     need not be thread-safe, but must not be sent across threads \
                     (nightly feature `local_waker`)",
                )
            } else {
                continue;
            };

            findings.push(Finding {
                rule_id: "waker_from_raw",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: format!("`{fn_name}` — {note}"),
            });
        }

        findings
    }
}
