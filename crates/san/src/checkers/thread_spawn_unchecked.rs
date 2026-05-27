/// Detects calls to `thread::Builder::spawn_unchecked`.
///
/// `spawn_unchecked` launches a thread without the `'static` bound on the
/// closure, allowing closures that borrow non-'static data. The caller must
/// guarantee that ALL borrowed references remain valid for the entire lifetime
/// of the spawned thread — including panic / unwind paths. Rust cannot verify
/// this automatically.
///
/// Failure modes:
///   • The parent thread drops or deallocates a local while the child thread
///     still holds a reference → use-after-free
///   • The parent returns from the function that owns the borrowed data before
///     the child thread exits → dangling reference, typically SIGSEGV
///   • Without `join`, there is no synchronization guarantee; even a `join` in
///     the non-panic path leaves the panic path unsound unless the handle is
///     wrapped in a scope guard
///
/// Use `std::thread::scope` (stable since 1.63) instead: it enforces that all
/// scoped threads complete before borrowed data is freed.
///
/// RustSec: This pattern underlies soundness issues in several scoped-thread
/// reimplementations (crossbeam-channel, rayon) before stdlib adopted it.
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct ThreadSpawnUnchecked;

impl Checker for ThreadSpawnUnchecked {
    fn check<'tcx>(&self, tcx: TyCtxt<'tcx>, body: &Body<'tcx>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, _)) = func.const_fn_def() else { continue };

            let path = tcx.def_path_str(def_id);
            if !path.ends_with("Builder::spawn_unchecked") {
                continue;
            }

            findings.push(Finding {
                rule_id: "thread_spawn_unchecked",
                severity: Severity::Warning,
                span: terminator.source_info.span,
                message: "`Builder::spawn_unchecked` — all references captured by the closure \
                          must outlive the thread; the parent must not drop borrowed data until \
                          the thread exits (including on panic paths); prefer `thread::scope`"
                    .to_string(),
            });
        }

        findings
    }
}
