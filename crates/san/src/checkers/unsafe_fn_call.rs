/// Backstop checker: flags calls to any `unsafe fn` that no more-specific
/// checker already covers.
///
/// san's other checkers target *known* unsafe APIs by path (`ptr::read`,
/// `NonNull::as_ref`, `UnsafeCell::get`, `Box::from_raw`, …). That leaves a
/// recall gap: a call to an arbitrary `unsafe fn` — a user-defined one, a trait
/// method declared `unsafe fn`, or a third-party API without a dedicated
/// checker — is not flagged at all. Calling any `unsafe fn` discharges a safety
/// contract the caller must uphold, so it is exactly the kind of site an audit
/// should surface.
///
/// Example this recovers (tokio's intrusive list): `Link::from_raw(ptr)` and
/// `LinkedList::remove(node)` are `unsafe fn`s with documented preconditions but
/// match no path-based checker, so they were previously invisible.
///
/// To avoid piling onto sites another checker already reported, findings from
/// this rule are dropped in `run_checks` whenever their call-site span overlaps
/// a finding from any other rule (see the suppression pass there). The result is
/// a pure gap-filler: it fires only where nothing more specific did.
use crate::{Checker, Finding, Severity};
use rustc_hir::Safety;
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct UnsafeFnCall;

impl Checker for UnsafeFnCall {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        _flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for block_data in body.basic_blocks.iter() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, .. } = &terminator.kind else { continue };
            let Some((def_id, args)) = func.const_fn_def() else { continue };

            // Only function items have a meaningful `fn_sig`; the safety of the
            // *instantiated* signature is what the caller must discharge.
            let sig = tcx.fn_sig(def_id).instantiate(tcx, args).skip_binder();
            if sig.safety() != Safety::Unsafe {
                continue;
            }

            // A compiler-synthesised or macro-expanded call is not user-written
            // code at this site — matching how the other checkers treat it.
            let span = terminator.source_info.span;
            if span.from_expansion() {
                continue;
            }

            let path = tcx.def_path_str(def_id);
            findings.push(Finding {
                rule_id: "unsafe_fn_call",
                severity: Severity::Info,
                span,
                message: format!(
                    "call to `unsafe fn` `{path}` — the function's safety \
                     preconditions must be upheld by the caller; verify them at this site"
                ),
            });
        }

        findings
    }
}
