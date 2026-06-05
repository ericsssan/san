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
use crate::analysis::state::FreedKind;
use crate::checkers::uaf::uaf_finding;
use crate::{Checker, Finding, Severity};
use rustc_hir::Safety;
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};

pub struct UnsafeFnCall;

impl Checker for UnsafeFnCall {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(terminator) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &terminator.kind else { continue };
            let Some((def_id, generic_args)) = func.const_fn_def() else { continue };

            // Only function items have a meaningful `fn_sig`; the safety of the
            // *instantiated* signature is what the caller must discharge.
            let sig = tcx.fn_sig(def_id).instantiate(tcx, generic_args).skip_binder();
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

            // If any raw-pointer argument was already freed, this is UAF — escalate
            // rather than emitting the generic unsafe-fn audit finding.
            if let Some(state) = flow.state_before_terminator(tcx, body, bb) {
                let mut uaf_found = false;
                let mut any_tracked = false;
                let mut any_bounded = false;
                for arg in args.iter() {
                    let Some(local) = (match &arg.node {
                        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                        _ => None,
                    }) else { continue };
                    // UAF escalation: only check raw-pointer typed args (freed_kind
                    // is only meaningful for raw pointer locals).
                    if matches!(body.local_decls[local].ty.kind(), TyKind::RawPtr(..)) {
                        match state.freed_kind(local) {
                            FreedKind::Definite => {
                                findings.push(uaf_finding(span, "read", false));
                                uaf_found = true;
                            }
                            FreedKind::Potential => {
                                findings.push(uaf_finding(span, "read", true));
                                uaf_found = true;
                            }
                            FreedKind::NotFreed => {}
                        }
                    }
                    // Track if ANY arg (raw pointer OR wrapper like NonNull) is being
                    // tracked by flow — if so, a specific checker will handle it.
                    if state.objects_for(local).next().is_some() {
                        any_tracked = true;
                    }
                    // A proven bound on an integer arg (e.g. `if n <= v.capacity()`
                    // ahead of `set_len(n)`) or a proven spare capacity on a
                    // receiver collection (e.g. `if v.len() < v.capacity()` ahead
                    // of `push_unchecked`) discharges the precondition of the
                    // bounds-checked-unchecked APIs. The specific checker has
                    // already suppressed itself on this fact, so the generic
                    // backstop must not re-flag the now-safe call.
                    if state.local_is_bounded_or_eq(local)
                        || state.collection_has_spare(local)
                        || state.collection_is_full(local)
                        || state.local_is_nonzero(local)
                        || state.local_is_finite(local)
                        || state.local_is_valid_scalar(local)
                        || state.fd_was_transferred(local)
                    {
                        any_bounded = true;
                    }
                }
                if uaf_found { continue; }
                if any_bounded { continue; }
                // For calls on tracked pointers where a specific checker handles the
                // lifecycle, suppress the generic backstop to avoid redundant audit noise.
                if any_tracked
                    && (crate::analysis::transfer::is_from_raw(&path)
                        || crate::analysis::transfer::is_ptr_read(&path)
                        || crate::analysis::transfer::is_raw_realloc(&path)
                        || crate::analysis::transfer::is_ptr_write_to_first_arg(&path)
                        || crate::is_owned_buffer_accessor(&path))
                {
                    continue;
                }
            }

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
