/// Detects calls to safe functions that have implicit unsafe preconditions —
/// functions that internally call unsafe operations on their parameters without
/// verifying the preconditions, exposing the unsafety to safe callers.
///
/// Example:
/// ```rust
/// // foo is a SAFE function but calls new_unchecked without a guard:
/// fn foo(x: u32) -> NonZeroU32 { unsafe { NonZeroU32::new_unchecked(x) } }
///
/// // Any caller passing an unguarded value can trigger UB through safe code:
/// fn bar(n: u32) { foo(n); }  // ← san fires here: n may be 0
/// ```
///
/// This is the dominant CVE pattern in the Rust ecosystem: a safe public API
/// wrapping an unsafe operation without enforcing the precondition, allowing
/// safe callers to trigger UB without writing `unsafe` themselves.
///
/// The checker uses pre-computed `PrecondSummary` entries (built by a separate
/// pass over all function bodies) to know which arguments of each function
/// carry implicit preconditions. At each call site it checks whether those
/// arguments are provably safe in the caller's flow state. If not, it fires.
use crate::analysis::precond::param_index;
use crate::{Checker, Finding, Severity};
use rustc_middle::mir::{Body, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

pub struct PrecondPropagation;

impl Checker for PrecondPropagation {
    fn check<'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        body: &Body<'tcx>,
        flow: &crate::analysis::FlowResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Precondition summaries are only available in the main checker pass
        // (not during summary extraction). Skip if not present.
        let Some(precond_map) = flow.precond_summaries.as_ref() else {
            return findings;
        };

        for (bb, block_data) in body.basic_blocks.iter_enumerated() {
            let Some(term) = &block_data.terminator else { continue };
            let TerminatorKind::Call { func, args, .. } = &term.kind else { continue };
            let Some((callee_def_id, _)) = func.const_fn_def() else { continue };

            let Some(precond) = precond_map.get(&callee_def_id) else { continue };
            if precond.is_empty() { continue; }

            let Some(state) = flow.state_before_terminator(tcx, body, bb) else { continue };

            let arg_local = |idx: usize| -> Option<rustc_middle::mir::Local> {
                args.get(idx).and_then(|a| match &a.node {
                    Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
                    _ => None,
                })
            };

            let callee_name = tcx.def_path_str(callee_def_id);
            let callee_short = callee_name.rsplit("::").take(2)
                .collect::<Vec<_>>().into_iter().rev()
                .collect::<Vec<_>>().join("::");

            // ── nonzero violations ───────────────────────────────────────────
            for &arg_idx in &precond.nonzero_args {
                let Some(local) = arg_local(arg_idx) else { continue };
                if state.local_is_nonzero(local) { continue; }

                // If the argument is itself a parameter, propagate rather than fire
                // here — the caller's caller might guard it. Fire only when the
                // argument is a concrete value that isn't proven nonzero.
                if param_index(body, local).is_some() { continue; }

                findings.push(Finding {
                    rule_id: "precond_violation",
                    severity: Severity::Warning,
                    span: term.source_info.span,
                    message: format!(
                        "`{callee_short}` requires arg[{arg_idx}] to be nonzero, \
                         but the value is not provably nonzero at this call site; \
                         `{callee_short}` is a safe function that internally calls \
                         unsafe code without verifying this precondition — the caller \
                         can trigger UB without writing `unsafe`"
                    ),
                });
            }

            // ── ASCII violations ─────────────────────────────────────────────
            for &arg_idx in &precond.ascii_args {
                let Some(local) = arg_local(arg_idx) else { continue };
                if state.local_is_ascii(local) { continue; }
                if param_index(body, local).is_some() { continue; }

                findings.push(Finding {
                    rule_id: "precond_violation",
                    severity: Severity::Warning,
                    span: term.source_info.span,
                    message: format!(
                        "`{callee_short}` requires arg[{arg_idx}] to be valid ASCII (≤ 127), \
                         but the value is not provably ASCII at this call site; \
                         `{callee_short}` is a safe function that internally calls \
                         `as_ascii_unchecked` without verifying this precondition"
                    ),
                });
            }

            // ── bounds violations ────────────────────────────────────────────
            for &(idx_arg, coll_arg) in &precond.bounded_for_args {
                let Some(idx_local)  = arg_local(idx_arg)  else { continue };
                let Some(coll_local) = arg_local(coll_arg) else { continue };
                let coll = state.deref_base(coll_local);
                if state.index_is_bounded_for(idx_local, coll)
                    || state.local_is_bounded(idx_local)
                {
                    continue;
                }
                if param_index(body, idx_local).is_some() { continue; }

                findings.push(Finding {
                    rule_id: "precond_violation",
                    severity: Severity::Warning,
                    span: term.source_info.span,
                    message: format!(
                        "`{callee_short}` requires arg[{idx_arg}] < arg[{coll_arg}].len(), \
                         but the index is not provably in-bounds at this call site; \
                         `{callee_short}` is a safe function wrapping `get_unchecked` without \
                         a bounds check — the caller can trigger an out-of-bounds read via safe code"
                    ),
                });
            }
        }

        findings
    }
}
