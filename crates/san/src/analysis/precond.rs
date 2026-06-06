/// Interprocedural precondition summaries.
///
/// When a function `fn foo(x: T)` (safe, not `unsafe fn`) calls an unsafe
/// operation on `x` without verifying its precondition, `foo` implicitly
/// requires its caller to satisfy that precondition. Any safe caller of `foo`
/// can trigger UB by passing a value that violates it — without touching
/// `unsafe` themselves.
///
/// `PrecondSummary` records which argument indices have which implicit
/// requirements. A separate pre-pass computes these over all function bodies;
/// the `precond_propagation` checker then fires at call sites where a callee's
/// precondition is not provably satisfied by the caller's flow state.
use std::collections::{BTreeSet, HashMap};

use rustc_hir::def_id::DefId;
use rustc_middle::mir::{Body, Local, Operand, TerminatorKind};
use rustc_middle::ty::TyCtxt;

use crate::analysis::dataflow::FlowResults;
use crate::analysis::transfer::first_arg_local;

/// Implicit preconditions a function places on its arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrecondSummary {
    /// Argument indices that must be nonzero (for `new_unchecked`, `ctlz_nonzero`, etc.).
    pub nonzero_args: BTreeSet<usize>,
    /// Argument indices that must be a valid ASCII value (≤ 127).
    pub ascii_args: BTreeSet<usize>,
    /// (index_arg, collection_arg) pairs: the index arg must be < the collection
    /// arg's length (for `get_unchecked`, `split_at_unchecked`, etc.).
    pub bounded_for_args: BTreeSet<(usize, usize)>,
}

impl PrecondSummary {
    pub fn is_empty(&self) -> bool {
        self.nonzero_args.is_empty()
            && self.ascii_args.is_empty()
            && self.bounded_for_args.is_empty()
    }
}

/// Maps function DefIds to their precondition requirements.
pub type PrecondSummaryMap = HashMap<DefId, PrecondSummary>;

/// Returns the 0-based argument index of `local` in `body`, or `None` if it
/// is not a direct parameter local.
pub fn param_index(body: &Body<'_>, local: Local) -> Option<usize> {
    let idx = local.as_usize();
    if idx >= 1 && idx <= body.arg_count {
        Some(idx - 1)
    } else {
        None
    }
}

fn arg_local(args: &[rustc_span::Spanned<Operand<'_>>], idx: usize) -> Option<Local> {
    args.get(idx).and_then(|a| match &a.node {
        Operand::Move(p) | Operand::Copy(p) if p.projection.is_empty() => Some(p.local),
        _ => None,
    })
}

/// Analyse `body` and produce a `PrecondSummary` recording which parameter
/// arguments are passed unguarded to unsafe operations. Only records an entry
/// when the argument is a DIRECT parameter local and the flow state does not
/// suppress the finding (i.e. the precondition is not verified inside the body).
///
/// This is intentionally conservative: if the body already guards the arg
/// (e.g. `if x != 0 { new_unchecked(x) }`), the suppression kicks in and
/// the arg is NOT added to the summary — the body is safe for callers.
pub fn extract_precond_summary<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    flow: &FlowResults,
) -> PrecondSummary {
    let mut summary = PrecondSummary::default();

    for (bb, block_data) in body.basic_blocks.iter_enumerated() {
        let Some(term) = &block_data.terminator else { continue };
        let TerminatorKind::Call { func, args, .. } = &term.kind else { continue };
        let Some((def_id, _)) = func.const_fn_def() else { continue };
        let Some(state) = flow.state_before_terminator(tcx, body, bb) else { continue };

        let path = tcx.def_path_str(def_id);

        // ── nonzero precondition ────────────────────────────────────────────
        let is_nonzero_precond = path.ends_with("::new_unchecked")
            || path.ends_with("::unchecked_new")
            || path.ends_with("::from_mut_unchecked")
            || path.ends_with("ctlz_nonzero")
            || path.ends_with("cttz_nonzero");

        if is_nonzero_precond {
            if let Some(a) = first_arg_local(args) {
                if !state.local_is_nonzero(a) {
                    if let Some(idx) = param_index(body, a) {
                        summary.nonzero_args.insert(idx);
                    }
                }
            }
        }

        // ── ASCII precondition ──────────────────────────────────────────────
        let is_ascii_precond = path.ends_with("::as_ascii_unchecked")
            || path.ends_with("Char::from_u8_unchecked");

        if is_ascii_precond {
            if let Some(a) = first_arg_local(args) {
                if !state.local_is_ascii(a) {
                    if let Some(idx) = param_index(body, a) {
                        summary.ascii_args.insert(idx);
                    }
                }
            }
        }

        // ── bounds precondition (index < collection.len()) ──────────────────
        let is_index_precond = (path.ends_with("get_unchecked_mut")
            || path.ends_with("get_unchecked"))
            && !path.contains("pin::Pin");

        if is_index_precond {
            let recv_local = arg_local(args, 0).map(|l| state.deref_base(l));
            let idx_local  = arg_local(args, 1);
            if let (Some(recv), Some(idx)) = (recv_local, idx_local) {
                let already_safe = state.index_is_bounded_for(idx, recv)
                    || state.local_is_bounded(idx);
                if !already_safe {
                    let recv_param = param_index(body, recv);
                    let idx_param  = param_index(body, idx);
                    // Both must be parameters for the precondition to make sense
                    // at the caller's side.
                    if let (Some(rp), Some(ip)) = (recv_param, idx_param) {
                        summary.bounded_for_args.insert((ip, rp));
                    }
                }
            }
        }
    }

    summary
}
